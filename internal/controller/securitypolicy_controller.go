package controller

import (
	"context"
	"reflect"
	"sort"
	"time"

	"github.com/go-logr/logr"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/client-go/util/retry"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/builder"
	"sigs.k8s.io/controller-runtime/pkg/client"
	logf "sigs.k8s.io/controller-runtime/pkg/log"
	"sigs.k8s.io/controller-runtime/pkg/predicate"

	nvtenantv1alpha1 "nvtenant.severinsdigitalsolutions.nl/api/v1alpha1"
)

var nvVulnProfileGVK = schema.GroupVersionKind{
	Group:   "neuvector.com",
	Kind:    "NvVulnerabilityProfile",
	Version: "v1",
}

type NvProfileEntry struct {
	Name    string   `json:"name"`
	Images  []string `json:"images,omitempty"`
	Domains []string `json:"domains,omitempty"`
	Days    int      `json:"days,omitempty"`
	Comment string   `json:"comment,omitempty"`
}

func entryToMap(e NvProfileEntry) map[string]interface{} {
	m := map[string]interface{}{
		"name": e.Name,
	}
	if len(e.Images) > 0 {
		imgs := make([]interface{}, len(e.Images))
		for i, v := range e.Images {
			imgs[i] = v
		}
		m["images"] = imgs
	}
	if len(e.Domains) > 0 {
		doms := make([]interface{}, len(e.Domains))
		for i, v := range e.Domains {
			doms[i] = v
		}
		m["domains"] = doms
	}
	if e.Days > 0 {
		m["days"] = int64(e.Days)
	}
	if e.Comment != "" {
		m["comment"] = e.Comment
	}
	return m
}

type SecurityPolicyReconciler struct {
	client.Client
	Scheme *runtime.Scheme
}

// +kubebuilder:rbac:groups=nvtenant.severinsdigitalsolutions.nl,resources=securitypolicies,verbs=get;list;watch;create;update;patch;delete
// +kubebuilder:rbac:groups=nvtenant.severinsdigitalsolutions.nl,resources=securitypolicies/status,verbs=get;update;patch
// +kubebuilder:rbac:groups=nvtenant.severinsdigitalsolutions.nl,resources=securitypolicies/finalizers,verbs=update
// +kubebuilder:rbac:groups=neuvector.com,resources=nvvulnerabilityprofiles,verbs=get;list;watch;create;update;patch

func (r *SecurityPolicyReconciler) Reconcile(ctx context.Context, req ctrl.Request) (ctrl.Result, error) {
	log := logf.FromContext(ctx)
	log.Info("Reconcile triggered")

	var currentPolicy nvtenantv1alpha1.SecurityPolicy
	currentPolicyExists := true
	if err := r.Get(ctx, req.NamespacedName, &currentPolicy); err != nil {
		if client.IgnoreNotFound(err) != nil {
			return ctrl.Result{}, err
		}
		currentPolicyExists = false
	}

	var allPolicies nvtenantv1alpha1.SecurityPolicyList
	if err := r.List(ctx, &allPolicies); err != nil {
		return ctrl.Result{}, err
	}

	unstructuredEntries := make([]interface{}, 0)
	activeForThisPolicy := 0

	for _, policy := range allPolicies.Items {
		for _, exemption := range policy.Spec.Exemptions {
			if exemption.ExpiresAt != nil && time.Now().After(exemption.ExpiresAt.Time) {
				continue
			}

			entry := NvProfileEntry{
				Name:    exemption.CVEID,
				Images:  []string{exemption.Image},
				Domains: []string{policy.Namespace},
				Comment: "VEX: " + exemption.VEXStatus + ", Justification: " + exemption.Justification,
				Days:    exemption.Days,
			}
			unstructuredEntries = append(unstructuredEntries, entryToMap(entry))

			if currentPolicyExists && policy.UID == currentPolicy.UID {
				activeForThisPolicy++
			}
		}
	}

	if err := r.syncNvProfile(ctx, log, unstructuredEntries); err != nil {
		return ctrl.Result{}, err
	}

	// Status update: avoid 409 conflicts by re-fetching latest and patching in a retry loop.
	if currentPolicyExists {
		retryErr := retry.RetryOnConflict(retry.DefaultRetry, func() error {
			var latest nvtenantv1alpha1.SecurityPolicy
			if err := r.Get(ctx, req.NamespacedName, &latest); err != nil {
				return err
			}

			patchBase := latest.DeepCopy()

			latest.Status.Synced = true
			latest.Status.ActiveCount = activeForThisPolicy
			now := metav1.Now()
			latest.Status.LastSync = &now

			return r.Status().Patch(ctx, &latest, client.MergeFrom(patchBase))
		})
		if retryErr != nil {
			return ctrl.Result{}, retryErr
		}
	}

	return ctrl.Result{RequeueAfter: 5 * time.Minute}, nil
}

// syncNvProfile writes the exemption entries to the NeuVector default vulnerability profile.
// If the NvVulnerabilityProfile CRD is not installed, the sync is skipped without error.
// Entries are sorted by CVE name for deterministic output, and the patch is skipped if unchanged.
func (r *SecurityPolicyReconciler) syncNvProfile(ctx context.Context, log logr.Logger, entries []interface{}) error {
	// 1. Normalize: sort entries by CVE name for deterministic ordering.
	sort.Slice(entries, func(i, j int) bool {
		iName, _ := entries[i].(map[string]interface{})["name"].(string)
		jName, _ := entries[j].(map[string]interface{})["name"].(string)
		return iName < jName
	})

	// 2. Fetch existing profile to compare.
	existing := &unstructured.Unstructured{}
	existing.SetGroupVersionKind(nvVulnProfileGVK)
	if err := r.Get(ctx, client.ObjectKey{Name: "default"}, existing); err != nil {
		if meta.IsNoMatchError(err) {
			log.Info("NvVulnerabilityProfile CRD not installed; skipping NeuVector sync")
			return nil
		}
		if !apierrors.IsNotFound(err) {
			// Real API error.
			return err
		}
		// Profile does not exist yet — will be created by SSA below.
		log.Info("NvVulnerabilityProfile not found; will create")
	} else {
		// 3. Compare: skip patch if entries are identical.
		existingEntries, _, _ := unstructured.NestedSlice(existing.Object, "spec", "profile", "entries")
		if reflect.DeepEqual(existingEntries, entries) {
			log.Info("NvVulnerabilityProfile unchanged; skipping patch")
			return nil
		}
	}

	// 4. Build the desired object and apply via SSA.
	nvProfile := &unstructured.Unstructured{}
	nvProfile.SetGroupVersionKind(nvVulnProfileGVK)
	nvProfile.SetName("default")

	if err := unstructured.SetNestedSlice(nvProfile.Object, entries, "spec", "profile", "entries"); err != nil {
		return err
	}

	if err := r.Patch(ctx, nvProfile, client.Apply, client.FieldOwner("securitypolicy-controller"), client.ForceOwnership); err != nil {
		if meta.IsNoMatchError(err) {
			log.Info("NvVulnerabilityProfile CRD not installed; skipping NeuVector sync")
			return nil
		}
		return err
	}

	log.Info("NvVulnerabilityProfile patched", "entryCount", len(entries))
	return nil
}

func (r *SecurityPolicyReconciler) SetupWithManager(mgr ctrl.Manager) error {
	return ctrl.NewControllerManagedBy(mgr).
		For(&nvtenantv1alpha1.SecurityPolicy{},
			builder.WithPredicates(predicate.GenerationChangedPredicate{}),
		).
		Named("securitypolicy").
		Complete(r)
}

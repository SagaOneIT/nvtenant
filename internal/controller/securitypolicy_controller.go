package controller

import (
	"context"
	"encoding/json"
	"time"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	logf "sigs.k8s.io/controller-runtime/pkg/log"

	nvtenantv1alpha1 "nvtenant.sagaone.it/api/v1alpha1"
)

// NvProfileEntry is een interne helper struct voor de controller.
// Geen deepcopy nodig — wordt niet gebruikt als Kubernetes object.
type NvProfileEntry struct {
	Name    string   `json:"name"`
	Images  []string `json:"images,omitempty"`
	Domains []string `json:"domains,omitempty"`
	Days    int      `json:"days,omitempty"`
	Comment string   `json:"comment,omitempty"`
}

// Converteert []NvProfileEntry naar []interface{} voor unstructured
func EntriesToUnstructured(entries []NvProfileEntry) ([]interface{}, error) {
	result := make([]interface{}, 0, len(entries))
	for _, e := range entries {
		data, err := json.Marshal(e)
		if err != nil {
			return nil, err
		}
		var m map[string]interface{}
		if err := json.Unmarshal(data, &m); err != nil {
			return nil, err
		}
		result = append(result, m)
	}
	return result, nil
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

	// Haal de huidige policy op
	var currentPolicy nvtenantv1alpha1.SecurityPolicy
	if err := r.Get(ctx, req.NamespacedName, &currentPolicy); err != nil {
		return ctrl.Result{}, client.IgnoreNotFound(err)
	}

	// Haal ALLE SecurityPolicies op uit alle namespaces voor de globale merge
	var allPolicies nvtenantv1alpha1.SecurityPolicyList
	if err := r.List(ctx, &allPolicies); err != nil {
		return ctrl.Result{}, err
	}

	// Bouw de lijst met filters (Merge)
	var entries []NvProfileEntry
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
				Comment: "Managed by SDS Operator, VEX: " + exemption.VEXStatus + ", Justification: " + exemption.Justification,
			}
			if exemption.Days > 0 {
				entry.Days = exemption.Days
			}

			entries = append(entries, entry)

			if policy.UID == currentPolicy.UID {
				activeForThisPolicy++
			}
		}
	}

	// Update het globale NeuVector profiel
	nvProfile := &unstructured.Unstructured{}
	nvProfile.SetGroupVersionKind(schema.GroupVersionKind{
		Group:   "neuvector.com",
		Kind:    "NvVulnerabilityProfile",
		Version: "v1",
	})

	// Probeer het bestaande profiel op te halen
	getErr := r.Get(ctx, client.ObjectKey{Name: "default"}, nvProfile)
	isNew := false
	if getErr != nil {
		if client.IgnoreNotFound(getErr) == nil {
			// Profiel bestaat nog niet, we gaan het aanmaken
			log.Info("NeuVector 'default' profiel niet gevonden, wordt aangemaakt")
			nvProfile.SetName("default")
			isNew = true
		} else {
			// Andere error (bijv. RBAC of API issues)
			return ctrl.Result{}, getErr
		}
	}

	unstructuredEntries, err := EntriesToUnstructured(entries)
	if err != nil {
		return ctrl.Result{}, err
	}

	// Zet de entries in het object
	if err := unstructured.SetNestedSlice(nvProfile.Object, unstructuredEntries, "spec", "profile", "entries"); err != nil {
		return ctrl.Result{}, err
	}

	// Create of Update afhankelijk van of het object al bestond
	if isNew {
		if err := r.Create(ctx, nvProfile); err != nil {
			return ctrl.Result{}, err
		}
	} else {
		if err := r.Update(ctx, nvProfile); err != nil {
			return ctrl.Result{}, err
		}
	}

	if err := r.Update(ctx, nvProfile); err != nil {
		return ctrl.Result{}, err
	}

	// Update Status van de huidige policy
	currentPolicy.Status.Synced = true
	currentPolicy.Status.ActiveCount = activeForThisPolicy
	now := metav1.Now()
	currentPolicy.Status.LastSync = &now

	if err := r.Status().Update(ctx, &currentPolicy); err != nil {
		return ctrl.Result{}, err
	}

	return ctrl.Result{RequeueAfter: 5 * time.Minute}, nil
}

func (r *SecurityPolicyReconciler) SetupWithManager(mgr ctrl.Manager) error {
	return ctrl.NewControllerManagedBy(mgr).
		For(&nvtenantv1alpha1.SecurityPolicy{}).
		Named("securitypolicy").
		Complete(r)
}

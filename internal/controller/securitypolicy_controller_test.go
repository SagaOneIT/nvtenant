package controller

import (
	"context"
	"time"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	"k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/types"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	nvtenantv1alpha1 "nvtenant.severinsdigitalsolutions.nl/api/v1alpha1"
)

func reconcilePolicy(ctx context.Context, name, namespace string) {
	controllerReconciler := &SecurityPolicyReconciler{
		Client: k8sClient,
		Scheme: k8sClient.Scheme(),
	}
	_, err := controllerReconciler.Reconcile(ctx, reconcile.Request{
		NamespacedName: types.NamespacedName{Name: name, Namespace: namespace},
	})
	Expect(err).NotTo(HaveOccurred())
}

var _ = Describe("SecurityPolicy Controller", func() {
	var (
		ctx               = context.Background()
		resourceName      = "test-policy"
		resourceNamespace = "default"
		nn                = types.NamespacedName{Name: resourceName, Namespace: resourceNamespace}
	)

	// helper to delete a policy by name if it exists
	deletePolicy := func(name, namespace string) {
		p := &nvtenantv1alpha1.SecurityPolicy{}
		if err := k8sClient.Get(ctx, types.NamespacedName{Name: name, Namespace: namespace}, p); err == nil {
			Expect(k8sClient.Delete(ctx, p)).To(Succeed())
		}
	}

	Context("basic reconcile", func() {
		BeforeEach(func() {
			policy := &nvtenantv1alpha1.SecurityPolicy{
				ObjectMeta: metav1.ObjectMeta{Name: resourceName, Namespace: resourceNamespace},
				Spec: nvtenantv1alpha1.SecurityPolicySpec{
					Exemptions: []nvtenantv1alpha1.VulnerabilityExemption{
						{
							CVEID:         "CVE-2023-1234",
							Image:         "nginx:latest",
							VEXStatus:     "affected",
							Justification: "Unit testing",
						},
					},
				},
			}
			err := k8sClient.Create(ctx, policy)
			if err != nil && !errors.IsAlreadyExists(err) {
				Expect(err).NotTo(HaveOccurred())
			}
		})

		AfterEach(func() { deletePolicy(resourceName, resourceNamespace) })

		It("should set Synced=true, ActiveCount=1 and LastSync", func() {
			reconcilePolicy(ctx, resourceName, resourceNamespace)

			updated := &nvtenantv1alpha1.SecurityPolicy{}
			Expect(k8sClient.Get(ctx, nn, updated)).To(Succeed())
			Expect(updated.Status.Synced).To(BeTrue())
			Expect(updated.Status.ActiveCount).To(Equal(1))
			Expect(updated.Status.LastSync).NotTo(BeNil())
		})
	})

	Context("expired exemption", func() {
		BeforeEach(func() {
			past := metav1.NewTime(time.Now().Add(-24 * time.Hour))
			policy := &nvtenantv1alpha1.SecurityPolicy{
				ObjectMeta: metav1.ObjectMeta{Name: resourceName, Namespace: resourceNamespace},
				Spec: nvtenantv1alpha1.SecurityPolicySpec{
					Exemptions: []nvtenantv1alpha1.VulnerabilityExemption{
						{
							CVEID:         "CVE-2023-9999",
							Image:         "nginx:latest",
							VEXStatus:     "affected",
							Justification: "Expired exemption test",
							ExpiresAt:     &nvtenantv1alpha1.Date{Time: past.Time},
						},
					},
				},
			}
			err := k8sClient.Create(ctx, policy)
			if err != nil && !errors.IsAlreadyExists(err) {
				Expect(err).NotTo(HaveOccurred())
			}
		})

		AfterEach(func() { deletePolicy(resourceName, resourceNamespace) })

		It("should set ActiveCount=0 for a fully expired policy", func() {
			reconcilePolicy(ctx, resourceName, resourceNamespace)

			updated := &nvtenantv1alpha1.SecurityPolicy{}
			Expect(k8sClient.Get(ctx, nn, updated)).To(Succeed())
			Expect(updated.Status.Synced).To(BeTrue())
			Expect(updated.Status.ActiveCount).To(Equal(0))
		})
	})

	Context("mixed expired and active exemptions", func() {
		BeforeEach(func() {
			past := metav1.NewTime(time.Now().Add(-24 * time.Hour))
			future := metav1.NewTime(time.Now().Add(24 * time.Hour))
			policy := &nvtenantv1alpha1.SecurityPolicy{
				ObjectMeta: metav1.ObjectMeta{Name: resourceName, Namespace: resourceNamespace},
				Spec: nvtenantv1alpha1.SecurityPolicySpec{
					Exemptions: []nvtenantv1alpha1.VulnerabilityExemption{
						{
							CVEID:         "CVE-2023-EXPIRED",
							Image:         "nginx:latest",
							VEXStatus:     "affected",
							Justification: "Expired",
							ExpiresAt:     &nvtenantv1alpha1.Date{Time: past.Time},
						},
						{
							CVEID:         "CVE-2023-ACTIVE",
							Image:         "nginx:latest",
							VEXStatus:     "affected",
							Justification: "Still valid",
							ExpiresAt:     &nvtenantv1alpha1.Date{Time: future.Time},
						},
						{
							CVEID:         "CVE-2023-NOEXPIRY",
							Image:         "redis:latest",
							VEXStatus:     "not_affected",
							Justification: "No expiry set",
						},
					},
				},
			}
			err := k8sClient.Create(ctx, policy)
			if err != nil && !errors.IsAlreadyExists(err) {
				Expect(err).NotTo(HaveOccurred())
			}
		})

		AfterEach(func() { deletePolicy(resourceName, resourceNamespace) })

		It("should only count non-expired exemptions in ActiveCount", func() {
			reconcilePolicy(ctx, resourceName, resourceNamespace)

			updated := &nvtenantv1alpha1.SecurityPolicy{}
			Expect(k8sClient.Get(ctx, nn, updated)).To(Succeed())
			Expect(updated.Status.Synced).To(BeTrue())
			Expect(updated.Status.ActiveCount).To(Equal(2)) // ACTIVE + NOEXPIRY
		})
	})

	Context("multiple SecurityPolicies", func() {
		const secondName = "test-policy-two"

		BeforeEach(func() {
			p1 := &nvtenantv1alpha1.SecurityPolicy{
				ObjectMeta: metav1.ObjectMeta{Name: resourceName, Namespace: resourceNamespace},
				Spec: nvtenantv1alpha1.SecurityPolicySpec{
					Exemptions: []nvtenantv1alpha1.VulnerabilityExemption{
						{CVEID: "CVE-2023-P1A", Image: "nginx:latest", VEXStatus: "affected"},
						{CVEID: "CVE-2023-P1B", Image: "nginx:1.25", VEXStatus: "affected"},
					},
				},
			}
			p2 := &nvtenantv1alpha1.SecurityPolicy{
				ObjectMeta: metav1.ObjectMeta{Name: secondName, Namespace: resourceNamespace},
				Spec: nvtenantv1alpha1.SecurityPolicySpec{
					Exemptions: []nvtenantv1alpha1.VulnerabilityExemption{
						{CVEID: "CVE-2023-P2A", Image: "redis:latest", VEXStatus: "not_affected"},
					},
				},
			}
			for _, p := range []*nvtenantv1alpha1.SecurityPolicy{p1, p2} {
				err := k8sClient.Create(ctx, p)
				if err != nil && !errors.IsAlreadyExists(err) {
					Expect(err).NotTo(HaveOccurred())
				}
			}
		})

		AfterEach(func() {
			deletePolicy(resourceName, resourceNamespace)
			deletePolicy(secondName, resourceNamespace)
		})

		It("should count only own exemptions in ActiveCount per policy", func() {
			// Reconcile p1 — ActiveCount should reflect only p1's exemptions
			reconcilePolicy(ctx, resourceName, resourceNamespace)
			p1 := &nvtenantv1alpha1.SecurityPolicy{}
			Expect(k8sClient.Get(ctx, nn, p1)).To(Succeed())
			Expect(p1.Status.ActiveCount).To(Equal(2))

			// Reconcile p2 — ActiveCount should reflect only p2's exemptions
			reconcilePolicy(ctx, secondName, resourceNamespace)
			p2 := &nvtenantv1alpha1.SecurityPolicy{}
			Expect(k8sClient.Get(ctx, types.NamespacedName{Name: secondName, Namespace: resourceNamespace}, p2)).To(Succeed())
			Expect(p2.Status.ActiveCount).To(Equal(1))
		})

	})
	Context("entryToMap unit tests", func() {
		It("should convert NvProfileEntry correctly", func() {
			entry := NvProfileEntry{
				Name:    "CVE-1",
				Images:  []string{"nginx:latest"},
				Domains: []string{"default"},
				Days:    7,
				Comment: "test",
			}

			m := entryToMap(entry)

			Expect(m["name"]).To(Equal("CVE-1"))
			Expect(m["days"]).To(Equal(int64(7)))
			Expect(m["images"]).To(Equal([]interface{}{"nginx:latest"}))
			Expect(m["domains"]).To(Equal([]interface{}{"default"}))
			Expect(m["comment"]).To(Equal("test"))
		})

		It("should omit empty optional fields", func() {
			entry := NvProfileEntry{Name: "CVE-2"}
			m := entryToMap(entry)

			Expect(m).To(HaveKey("name"))
			Expect(m).NotTo(HaveKey("images"))
			Expect(m).NotTo(HaveKey("domains"))
			Expect(m).NotTo(HaveKey("days"))
			Expect(m).NotTo(HaveKey("comment"))
		})
	})
})

/*
Copyright 2026.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package v1alpha1

import (
	"context"
	"fmt"
	"strings"
	"time"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/webhook/admission"
)

const dateFormat = "02/01/2006"

// +kubebuilder:validation:Type=string
// +kubebuilder:validation:Pattern=`^\d{2}/\d{2}/\d{4}$`
type Date struct {
	time.Time `json:"-"`
}

// VulnerabilityExemption defines a specific CVE exemption
type VulnerabilityExemption struct {
	// The CVE ID, e.g., CVE-2024-1234
	CVEID string `json:"cveId"`
	// The specific image for which this exemption applies, e.g., "nginx:latest"
	Image string `json:"image"`
	// The number of days the cve is discovered but not yet fixed. (optional)
	Days int `json:"days,omitempty"`
	// The required expiration date for this exemption in dd/mm/yyyy format (optional)
	ExpiresAt *Date `json:"expiresAt,omitempty"`
	// VEX status for the exemption (required)
	VEXStatus string `json:"vexStatus"`
	// Justification for the exemption (optional)
	// example: component_not_present, vulnerable_code_not_present, vulnerable_code_not_in_execute_path, vulnerable_code_cannot_be_controlled_by_adversary, inline_mitigations_already_exist
	Justification string `json:"justification,omitempty"`
}

// SecurityPolicySpec defines the desired state of SecurityPolicy
type SecurityPolicySpec struct {
	Exemptions []VulnerabilityExemption `json:"exemptions"`
}

// SecurityPolicyStatus definieert de waargenomen staat
type SecurityPolicyStatus struct {
	// Synced geeft aan of de regels succesvol naar NeuVector zijn gepusht
	Synced bool `json:"synced"`
	// Aantal actieve uitzonderingen
	ActiveCount int `json:"activeCount"`
	// Tijdstip van de laatste succesvolle sync
	LastSync   *metav1.Time       `json:"lastSync,omitempty"`
	Conditions []metav1.Condition `json:"conditions,omitempty"`
}

// +kubebuilder:object:root=true
// +kubebuilder:subresource:status
// +kubebuilder:webhook:path=/validate-nvtenant-severinsdigitalsolutions-nl-v1alpha1-securitypolicy,mutating=false,failurePolicy=fail,sideEffects=None,groups=nvtenant.severinsdigitalsolutions.nl,resources=securitypolicies,verbs=create;update,versions=v1alpha1,name=vsecuritypolicy.kb.io,admissionReviewVersions=v1

// SecurityPolicy is the Schema for the securitypolicies API
type SecurityPolicy struct {
	metav1.TypeMeta `json:",inline"`

	// metadata is a standard object metadata
	// +optional
	metav1.ObjectMeta `json:"metadata,omitzero"`

	// spec defines the desired state of SecurityPolicy
	// +required
	Spec SecurityPolicySpec `json:"spec"`

	// status defines the observed state of SecurityPolicy
	// +optional
	Status SecurityPolicyStatus `json:"status,omitzero"`
}

func (r *SecurityPolicy) ValidateCreate(ctx context.Context, obj *SecurityPolicy) (admission.Warnings, error) {
	return nil, r.validateSecurityPolicy()
}

func (r *SecurityPolicy) ValidateUpdate(ctx context.Context, oldObj *SecurityPolicy, newObj *SecurityPolicy) (admission.Warnings, error) {
	return nil, newObj.validateSecurityPolicy()
}

func (r *SecurityPolicy) ValidateDelete(ctx context.Context, obj *SecurityPolicy) (admission.Warnings, error) {
	return nil, nil
}

func (r *SecurityPolicy) validateSecurityPolicy() error {
	for i, ex := range r.Spec.Exemptions {

		// Validate date is not in the past
		if ex.ExpiresAt != nil {
			if ex.ExpiresAt.Time.IsZero() {
				return fmt.Errorf("exemptions[%d].expiresAt is invalid", i)
			}

			if time.Now().After(ex.ExpiresAt.Time) {
				return fmt.Errorf("exemptions[%d].expiresAt cannot be in the past", i)
			}
		}

		// Example: ensure CVE format basic sanity
		if !strings.HasPrefix(ex.CVEID, "CVE-") {
			return fmt.Errorf("exemptions[%d].cveId must start with CVE-", i)
		}
	}
	return nil
}

// +kubebuilder:object:root=true

// SecurityPolicyList contains a list of SecurityPolicy
type SecurityPolicyList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitzero"`
	Items           []SecurityPolicy `json:"items"`
}

// Date is a custom type that serializes as dd/mm/yyyy in JSON/YAML
// +kubebuilder:validation:Pattern=`^\d{2}/\d{2}/\d{4}$`
func (d Date) MarshalJSON() ([]byte, error) {
	if d.IsZero() {
		return []byte("null"), nil
	}
	return []byte(`"` + d.Format(dateFormat) + `"`), nil
}

func (d *Date) UnmarshalJSON(data []byte) error {
	s := strings.Trim(string(data), `"`)
	if s == "null" || s == "" {
		return nil
	}
	t, err := time.Parse(dateFormat, s)
	if err != nil {
		return fmt.Errorf("invalid date format, expected dd/mm/yyyy: %w", err)
	}
	d.Time = t
	return nil
}
func (r *SecurityPolicy) SetupWebhookWithManager(mgr ctrl.Manager) error {
	return ctrl.NewWebhookManagedBy(mgr, r).
		WithValidator(r).
		Complete()
}

// DeepCopyInto is required for controller-gen
func (d *Date) DeepCopyInto(out *Date) {
	*out = *d
}

func init() {
	SchemeBuilder.Register(&SecurityPolicy{}, &SecurityPolicyList{})
}

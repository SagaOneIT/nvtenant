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
	"fmt"
	"strings"
	"time"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
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

// DeepCopyInto is required for controller-gen
func (d *Date) DeepCopyInto(out *Date) {
	*out = *d
}

func init() {
	SchemeBuilder.Register(&SecurityPolicy{}, &SecurityPolicyList{})
}

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
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// EDIT THIS FILE!  THIS IS SCAFFOLDING FOR YOU TO OWN!
// NOTE: json tags are required.  Any new fields you add must have json tags for the fields to be serialized.

// SecurityNotificationPolicySpec defines the desired state of SecurityNotificationPolicy
type SecurityNotificationPolicySpec struct {
	// The URL where notifications should be sent (e.g., Slack/Teams webhook)
	WebhookURL string `json:"webhookUrl"`

	// Minimum severity to notify (e.g., High, Critical)
	// +kubebuilder:default:=High
	MinSeverity string `json:"minSeverity,omitempty"`

	// Filter by event types (e.g., vulnerability, runtime, admission)
	EventTypes []string `json:"eventTypes,omitempty"`

	// Optional: Reference to a secret containing an API Key or Token (webhook token?)
	SecretRef string `json:"secretRef,omitempty"`
}

// SecurityNotificationPolicyStatus defines the observed state of SecurityNotificationPolicy.
type SecurityNotificationPolicyStatus struct {
	// +listType=map
	// +listMapKey=type
	// +optional
	Conditions []metav1.Condition `json:"conditions,omitempty"`

	// LastEventReceivedAt is the timestamp of the last NeuVector event processed.
	// +optional
	LastEventReceivedAt *metav1.Time `json:"lastEventReceivedAt,omitempty"`

	// EventsForwarded is the total number of events successfully forwarded.
	// +optional
	EventsForwarded int64 `json:"eventsForwarded,omitempty"`

	// EventsDropped is the total number of events dropped due to filtering or errors.
	// +optional
	EventsDropped int64 `json:"eventsDropped,omitempty"`
}

// +kubebuilder:object:root=true
// +kubebuilder:subresource:status

// SecurityNotificationPolicy is the Schema for the securitynotificationpolicies API
type SecurityNotificationPolicy struct {
	metav1.TypeMeta `json:",inline"`

	// metadata is a standard object metadata
	// +optional
	metav1.ObjectMeta `json:"metadata,omitzero"`

	// spec defines the desired state of SecurityNotificationPolicy
	// +required
	Spec SecurityNotificationPolicySpec `json:"spec"`

	// status defines the observed state of SecurityNotificationPolicy
	// +optional
	Status SecurityNotificationPolicyStatus `json:"status,omitzero"`
}

// +kubebuilder:object:root=true

// SecurityNotificationPolicyList contains a list of SecurityNotificationPolicy
type SecurityNotificationPolicyList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitzero"`
	Items           []SecurityNotificationPolicy `json:"items"`
}

func init() {
	SchemeBuilder.Register(&SecurityNotificationPolicy{}, &SecurityNotificationPolicyList{})
}

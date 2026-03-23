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
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/go-logr/logr"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"sigs.k8s.io/controller-runtime/pkg/client"

	nvtenantv1alpha1 "nvtenant.severinsdigitalsolutions.nl/api/v1alpha1"
)

// NeuVectorEvent is the incoming payload from NeuVector.
// Adjust fields to match your actual NeuVector webhook payload.
type NeuVectorEvent struct {
	// Namespace the event originated from
	Namespace string `json:"namespace"`
	// Type of event e.g. "vulnerability", "runtime", "admission"
	Type string `json:"type"`
	// Severity e.g. "Critical", "High", "Medium", "Low"
	Severity string `json:"severity"`
	// Name of the workload or image
	Name string `json:"name"`
	// Message is the human-readable event description
	Message string `json:"message"`
	// ReportedAt is the event timestamp from NeuVector
	ReportedAt time.Time `json:"reportedAt"`
}

// severityLevel maps severity strings to numeric levels for comparison.
var severityLevel = map[string]int{
	"critical": 4,
	"high":     3,
	"medium":   2,
	"low":      1,
}

// NeuVectorEventHandler receives NeuVector events and routes them to tenant webhooks.
type NeuVectorEventHandler struct {
	Client client.Client
	Log    logr.Logger
}

func (h *NeuVectorEventHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	body, err := io.ReadAll(io.LimitReader(r.Body, 1<<20)) // 1MB limit
	if err != nil {
		h.Log.Error(err, "failed to read request body")
		http.Error(w, "failed to read body", http.StatusBadRequest)
		return
	}
	defer r.Body.Close()

	var event NeuVectorEvent
	if err := json.Unmarshal(body, &event); err != nil {
		h.Log.Error(err, "failed to parse NeuVector event")
		http.Error(w, "invalid JSON", http.StatusBadRequest)
		return
	}

	if event.Namespace == "" {
		h.Log.Info("dropping event: missing namespace")
		w.WriteHeader(http.StatusOK)
		return
	}

	ctx := r.Context()
	h.routeEvent(ctx, event, body)
	w.WriteHeader(http.StatusOK)
}

func (h *NeuVectorEventHandler) routeEvent(ctx context.Context, event NeuVectorEvent, rawBody []byte) {
	log := h.Log.WithValues("namespace", event.Namespace, "eventType", event.Type, "severity", event.Severity)

	// List all SecurityNotificationPolicies in the event's namespace
	var policyList nvtenantv1alpha1.SecurityNotificationPolicyList
	if err := h.Client.List(ctx, &policyList, client.InNamespace(event.Namespace)); err != nil {
		log.Error(err, "failed to list SecurityNotificationPolicies")
		return
	}

	if len(policyList.Items) == 0 {
		log.V(1).Info("no SecurityNotificationPolicy found in namespace, dropping event")
		return
	}

	for i := range policyList.Items {
		policy := &policyList.Items[i]

		if !h.matchesPolicy(event, policy.Spec) {
			log.V(1).Info("event filtered out by policy", "policy", policy.Name)
			h.incrementDropped(ctx, policy)
			continue
		}

		if err := h.forward(ctx, event, rawBody, policy); err != nil {
			log.Error(err, "failed to forward event", "policy", policy.Name, "webhookUrl", policy.Spec.WebhookURL)
			h.incrementDropped(ctx, policy)
		} else {
			log.Info("event forwarded", "policy", policy.Name)
			h.incrementForwarded(ctx, policy)
		}
	}
}

// matchesPolicy returns true if the event passes the policy's filters.
func (h *NeuVectorEventHandler) matchesPolicy(event NeuVectorEvent, spec nvtenantv1alpha1.SecurityNotificationPolicySpec) bool {
	// Check event type filter
	if len(spec.EventTypes) > 0 {
		matched := false
		for _, t := range spec.EventTypes {
			if strings.EqualFold(t, event.Type) {
				matched = true
				break
			}
		}
		if !matched {
			return false
		}
	}

	// Check minimum severity
	if spec.MinSeverity != "" {
		minLevel := severityLevel[strings.ToLower(spec.MinSeverity)]
		eventLevel := severityLevel[strings.ToLower(event.Severity)]
		if eventLevel < minLevel {
			return false
		}
	}

	return true
}

// forward POSTs the raw NeuVector payload to the tenant's webhook URL.
func (h *NeuVectorEventHandler) forward(_ context.Context, _ NeuVectorEvent, rawBody []byte, policy *nvtenantv1alpha1.SecurityNotificationPolicy) error {
	req, err := http.NewRequest(http.MethodPost, policy.Spec.WebhookURL, bytes.NewReader(rawBody))
	if err != nil {
		return fmt.Errorf("building request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")

	// TODO: if policy.Spec.SecretRef is set, load the token from the Secret and add as Bearer token
	// secret := &corev1.Secret{}
	// h.Client.Get(ctx, types.NamespacedName{Name: policy.Spec.SecretRef, Namespace: policy.Namespace}, secret)
	// req.Header.Set("Authorization", "Bearer " + string(secret.Data["token"]))

	httpClient := &http.Client{Timeout: 10 * time.Second}
	resp, err := httpClient.Do(req)
	if err != nil {
		return fmt.Errorf("sending request: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return fmt.Errorf("upstream returned %d", resp.StatusCode)
	}
	return nil
}

func (h *NeuVectorEventHandler) incrementForwarded(ctx context.Context, policy *nvtenantv1alpha1.SecurityNotificationPolicy) {
	patch := client.MergeFrom(policy.DeepCopy())
	policy.Status.EventsForwarded++
	now := metav1.Now()
	policy.Status.LastEventReceivedAt = &now
	if err := h.Client.Status().Patch(ctx, policy, patch); err != nil {
		h.Log.Error(err, "failed to patch status (forwarded)", "policy", policy.Name)
	}
}

func (h *NeuVectorEventHandler) incrementDropped(ctx context.Context, policy *nvtenantv1alpha1.SecurityNotificationPolicy) {
	patch := client.MergeFrom(policy.DeepCopy())
	policy.Status.EventsDropped++
	if err := h.Client.Status().Patch(ctx, policy, patch); err != nil {
		h.Log.Error(err, "failed to patch status (dropped)", "policy", policy.Name)
	}
}

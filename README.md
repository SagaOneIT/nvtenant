# NeuVector Multi-Tenant Security Operator

## Description

The **NeuVector Multi-Tenant Security Operator** automates vulnerability exception management and security event routing within NeuVector, based on Kubernetes Custom Resources. In a multi-tenant OpenShift environment, it enables application teams to self-service CVE exemptions and configure security notifications — without requiring cluster-admin access to NeuVector.

This project is designed to provide full traceability of exceptions, including VEX-compatible metadata (status and justification), directly visible in the NeuVector console.

---

## Key Features

### SecurityPolicy — CVE Exemption Management
- **Multi-Tenant Self-Service**: Teams manage their own exemptions in their own namespace without NeuVector cluster-admin rights.
- **VEX Compliance**: Supports VEX fields (`vexStatus`, `justification`) for full audit-trail compliance.
- **Automatic Lifecycle**: Exemptions expire automatically based on the `expiresAt` date.
- **Global Sync**: All namespaced policies are automatically merged into the global NeuVector `default` vulnerability profile.
- **Self-Healing**: The operator automatically creates the `default` NeuVector profile if it is missing.

### SecurityNotificationPolicy — Event Routing
- **Tenant-Scoped Webhooks**: Teams configure their own webhook endpoint (e.g., Slack, Teams) per namespace.
- **Severity Filtering**: Only forward events that meet or exceed a configured minimum severity (`Low`, `Medium`, `High`, `Critical`).
- **Event Type Filtering**: Filter by NeuVector event type (e.g., `vulnerability`, `runtime`, `admission`).
- **Observability**: The operator tracks `eventsForwarded`, `eventsDropped`, and `lastEventReceivedAt` per policy in the resource status.
- **Secret Support**: Optional `secretRef` for authenticated webhook endpoints (Bearer token).

---

## Architecture

**CVE Exemption Flow:**

```
[Namespace A: SecurityPolicy] ──┐
[Namespace B: SecurityPolicy] ──┼──► [NV Tenant Operator] ──► [NvVulnerabilityProfile/default]
[Namespace C: SecurityPolicy] ──┘
```

**Event Routing Flow:**

```
[NeuVector]
    |
    | POST /events
    v
[NV Tenant Operator]
    |
    | namespace match
    v
[SecurityNotificationPolicy]
    |
    +------------------+------------------+
    |                  |                  |
    v                  v                  v
[Slack Webhook]  [Teams Webhook]  [Custom Webhook]
 ```
---

## Custom Resources

### SecurityPolicy

Allows teams to declare CVE exemptions for their workloads.

```yaml
apiVersion: nvtenant.severinsdigitalsolutions.nl/v1alpha1
kind: SecurityPolicy
metadata:
  name: app-exemption
  namespace: my-team-namespace
spec:
  exemptions:
    - cveId: "CVE-2024-1234"
      image: "my-app:latest"
      vexStatus: "not_affected"
      justification: "component_not_present"
      days: 30
      expiresAt: "31/12/2026"
```

| Field           | Required | Description                                                                         |
|-----------------|----------|-------------------------------------------------------------------------------------|
| `cveId`         | yes      | CVE identifier (e.g. `CVE-2024-1234`)                                               |
| `image`         | yes      | Image name the exemption applies to                                                 |
| `vexStatus`     | no       | VEX status (`not_affected`, `affected`, `fixed`, `under_investigation`)             |
| `justification` | no       | VEX justification (`component_not_present`, `vulnerable_code_not_present`, etc.)   |
| `days`          | no       | Duration in days (informational)                                                    |
| `expiresAt`     | no       | Expiry date in `dd/mm/yyyy` format — exemption is excluded after this date          |

**Status fields:**

| Field         | Description                                       |
|---------------|---------------------------------------------------|
| `activeCount` | Number of currently active (non-expired) exemptions |
| `conditions`  | Standard Kubernetes condition array               |

---

### SecurityNotificationPolicy

Allows teams to configure where NeuVector security events are forwarded.

```yaml
apiVersion: nvtenant.severinsdigitalsolutions.nl/v1alpha1
kind: SecurityNotificationPolicy
metadata:
  name: slack-notifications
  namespace: my-team-namespace
spec:
  webhookUrl: "https://hooks.slack.com/services/T00000000/B00000000/XXXXXXXX"
  minSeverity: "High"
  eventTypes:
    - "vulnerability"
    - "runtime"
  secretRef: "my-webhook-secret"
```

| Field         | Required | Description                                                         |
|---------------|----------|---------------------------------------------------------------------|
| `webhookUrl`  | yes      | Target webhook URL (Slack, Teams, or any HTTP endpoint)             |
| `minSeverity` | no       | Minimum severity to forward. Default: `High`                        |
| `eventTypes`  | no       | List of NeuVector event types to forward. Empty = all types         |
| `secretRef`   | no       | Name of a Secret in the same namespace containing a Bearer token    |

**Status fields:**

| Field                 | Description                                           |
|-----------------------|-------------------------------------------------------|
| `eventsForwarded`     | Total number of events successfully forwarded         |
| `eventsDropped`       | Total number of events dropped (filtered or errored)  |
| `lastEventReceivedAt` | Timestamp of the last processed event                 |
| `conditions`          | Standard Kubernetes condition array                   |

---

## NeuVector Integration

The operator exposes a `/events` HTTP endpoint that NeuVector must be configured to POST to.

### Configure NeuVector Webhook

1. Log in to the NeuVector Console.
2. Navigate to **Settings** -> **Webhooks**.
3. Click **Add** and configure:
   - **Name:** `nvtenant-operator`
   - **URL:** `https://<operator-service>.<namespace>.svc.cluster.local:9443/events`
   - **Type:** Select the event types you want to route (Vulnerability, Runtime, Admission).
4. Save and enable the webhook.

> **Note:** The operator uses HTTPS (port `9443`). Ensure NeuVector trusts the CA that signed the operator's TLS certificate (typically managed by `cert-manager` or the OpenShift service CA).

---

## Deployment

### Helm (Recommended)

```bash
helm install nvtenant-operator oci://registry-1.docker.io/severinsm/nvtenant-operator --version 0.1.0 \
  --namespace nvtenant-operator \
  --create-namespace
```

### Prerequisites

- OpenShift / Kubernetes cluster
- NeuVector installed with the `nvvulnerabilityprofiles.neuvector.com` CRD
- `kubectl` / `oc` CLI

### Manual Deployment

**Install CRDs:**

```sh
make install
```

**Deploy the operator:**

```sh
make deploy IMG=severinsm/nvtenant-operator:latest
```

> **NOTE:** If you encounter RBAC errors, you may need cluster-admin privileges.

**Apply sample resources:**

```sh
kubectl apply -k config/samples/
```

### Uninstall

```sh
kubectl delete -k config/samples/
make uninstall
make undeploy
```

---

## Development

### Prerequisites

- Go v1.24.6+
- Docker 17.03+
- kubectl v1.11.3+
- Access to a Kubernetes v1.11.3+ cluster

### Run Tests

```sh
make test
```

### Build

```sh
make build
make docker-build IMG=severinsm/nvtenant-operator:dev
```

### Distribution

**Build a single-file installer:**

```sh
make build-installer IMG=severinsm/nvtenant-operator:tag
kubectl apply -f https://raw.githubusercontent.com/SagaOneIT/nvtenant/<tag>/dist/install.yaml
```

**Build Helm chart:**

```sh
kubebuilder edit --plugins=helm/v2-alpha
```

---

## Contributing

See `CONTRIBUTING.md` for guidelines. Run `make help` for all available targets.

More information: [Kubebuilder Documentation](https://book.kubebuilder.io/introduction.html)

---

## License

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

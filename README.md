# NeuVector Tenant Operator

## Description

De **SDS SecurityPolicy Operator** automatiseert het beheer van vulnerability uitzonderingen binnen NeuVector op basis van Custom Resources. In een multi-tenant OpenShift omgeving stelt deze operator applicatieteams in staat om zelfstandig CVE-vrijstellingen aan te vragen via `SecurityPolicy` objecten in hun eigen namespace. De operator aggregeert deze aanvragen, valideert de TTL (ExpiresAt) en synchroniseert ze naar het centrale `NvVulnerabilityProfile` van NeuVector.

Dit project is ontworpen om te voldoen aan de **BIO 2.0** richtlijnen door volledige traceerbaarheid te bieden van uitzonderingen, inclusief VEX-compatibele metadata zoals status en rechtvaardiging, direct zichtbaar in de NeuVector console.

## Key Features

- **Multi-tenant Self-Service**: Teams beheren hun eigen uitzonderingen zonder cluster-admin rechten in NeuVector.
- **VEX Compliance**: Ondersteuning voor VEX-velden (Status, Justification) voor audit-trail doeleinden.
- **Automatische Lifecycle**: Uitzonderingen verlopen automatisch op basis van de `expiresAt` datum (formaat `dd/mm/yyyy`).
- **Global Sync**: Automatische merge van alle namespaced policies naar het globale `default` NeuVector profiel.
- **Self-Healing**: De operator maakt het `default` NeuVector profiel automatisch aan als dit ontbreekt.

## Getting Started

### Installatie

```sh
make manifests
make install
make deploy IMG=<your-registry>/sds-operator:latest
```

### Gebruik

Maak een `SecurityPolicy` aan in je namespace:

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

## Architecture

De operator monitort alle `SecurityPolicy` resources en voert een globale reconciliatie uit op de `NvVulnerabilityProfile` (CRD van NeuVector). Hierdoor blijft de security posture consistent over het gehele platform terwijl de administratieve last voor het security team wordt verlaagd.

```
[Namespace A: SecurityPolicy] ──┐
[Namespace B: SecurityPolicy] ──┼──► [SDS Operator] ──► [NvVulnerabilityProfile/default]
[Namespace C: SecurityPolicy] ──┘
```

## Prerequisites

- OpenShift / Kubernetes cluster
- NeuVector geïnstalleerd met de `nvvulnerabilityprofiles.neuvector.com` CRD
- `kubectl` / `oc` CLI

## License

Apache 2.0

## Getting Started

### Prerequisites
- go version v1.24.6+
- docker version 17.03+.
- kubectl version v1.11.3+.
- Access to a Kubernetes v1.11.3+ cluster.

### To Deploy on the cluster
**Build and push your image to the location specified by `IMG`:**

```sh
make docker-build docker-push IMG=<some-registry>/neuvector:tag
```

**NOTE:** This image ought to be published in the personal registry you specified.
And it is required to have access to pull the image from the working environment.
Make sure you have the proper permission to the registry if the above commands don’t work.

**Install the CRDs into the cluster:**

```sh
make install
```

**Deploy the Manager to the cluster with the image specified by `IMG`:**

```sh
make deploy IMG=<some-registry>/neuvector:tag
```

> **NOTE**: If you encounter RBAC errors, you may need to grant yourself cluster-admin
privileges or be logged in as admin.

**Create instances of your solution**
You can apply the samples (examples) from the config/sample:

```sh
kubectl apply -k config/samples/
```

>**NOTE**: Ensure that the samples has default values to test it out.

### To Uninstall
**Delete the instances (CRs) from the cluster:**

```sh
kubectl delete -k config/samples/
```

**Delete the APIs(CRDs) from the cluster:**

```sh
make uninstall
```

**UnDeploy the controller from the cluster:**

```sh
make undeploy
```

## Project Distribution

Following the options to release and provide this solution to the users.

### By providing a bundle with all YAML files

1. Build the installer for the image built and published in the registry:

```sh
make build-installer IMG=<some-registry>/neuvector:tag
```

**NOTE:** The makefile target mentioned above generates an 'install.yaml'
file in the dist directory. This file contains all the resources built
with Kustomize, which are necessary to install this project without its
dependencies.

2. Using the installer

Users can just run 'kubectl apply -f <URL for YAML BUNDLE>' to install
the project, i.e.:

```sh
kubectl apply -f https://raw.githubusercontent.com/<org>/neuvector/<tag or branch>/dist/install.yaml
```

### By providing a Helm Chart

1. Build the chart using the optional helm plugin

```sh
kubebuilder edit --plugins=helm/v2-alpha
```

2. See that a chart was generated under 'dist/chart', and users
can obtain this solution from there.

**NOTE:** If you change the project, you need to update the Helm Chart
using the same command above to sync the latest changes. Furthermore,
if you create webhooks, you need to use the above command with
the '--force' flag and manually ensure that any custom configuration
previously added to 'dist/chart/values.yaml' or 'dist/chart/manager/manager.yaml'
is manually re-applied afterwards.

## Contributing
// TODO(user): Add detailed information on how you would like others to contribute to this project

**NOTE:** Run `make help` for more information on all potential `make` targets

More information can be found via the [Kubebuilder Documentation](https://book.kubebuilder.io/introduction.html)

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


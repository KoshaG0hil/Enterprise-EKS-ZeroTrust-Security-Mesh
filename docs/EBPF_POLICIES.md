# Cilium eBPF Network Policies & Microsegmentation Guide

## 1. Zero-Trust Default-Deny Architecture

Under the Zero-Trust network paradigm, every pod endpoint starts in an implicit **Deny-All** state. No pod is permitted to communicate with another pod or access external network destinations unless an explicit `CiliumNetworkPolicy` is applied.

### Baseline Invariant Policy: Default-Deny
- **File**: `policies/cilium/01_default_deny_all.yaml`
- **Scope**: All pods in namespace `production`.
- **Allowed Exception**: Outbound UDP/TCP port 53 exclusively to `kube-system:kube-dns` for domain resolution.

---

## 2. Layer 7 API-Aware Microsegmentation

Traditional Kubernetes NetworkPolicies only operate at Layer 3 (IP) and Layer 4 (Port). Cilium utilizes eBPF and Envoy proxies to enforce Layer 7 application semantics:

```yaml
apiVersion: cilium.io/v2
kind: CiliumNetworkPolicy
metadata:
  name: allow-frontend-to-backend-l7
  namespace: production
spec:
  endpointSelector:
    matchLabels:
      app: payment-backend
  ingress:
    - fromEndpoints:
        - matchLabels:
            app: frontend-gateway
      toPorts:
        - ports:
            - port: "8080"
              protocol: TCP
          rules:
            http:
              - method: "GET"
                path: "/api/v1/.*"
              - method: "POST"
                path: "/api/v1/checkout"
```

Any unauthorized HTTP verb (e.g. `DELETE /api/v1/users`) or unapproved URI path is dropped at the socket layer before reaching the backend container.

---

## 3. FQDN-Based Egress Filtering (Data Exfiltration Prevention)

Adversaries exfiltrating data typically attempt to open outbound TCP/UDP channels to command-and-control (C2) servers or public IP addresses. 

Cilium eBPF FQDN filtering inspects DNS queries made by pods and dynamically programs eBPF maps to permit traffic only to verified domain endpoints:
- `*.amazonaws.com` (Port 443)
- `dynamodb.us-east-1.amazonaws.com`
- `s3.us-east-1.amazonaws.com`

All other public IP ranges (e.g., direct connections to unknown external IPs) are dropped instantly at the kernel layer.

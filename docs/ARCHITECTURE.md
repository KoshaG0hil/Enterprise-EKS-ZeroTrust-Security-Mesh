# Enterprise EKS Zero-Trust Security Mesh Architecture

## 1. Executive Summary

This architecture establishes an autonomous Zero-Trust runtime defense mesh on Amazon EKS (Kubernetes 1.30). By combining **OPA Gatekeeper admission controls**, **Cilium eBPF network microsegmentation**, and **Falco real-time kernel threat hunting**, the platform achieves sub-second detection and isolation of compromised pods while adhering to **CIS Amazon EKS Benchmark v1.4.0** and **NIST SP 800-190 (Application Container Security Guide)**.

---

## 2. Structural Mesh Topology

```text
       +-------------------------------------------------------------------------+
       |                         Amazon EKS Control Plane                        |
       |  (Audit Logging, KMS Envelope Secrets Encryption, Private API Endpoint) |
       +------------------------------------+------------------------------------+
                                            |
                                            v
       +-------------------------------------------------------------------------+
       |                 Admission Layer: OPA Gatekeeper Webhook                 |
       |    • Disallow Privileged Containers    • Require ReadOnly RootFS        |
       |    • Enforce Non-Root UID              • Block HostPath Volume Mounts   |
       +------------------------------------+------------------------------------+
                                            | (Valid Pods Admitted)
                                            v
+---------------------------------------------------------------------------------------+
|                               Worker Node (eBPF Kernel Layer)                         |
|                                                                                       |
|  +---------------------------+                         +---------------------------+  |
|  |     payment-gateway       | -- [L7 HTTP Filter] --> |     auth-vault-token      |  |
|  | (ReadOnly RootFS, NonRoot)|                         | (Cilium eBPF Enforced)    |  |
|  +---------------------------+                         +---------------------------+  |
|                                                                                       |
|  +---------------------------+                         +---------------------------+  |
|  |  compromised-web-frontend |                         |    quarantine-deny-all    |  |
|  |   (/bin/sh spawned alert) | -- [eBPF Drop All] ---> |  (Zero-Traffic Isolation) |  |
|  +-------------+-------------+                         +---------------------------+  |
|                |                                                                      |
|                v                                                                      |
|      [Falco eBPF Probe]                                                               |
|                |                                                                      |
+----------------|----------------------------------------------------------------------+
                 | (Runtime Threat Alert)
                 v
   +---------------------------+          +---------------------------+
   |     Amazon EventBridge    | -------> |   Lambda Pod Isolator     |
   | (Falco Security Filter)   |          | (Applies eBPF Quarantine) |
   +---------------------------+          +---------------------------+
```

---

## 3. Defense-in-Depth Layering

1. **Shift-Left Admission Control**: OPA Gatekeeper intercepts all Pod creation and mutation requests before they hit the etcd data store, rejecting privileged containers, writable filesystems, and hostPath mounts.
2. **eBPF Kernel-Level Microsegmentation**: Cilium operates directly in the Linux kernel using eBPF programs, enforcing L3/L4/L7 policy filtering with near-zero latency overhead.
3. **Behavioral Runtime Threat Detection**: Falco attaches to kernel tracepoints to inspect process executions, file writes, and network sockets, triggering alerts when anomalous activity occurs.
4. **Autonomous Quarantine**: EventBridge captures Falco alerts and invokes AWS Lambda, which dynamically labels the target pod and injects an eBPF `quarantine-deny-all` network policy in under 600ms without terminating the pod, preserving process memory and disk for digital forensics.

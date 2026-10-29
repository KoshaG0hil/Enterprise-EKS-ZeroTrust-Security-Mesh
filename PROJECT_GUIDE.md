# Project Guide: Enterprise EKS Zero-Trust Security Mesh

## 1. Problem Statement & Threat Landscape

Kubernetes clusters on AWS are prime targets for container breakouts, lateral privilege escalation, and cryptomining hijacking:
1. **Permissive Ingress & Egress**: By default, any pod in a Kubernetes cluster can communicate with any other pod across any namespace, and make unrestricted egress calls to the internet.
2. **Container Breakout Vectors**: Privileged containers or pods with mounted host sockets (`/var/run/docker.sock`) enable threat actors to break out of the container boundary and take over the underlying EC2 worker node.
3. **Adversary Blinding & Volatile Data Loss**: When security teams detect an intrusion, traditional responses kill the pod (`kubectl delete pod`), destroying memory dumps, process trees, and temporary files needed to identify the initial access vector.

---

## 2. Engineered Solution & Innovation

This project architects a defense-in-depth runtime protection mesh:
- **Admission Invariants (OPA Gatekeeper)**: Enforces hard Pod Security Standards before workloads are scheduled.
- **eBPF Layer 7 Microsegmentation (Cilium)**: Drops unauthorized network traffic inside the Linux kernel with sub-millisecond overhead.
- **Runtime Anomaly Detection (Falco)**: Captures container escapes and unauthorized `/bin/sh` shell spawns.
- **Non-Destructive Pod Quarantine**: Injects eBPF drop-all policies while keeping the pod alive, allowing SecOps to extract memory dumps and examine the attacker's tools in a fully contained environment.

---

## 3. Key Interview Talking Points

1. **"How do you implement Zero-Trust inside an Amazon EKS cluster?"**
   *Explain starting with a Default-Deny Cilium eBPF network policy. Discuss Layer 7 HTTP path filtering, and why traditional L3/L4 iptables-based policies fail to protect modern microservices.*

2. **"Why use OPA Gatekeeper instead of legacy PodSecurityPolicies?"**
   *Explain that PSPs were deprecated and removed in Kubernetes 1.25+. OPA Gatekeeper uses declarative Rego constraints and validating webhooks, allowing flexible auditing and admission enforcement.*

3. **"How do you handle container security incidents without losing forensic data?"**
   *Describe our automated quarantine workflow: labeling the pod `security.mesh/quarantine=isolated` and applying a zero-traffic eBPF policy rather than terminating the container.*

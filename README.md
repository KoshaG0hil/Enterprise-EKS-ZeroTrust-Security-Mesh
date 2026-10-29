# Enterprise Kubernetes (EKS) Zero-Trust Security & eBPF Threat Mesh

[![Build Status](https://github.com/KoshaG0hil/Enterprise-EKS-ZeroTrust-Security-Mesh/actions/workflows/ci.yml/badge.svg)](https://github.com/KoshaG0hil/Enterprise-EKS-ZeroTrust-Security-Mesh/actions/workflows/ci.yml)
[![Pages Deployment](https://github.com/KoshaG0hil/Enterprise-EKS-ZeroTrust-Security-Mesh/actions/workflows/pages.yml/badge.svg)](https://koshag0hil.github.io/Enterprise-EKS-ZeroTrust-Security-Mesh/)
[![Kubernetes Version](https://img.shields.io/badge/Kubernetes-EKS%201.30-326ce5.svg)](https://kubernetes.io/)
[![Cilium eBPF](https://img.shields.io/badge/Cilium-eBPF%20Mesh-orange.svg)](https://cilium.io/)
[![OPA Gatekeeper](https://img.shields.io/badge/OPA-Gatekeeper%20v3.16-teal.svg)](https://open-policy-agent.github.io/gatekeeper/)
[![Falco Runtime](https://img.shields.io/badge/Falco-Runtime%20Threats-00aec7.svg)](https://falco.org/)
[![Compliance](https://img.shields.io/badge/Compliance-CIS%20EKS%20v1.4.0%20%7C%20NIST%20SP%20800--190-emerald.svg)](https://www.cisecurity.org/)
[![Tests](https://img.shields.io/badge/Tests-100%25%20Passing%20(Pytest)-brightgreen.svg)](https://github.com/KoshaG0hil/Enterprise-EKS-ZeroTrust-Security-Mesh)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)

> **Enterprise Amazon EKS Zero-Trust container security mesh integrating OPA Gatekeeper shift-left admission controls, Cilium eBPF Layer 7 microsegmentation, Falco real-time kernel threat hunting, and automated sub-second pod quarantine.**

🔗 **Live Interactive Cyber SOC Console & Simulator:** [https://koshag0hil.github.io/Enterprise-EKS-ZeroTrust-Security-Mesh/](https://koshag0hil.github.io/Enterprise-EKS-ZeroTrust-Security-Mesh/)

---

## Architecture Overview

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

## Key Capabilities

1. **OPA Gatekeeper Admission Controls**:
   - `01_disallow_privileged_containers.yaml`: Blocks privileged containers and capability escalations (`CAP_SYS_ADMIN`).
   - `02_require_readonly_root_filesystem.yaml`: Enforces read-only root filesystems, preventing attackers from writing backdoors to `/bin` or `/etc`.
   - `03_block_hostpath_mounts.yaml`: Restricts host filesystem mounting, mitigating node breakout vectors.
   - `04_enforce_non_root_user.yaml`: Mandates that containers run as non-root user UIDs (> 1000).

2. **Cilium eBPF Layer 7 Microsegmentation**:
   - `01_default_deny_all.yaml`: Zero-trust default-deny on all ingress and egress traffic.
   - `02_strict_microsegmentation.yaml`: Enforces HTTP L7 route filtering (e.g. permitting only `GET /api/v1/*` from frontend to backend).
   - `03_egress_fqdn_filtering.yaml`: Blocks arbitrary public IPs, allowing egress only to explicit AWS domain names (`*.amazonaws.com`).

3. **Falco Runtime Threat Detection**:
   - Kernel tracepoint monitoring detecting interactive shells (`/bin/sh`), unauthorized file writes, and outbound Monero mining pool traffic.

4. **Sub-Second Autonomous Pod Quarantine**:
   - EventBridge and AWS Lambda event mesh that labels compromised pods with `security.mesh/quarantine=isolated` and applies a dynamic `quarantine-deny-all` eBPF policy in under 600ms without killing the container, preserving forensic evidence for SecOps teams.

5. **Infrastructure as Code (Terraform)**:
   - Full Terraform module (`terraform/`) provisioning the hardened EKS 1.30 cluster, KMS envelope encryption for Kubernetes secrets, and EventBridge auto-quarantine pipeline.

---

## Quickstart & CLI Commands

### 1. Installation
```bash
git clone https://github.com/KoshaG0hil/Enterprise-EKS-ZeroTrust-Security-Mesh.git
cd Enterprise-EKS-ZeroTrust-Security-Mesh
python -m venv venv
# On Windows:
.\venv\Scripts\activate
# On Linux/macOS:
source venv/bin/activate
pip install -r requirements.txt
```

### 2. Audit EKS Cluster Security Posture
```bash
python -m src.cli audit-cluster
```

### 3. Run Attack Simulation & Autonomous Quarantine
```bash
python -m src.cli simulate
```

### 4. Run Pytest Test Suite
```bash
pytest -v
```

---

## Terraform Deployment

```bash
cd terraform
cp terraform.tfvars.example terraform.tfvars
terraform init
terraform plan
terraform apply
```

---

## Author & Engineering Attribution

**Kosha Gohil**  
*AWS Cloud Security & DevSecOps Engineer*  
- **LinkedIn:** [linkedin.com/in/kosha-gohil](https://www.linkedin.com/in/kosha-gohil/)  
- **GitHub:** [@KoshaG0hil](https://github.com/KoshaG0hil)

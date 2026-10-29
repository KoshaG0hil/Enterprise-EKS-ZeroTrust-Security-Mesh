# SecOps Incident Response Runbooks for EKS Zero-Trust Mesh

## Runbook 1: Immediate Pod Quarantine & Containment

### Objective
Isolate an actively exploited or compromised container within 600 milliseconds to prevent lateral movement across the Kubernetes cluster.

### Trigger Conditions
- Falco alert: `Terminal Shell Spawned in Container` (Priority: CRITICAL).
- Falco alert: `Outbound Connection to Crypto Mining Pool` (Priority: CRITICAL).
- Amazon GuardDuty EKS Runtime Monitoring finding: `Execution:Kubernetes/MaliciousFile` or `Execution:Kubernetes/SuspiciousTool`.

### Execution Procedure
1. **Automated EventBridge Route**:
   The alert is ingested via EventBridge and passed to `lambda_falco_quarantine.py`.
2. **eBPF Drop-All Policy Attachment**:
   The controller attaches the `quarantine-deny-all` Cilium policy to the specific pod labels.
3. **Manual CLI Override (if needed)**:
   ```bash
   python -m src.cli simulate
   ```
4. **Forensic Preservation**:
   Do **NOT** delete or kill the pod (`kubectl delete pod`). The process memory, container filesystem overlay, and network socket tables remain frozen for memory dumping and analysis.

---

## Runbook 2: Forensic Triage & Evidence Collection

### Objective
Extract volatile forensic evidence from an isolated pod without breaking containment.

### Procedure
1. Verify pod is safely quarantined:
   ```bash
   kubectl get pod <pod-name> --show-labels | grep quarantine=isolated
   ```
2. Attach forensic sidecar container or capture container PID:
   ```bash
   crictl inspect --output json <container-id> | jq '.info.pid'
   ```
3. Dump volatile memory:
   ```bash
   gcore -o /forensics/memory_dump.core <pid>
   ```
4. Snapshot node EBS root volume in AWS:
   ```bash
   aws ec2 create-snapshot --volume-id vol-0123456789abcdef0 --description "Forensic snapshot of compromised worker node"
   ```

---

## Runbook 3: Safe Post-Remediation De-Quarantine

### Objective
Release a verified benign or remediated pod back into the production service mesh.

```bash
python -m src.cli audit-cluster
```
Verify 100% compliance before removing quarantine labels:
```bash
kubectl label pod <pod-name> security.mesh/quarantine-
```

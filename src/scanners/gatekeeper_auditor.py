"""OPA Gatekeeper Admission & Static Audit Controller."""

from typing import List

from ..core.config import GatekeeperViolation, PodContext, Severity


class GatekeeperAuditor:
    """Evaluates Kubernetes Pod specifications against OPA Gatekeeper constraint policies."""

    def audit_pod(self, pod: PodContext) -> List[GatekeeperViolation]:
        """Audits a single Pod against all defined Gatekeeper constraints."""
        violations: List[GatekeeperViolation] = []

        # 1. Privileged Container Check
        if pod.privileged:
            violations.append(
                GatekeeperViolation(
                    rule_id="GK-01-NO-PRIVILEGED",
                    constraint_name="psp-disallow-privileged-containers",
                    pod_name=pod.name,
                    namespace=pod.namespace,
                    severity=Severity.CRITICAL,
                    description="Pod contains containers running in privileged mode, granting host capabilities.",
                    remediation_advice="Set securityContext.privileged: false and drop CAP_SYS_ADMIN capabilities.",
                )
            )

        # 2. ReadOnly Root Filesystem Check
        if not pod.readonly_root_fs and pod.namespace in ["production", "workloads"]:
            violations.append(
                GatekeeperViolation(
                    rule_id="GK-02-READONLY-ROOTFS",
                    constraint_name="psp-require-readonly-root-filesystem",
                    pod_name=pod.name,
                    namespace=pod.namespace,
                    severity=Severity.HIGH,
                    description="Root filesystem is writable, permitting malware persistence and binary tampering.",
                    remediation_advice="Set securityContext.readOnlyRootFilesystem: true and use emptyDir for scratch storage.",
                )
            )

        # 3. HostPath Volume Mount Check
        if pod.hostpath_mounts:
            violations.append(
                GatekeeperViolation(
                    rule_id="GK-03-NO-HOSTPATH",
                    constraint_name="psp-block-hostpath-mounts",
                    pod_name=pod.name,
                    namespace=pod.namespace,
                    severity=Severity.CRITICAL,
                    description=f"Pod mounts host paths: {', '.join(pod.hostpath_mounts)}, exposing node host escape risk.",
                    remediation_advice="Remove hostPath volume mounts; use PVCs or ConfigMaps instead.",
                )
            )

        # 4. Non-Root User Execution Check
        if not pod.run_as_non_root and pod.namespace in ["production", "workloads"]:
            violations.append(
                GatekeeperViolation(
                    rule_id="GK-04-MUST-RUN-NON-ROOT",
                    constraint_name="psp-enforce-non-root-user",
                    pod_name=pod.name,
                    namespace=pod.namespace,
                    severity=Severity.HIGH,
                    description="Container runs as root (UID 0), violating principle of least privilege.",
                    remediation_advice="Set securityContext.runAsNonRoot: true and specify runAsUser > 1000 in Dockerfile.",
                )
            )

        return violations

    def audit_cluster(self, pods: List[PodContext]) -> List[GatekeeperViolation]:
        """Audits all pods in cluster and aggregates Gatekeeper violations."""
        all_violations: List[GatekeeperViolation] = []
        for pod in pods:
            all_violations.extend(self.audit_pod(pod))
        return all_violations

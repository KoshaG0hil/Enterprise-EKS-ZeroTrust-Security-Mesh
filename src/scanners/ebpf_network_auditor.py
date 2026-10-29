"""Cilium eBPF Network Policy Auditor."""

from typing import List

from ..core.config import CiliumNetworkViolation, PodContext, Severity


class EBPFNetworkAuditor:
    """Audits Pod network isolation and Cilium eBPF zero-trust policy coverage."""

    def audit_pod_network(self, pod: PodContext) -> List[CiliumNetworkViolation]:
        """Checks if pod has active Cilium eBPF network security policies attached."""
        violations: List[CiliumNetworkViolation] = []

        if not pod.has_cilium_policy:
            violations.append(
                CiliumNetworkViolation(
                    pod_name=pod.name,
                    namespace=pod.namespace,
                    missing_policy="CiliumNetworkPolicy (Default-Deny / L7 Filter)",
                    severity=Severity.HIGH,
                    risk_summary="Pod is exposed to all East-West pod traffic and unrestrained egress.",
                )
            )

        return violations

    def audit_cluster_network(self, pods: List[PodContext]) -> List[CiliumNetworkViolation]:
        """Audits all cluster pods for eBPF network policy posture."""
        violations: List[CiliumNetworkViolation] = []
        for pod in pods:
            violations.extend(self.audit_pod_network(pod))
        return violations

"""Tests for Cilium eBPF Network Auditor."""

from src.scanners.ebpf_network_auditor import EBPFNetworkAuditor


def test_clean_pod_has_active_ebpf_policy(clean_pod):
    auditor = EBPFNetworkAuditor()
    violations = auditor.audit_pod_network(clean_pod)
    assert len(violations) == 0


def test_detects_unprotected_pod_missing_cilium_policy(non_compliant_pod):
    auditor = EBPFNetworkAuditor()
    violations = auditor.audit_pod_network(non_compliant_pod)
    assert len(violations) == 1
    assert "CiliumNetworkPolicy" in violations[0].missing_policy

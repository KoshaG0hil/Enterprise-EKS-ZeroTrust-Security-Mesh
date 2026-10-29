"""Tests for OPA Gatekeeper Auditor."""

from src.scanners.gatekeeper_auditor import GatekeeperAuditor


def test_clean_pod_has_no_gatekeeper_violations(clean_pod):
    auditor = GatekeeperAuditor()
    violations = auditor.audit_pod(clean_pod)
    assert len(violations) == 0


def test_detects_all_gatekeeper_violations(non_compliant_pod):
    auditor = GatekeeperAuditor()
    violations = auditor.audit_pod(non_compliant_pod)

    # Privileged, ReadOnly RootFS, HostPath, and Non-Root UID
    assert len(violations) == 4
    rule_ids = [v.rule_id for v in violations]
    assert "GK-01-NO-PRIVILEGED" in rule_ids
    assert "GK-02-READONLY-ROOTFS" in rule_ids
    assert "GK-03-NO-HOSTPATH" in rule_ids
    assert "GK-04-MUST-RUN-NON-ROOT" in rule_ids

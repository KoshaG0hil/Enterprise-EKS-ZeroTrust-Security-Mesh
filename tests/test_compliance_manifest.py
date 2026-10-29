"""Tests for Compliance Manifest Generator."""

from src.core.config import ClusterAuditResult
from src.reporters.compliance_manifest import ComplianceManifestGenerator


def test_calculate_score_deductions(clean_pod):
    score_clean = ComplianceManifestGenerator.calculate_score([clean_pod], 0)
    assert score_clean == 100.0

    score_drifted = ComplianceManifestGenerator.calculate_score([clean_pod], 2)
    assert score_drifted == 75.0


def test_generate_manifest_and_sha256_integrity(clean_pod, non_compliant_pod):
    generator = ComplianceManifestGenerator()
    pods = [clean_pod, non_compliant_pod]

    audit_result = ClusterAuditResult(
        total_evaluated_pods=2,
        compliant_pods=1,
        quarantined_pods=0,
        compliance_score=75.0,
    )

    manifest = generator.generate(audit_result, pods)

    assert "sha256_checksum" in manifest
    assert len(manifest["sha256_checksum"]) == 64
    assert manifest["summary"]["total_pods_evaluated"] == 2
    assert manifest["summary"]["compliant_pods"] == 1

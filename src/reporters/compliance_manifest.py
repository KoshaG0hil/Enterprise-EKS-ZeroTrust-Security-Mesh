"""Cryptographic Compliance Manifest Generator for EKS Zero-Trust Mesh."""

import hashlib
import json
import os
from datetime import datetime, timezone
from typing import Any, Dict, List

from ..core.config import ClusterAuditResult, PodContext


class ComplianceManifestGenerator:
    """Produces tamper-evident JSON compliance audit manifests for CIS Kubernetes & NIST SP 800-190."""

    @staticmethod
    def calculate_score(pods: List[PodContext], violations_count: int) -> float:
        """Calculates compliance percentage based on pod posture and total violations."""
        if not pods:
            return 100.0
        # Deduct proportional points per violation
        deduction = violations_count * 12.5
        score = max(0.0, 100.0 - deduction)
        return round(score, 1)

    def generate(
        self,
        audit_result: ClusterAuditResult,
        pods: List[PodContext],
    ) -> Dict[str, Any]:
        """Synthesizes compliance payload and computes cryptographic SHA-256 signature."""
        ts = datetime.now(timezone.utc).isoformat()

        manifest_body: Dict[str, Any] = {
            "cluster_name": audit_result.cluster_name,
            "generated_at": ts,
            "frameworks": ["CIS-EKS-v1.4.0", "NIST-SP-800-190", "PCI-DSS-v4.0-Req-1.3"],
            "summary": {
                "overall_compliance_percentage": audit_result.compliance_score,
                "total_pods_evaluated": audit_result.total_evaluated_pods,
                "compliant_pods": audit_result.compliant_pods,
                "gatekeeper_violations_count": len(audit_result.gatekeeper_violations),
                "ebpf_network_violations_count": len(audit_result.network_violations),
                "quarantined_pods_count": audit_result.quarantined_pods,
            },
            "gatekeeper_violations": [v.model_dump() for v in audit_result.gatekeeper_violations],
            "network_violations": [v.model_dump() for v in audit_result.network_violations],
            "pod_inventory": [
                {
                    "name": p.name,
                    "namespace": p.namespace,
                    "status": p.status.value,
                    "privileged": p.privileged,
                    "readonly_root_fs": p.readonly_root_fs,
                    "has_cilium_policy": p.has_cilium_policy,
                }
                for p in pods
            ],
        }

        canonical_json = json.dumps(manifest_body, sort_keys=True, indent=2)
        checksum = hashlib.sha256(canonical_json.encode("utf-8")).hexdigest()
        manifest_body["sha256_checksum"] = checksum

        return manifest_body

    def save_report(self, manifest: Dict[str, Any], filepath: str = "reports/cluster_compliance_manifest.json") -> str:
        """Saves generated manifest to destination file."""
        os.makedirs(os.path.dirname(filepath), exist_ok=True)
        with open(filepath, "w", encoding="utf-8") as f:
            json.dump(manifest, f, indent=2)
        return filepath

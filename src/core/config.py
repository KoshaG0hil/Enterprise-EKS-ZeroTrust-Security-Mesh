"""Enterprise EKS Zero-Trust Configuration & Data Models."""

from enum import Enum
from typing import Dict, List, Optional

from pydantic import BaseModel, Field


class Severity(str, Enum):
    INFO = "INFO"
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"


class PodStatus(str, Enum):
    HEALTHY = "HEALTHY"
    VIOLATION_DETECTED = "VIOLATION_DETECTED"
    QUARANTINED = "QUARANTINED"
    TERMINATED = "TERMINATED"


class PodContext(BaseModel):
    """Contextual metadata representing a Kubernetes Pod in EKS."""

    name: str
    namespace: str
    labels: Dict[str, str] = Field(default_factory=dict)
    privileged: bool = False
    readonly_root_fs: bool = True
    run_as_non_root: bool = True
    hostpath_mounts: List[str] = Field(default_factory=list)
    has_cilium_policy: bool = True
    status: PodStatus = PodStatus.HEALTHY
    ip_address: Optional[str] = "10.0.1.42"
    node_name: Optional[str] = "ip-10-0-1-100.ec2.internal"


class GatekeeperViolation(BaseModel):
    """Represents a Pod policy admission violation under OPA Gatekeeper."""

    rule_id: str
    constraint_name: str
    pod_name: str
    namespace: str
    severity: Severity
    description: str
    remediation_advice: str


class CiliumNetworkViolation(BaseModel):
    """Represents an unsegmented or unprotected Pod endpoint."""

    pod_name: str
    namespace: str
    missing_policy: str
    severity: Severity
    risk_summary: str


class FalcoAlert(BaseModel):
    """Normalized runtime security threat event emitted by Falco."""

    rule_name: str
    priority: Severity
    pod_name: str
    namespace: str
    container_id: str
    message: str
    timestamp: str
    tags: List[str] = Field(default_factory=list)


class QuarantineAction(BaseModel):
    """Record of an autonomous pod isolation action."""

    pod_name: str
    namespace: str
    action_type: str = "ZERO_TRUST_ISOLATION_EBPF_DENY"
    timestamp: str
    reason: str
    policy_attached: str = "quarantine-deny-all"
    success: bool = True


class ClusterAuditResult(BaseModel):
    """Overall health and compliance evaluation result for the EKS Cluster."""

    cluster_name: str = "prod-eks-zero-trust-mesh"
    total_evaluated_pods: int
    compliant_pods: int
    gatekeeper_violations: List[GatekeeperViolation] = Field(default_factory=list)
    network_violations: List[CiliumNetworkViolation] = Field(default_factory=list)
    quarantined_pods: int = 0
    compliance_score: float = 100.0

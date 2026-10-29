"""Pytest fixtures for EKS Zero-Trust Security Mesh tests."""

import pytest

from src.core.config import PodContext, PodStatus


@pytest.fixture
def clean_pod():
    """Returns a fully compliant production pod."""
    return PodContext(
        name="secure-api-pod-101",
        namespace="production",
        labels={"app": "secure-api", "tier": "backend"},
        privileged=False,
        readonly_root_fs=True,
        run_as_non_root=True,
        hostpath_mounts=[],
        has_cilium_policy=True,
        status=PodStatus.HEALTHY,
    )


@pytest.fixture
def non_compliant_pod():
    """Returns a pod violating multiple Gatekeeper constraints."""
    return PodContext(
        name="rogue-debug-pod-999",
        namespace="production",
        labels={"app": "debug-pod"},
        privileged=True,
        readonly_root_fs=False,
        run_as_non_root=False,
        hostpath_mounts=["/var/run/docker.sock", "/etc"],
        has_cilium_policy=False,
        status=PodStatus.VIOLATION_DETECTED,
    )

"""Tests for Pod Isolation & Quarantine Controller."""

from src.core.config import PodStatus
from src.runtime.pod_isolation_controller import PodIsolationController


def test_quarantine_pod_labels_and_updates_status(clean_pod):
    controller = PodIsolationController(dry_run=True)
    action = controller.quarantine_pod(clean_pod, reason="Falco Runtime Breach")

    assert clean_pod.status == PodStatus.QUARANTINED
    assert clean_pod.labels.get("security.mesh/quarantine") == "isolated"
    assert "security.mesh/isolation-timestamp" in clean_pod.labels
    assert action.success is True
    assert action.policy_attached == "quarantine-deny-all"


def test_release_pod_restores_healthy_state(clean_pod):
    controller = PodIsolationController(dry_run=True)
    controller.quarantine_pod(clean_pod, reason="Investigation")
    assert clean_pod.status == PodStatus.QUARANTINED

    released = controller.release_pod(clean_pod)
    assert released is True
    assert clean_pod.status == PodStatus.HEALTHY
    assert "security.mesh/quarantine" not in clean_pod.labels

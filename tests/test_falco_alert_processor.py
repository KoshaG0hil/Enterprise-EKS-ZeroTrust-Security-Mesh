"""Tests for Falco Runtime Alert Processor."""

from src.core.config import Severity
from src.runtime.falco_alert_processor import FalcoAlertProcessor


def test_parse_valid_falco_payload():
    payload = {
        "rule": "Terminal Shell Spawned in Container",
        "priority": "CRITICAL",
        "output_fields": {
            "k8s.pod.name": "web-pod-123",
            "k8s.ns.name": "production",
            "container.id": "containerd://12345",
        },
        "output": "Shell executed inside container",
        "time": "2026-10-29T10:15:00Z",
    }
    alert = FalcoAlertProcessor.parse_alert_payload(payload)
    assert alert is not None
    assert alert.rule_name == "Terminal Shell Spawned in Container"
    assert alert.priority == Severity.CRITICAL
    assert alert.pod_name == "web-pod-123"
    assert alert.namespace == "production"
    assert FalcoAlertProcessor.requires_immediate_quarantine(alert) is True


def test_parse_non_critical_alert():
    payload = {
        "rule": "Noticeable System Call",
        "priority": "INFO",
        "output_fields": {"k8s.pod.name": "log-collector-456", "k8s.ns.name": "kube-system"},
        "output": "Benign system call recorded",
    }
    alert = FalcoAlertProcessor.parse_alert_payload(payload)
    assert alert is not None
    assert alert.priority == Severity.INFO
    assert FalcoAlertProcessor.requires_immediate_quarantine(alert) is False

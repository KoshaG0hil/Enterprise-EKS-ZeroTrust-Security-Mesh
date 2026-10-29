"""Falco Runtime Security Alert Processor."""

from typing import Any, Dict, Optional

from ..core.config import FalcoAlert, Severity


class FalcoAlertProcessor:
    """Ingests and parses runtime threat events from Falco eBPF probe."""

    @staticmethod
    def parse_alert_payload(payload: Dict[str, Any]) -> Optional[FalcoAlert]:
        """Normalizes raw Falco webhook/EventBridge JSON payload into FalcoAlert model."""
        try:
            rule = payload.get("rule", "Unknown Threat Rule")
            priority_str = payload.get("priority", "HIGH").upper()
            try:
                priority = Severity(priority_str)
            except ValueError:
                priority = Severity.HIGH

            output_fields = payload.get("output_fields", {})
            pod_name = output_fields.get("k8s.pod.name", payload.get("pod_name", "unknown-pod"))
            namespace = output_fields.get("k8s.ns.name", payload.get("namespace", "default"))
            container_id = output_fields.get("container.id", payload.get("container_id", "c-unknown"))
            message = payload.get("output", "Security alert triggered in container runtime")
            timestamp = payload.get("time", "2026-10-29T10:00:00Z")
            tags = payload.get("tags", [])

            return FalcoAlert(
                rule_name=rule,
                priority=priority,
                pod_name=pod_name,
                namespace=namespace,
                container_id=container_id,
                message=message,
                timestamp=timestamp,
                tags=tags,
            )
        except Exception:
            return None

    @staticmethod
    def requires_immediate_quarantine(alert: FalcoAlert) -> bool:
        """Determines if the detected runtime threat warrants immediate pod isolation."""
        # Critical priority alerts or shell execution / cryptomining require quarantine
        if alert.priority == Severity.CRITICAL:
            return True
        if any(t in alert.rule_name.lower() for t in ["shell", "crypto", "privilege", "breakout"]):
            return True
        return False

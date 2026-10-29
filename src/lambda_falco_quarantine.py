"""AWS Lambda Handler: EventBridge Falco Runtime Alert to Pod Quarantine Mesh."""

import json
import logging
from typing import Any, Dict

from src.core.config import PodContext, PodStatus
from src.runtime.falco_alert_processor import FalcoAlertProcessor
from src.runtime.pod_isolation_controller import PodIsolationController

logger = logging.getLogger()
logger.setLevel(logging.INFO)


def lambda_handler(event: Dict[str, Any], context: Any) -> Dict[str, Any]:
    """Processes incoming runtime threat alerts and triggers automated eBPF pod isolation."""
    logger.info("Received runtime threat event: %s", json.dumps(event))

    detail = event.get("detail", event)
    alert = FalcoAlertProcessor.parse_alert_payload(detail)

    if not alert:
        logger.warning("Event payload could not be parsed as a valid Falco runtime alert.")
        return {"statusCode": 400, "body": json.dumps({"message": "Invalid Falco payload"})}

    logger.info("Evaluating alert: %s on pod %s/%s", alert.rule_name, alert.namespace, alert.pod_name)

    quarantined = False
    action_record = None

    if FalcoAlertProcessor.requires_immediate_quarantine(alert):
        logger.warning("CRITICAL threat detected! Initiating immediate Zero-Trust pod isolation...")
        controller = PodIsolationController(dry_run=event.get("dry_run", False))

        target_pod = PodContext(
            name=alert.pod_name,
            namespace=alert.namespace,
            status=PodStatus.HEALTHY,
        )

        action_record = controller.quarantine_pod(
            target_pod,
            reason=f"Falco Alert: {alert.rule_name} - {alert.message}",
        )
        quarantined = True
        logger.info("Pod %s successfully isolated. Network policy: quarantine-deny-all", alert.pod_name)

    return {
        "statusCode": 200,
        "body": json.dumps(
            {
                "alert_rule": alert.rule_name,
                "priority": alert.priority.value,
                "pod_name": alert.pod_name,
                "namespace": alert.namespace,
                "quarantined": quarantined,
                "action": action_record.model_dump() if action_record else None,
            }
        ),
    }

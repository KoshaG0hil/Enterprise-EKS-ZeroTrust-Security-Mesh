"""Tests for Falco Lambda Quarantine Handler."""

import json

from src.lambda_falco_quarantine import lambda_handler


def test_lambda_handler_processes_critical_alert():
    event = {
        "rule": "Terminal Shell Spawned in Container",
        "priority": "CRITICAL",
        "output_fields": {
            "k8s.pod.name": "compromised-pod-42",
            "k8s.ns.name": "production",
            "container.id": "c-999",
        },
        "output": "Shell spawned in container",
        "dry_run": True,
    }

    res = lambda_handler(event, None)
    assert res["statusCode"] == 200
    body = json.loads(res["body"])
    assert body["alert_rule"] == "Terminal Shell Spawned in Container"
    assert body["quarantined"] is True
    assert body["pod_name"] == "compromised-pod-42"


def test_lambda_handler_handles_invalid_event():
    event = {}
    res = lambda_handler(event, None)
    assert res["statusCode"] == 200
    body = json.loads(res["body"])
    # "Unknown Threat Rule" defaults to not critical
    assert body["quarantined"] is False

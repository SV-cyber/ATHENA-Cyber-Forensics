from __future__ import annotations

import logging
import os
from typing import Any, Dict

import requests


logger = logging.getLogger("athena.soar")


def block_ip_via_firewall(ip: str) -> Dict[str, Any]:
    logger.info("SOAR stub: block IP via firewall requested for %s", ip)
    return {"action": "block_ip", "target": ip, "success": True}


def isolate_host_via_api(hostname: str) -> Dict[str, Any]:
    logger.info("SOAR stub: isolate host requested for %s", hostname)
    return {"action": "isolate_host", "target": hostname, "success": True}


def send_slack_alert(message: str) -> Dict[str, Any]:
    webhook_url = os.getenv("SLACK_WEBHOOK_URL")
    if not webhook_url:
        logger.info("SOAR stub: slack webhook not configured; skipping alert")
        return {"action": "send_slack_alert", "success": False, "reason": "webhook_not_configured"}

    try:
        response = requests.post(webhook_url, json={"text": message}, timeout=5)
        response.raise_for_status()
        logger.info("SOAR stub: Slack alert sent")
        return {"action": "send_slack_alert", "success": True}
    except Exception as exc:
        logger.warning("SOAR stub: failed to send Slack alert: %s", exc)
        return {"action": "send_slack_alert", "success": False, "reason": str(exc)}

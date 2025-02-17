"""
Response Agent for Network-Security-AI-Agent

This agent executes automated response playbooks based on detection results.
Capabilities include:
- Blocking IPs using iptables
- Writing to blocklists
- Sending alerts to Slack/webhooks
- Logging incidents

Uses CrewAI for orchestration.
"""

import json
import logging
import subprocess
import os
from typing import Any, Dict, List, Optional
from datetime import datetime
from dataclasses import dataclass
import requests

try:
    from crewai import Agent
except ImportError:
    logging.warning("CrewAI not installed (optional for Response Agent)")

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)


@dataclass
class ResponseAction:
    """Record of a response action executed."""
    timestamp: str
    action_type: str  # "BLOCK_IP", "ALERT", "LOG", "ISOLATE"
    target: str  # IP, hostname, etc.
    status: str  # "SUCCESS", "FAILED", "PENDING"
    details: Dict[str, Any]


class IPBlockManager:
    """
    Manages IP blocking using iptables (Linux) or Windows Firewall.
    """

    def __init__(self, dry_run: bool = False):
        """
        Initialize IP block manager.

        Args:
            dry_run: If True, log actions without executing them
        """
        self.dry_run = dry_run
        self.blocked_ips = set()
        self.blocklist_file = "/tmp/threat_intelligence_blocklist.txt"

        if not self.dry_run:
            os.makedirs(os.path.dirname(self.blocklist_file), exist_ok=True)

        logger.info(f"IPBlockManager initialized (dry_run={self.dry_run})")

    def block_ip(self, ip_address: str, direction: str = "both") -> ResponseAction:
        """
        Block an IP address using iptables.

        Args:
            ip_address: IP to block (e.g., "192.168.1.100")
            direction: "inbound", "outbound", or "both"

        Returns:
            ResponseAction with status
        """
        action = ResponseAction(
            timestamp=datetime.utcnow().isoformat(),
            action_type="BLOCK_IP",
            target=ip_address,
            status="PENDING",
            details={"direction": direction, "dry_run": self.dry_run}
        )

        try:
            if self.dry_run:
                logger.info(f"[DRY RUN] Would block {ip_address} (direction: {direction})")
                action.status = "SUCCESS"
                action.details["message"] = "Dry-run successful"
                return action

            # Add to blocklist file (non-privileged operation)
            self._add_to_blocklist(ip_address)

            # Attempt iptables block if running as root
            if os.geteuid() == 0:
                if direction in ("inbound", "both"):
                    self._iptables_block(ip_address, "INPUT")
                if direction in ("outbound", "both"):
                    self._iptables_block(ip_address, "OUTPUT")

                logger.info(f"Successfully blocked IP: {ip_address}")
                action.status = "SUCCESS"
                action.details["message"] = "IP blocked with iptables"
            else:
                logger.warning(
                    f"Not running as root. IP added to blocklist but iptables block skipped."
                )
                action.status = "SUCCESS"
                action.details["message"] = "IP added to blocklist (non-root)"

            self.blocked_ips.add(ip_address)

        except Exception as e:
            logger.error(f"IP blocking failed for {ip_address}: {e}")
            action.status = "FAILED"
            action.details["error"] = str(e)

        return action

    def unblock_ip(self, ip_address: str) -> ResponseAction:
        """
        Unblock a previously blocked IP.

        Args:
            ip_address: IP to unblock

        Returns:
            ResponseAction with status
        """
        action = ResponseAction(
            timestamp=datetime.utcnow().isoformat(),
            action_type="UNBLOCK_IP",
            target=ip_address,
            status="PENDING",
            details={"dry_run": self.dry_run}
        )

        try:
            if os.geteuid() == 0:
                # Remove from iptables
                subprocess.run(
                    [
                        "iptables", "-D", "INPUT", "-s", ip_address, "-j", "DROP"
                    ],
                    check=False
                )
                subprocess.run(
                    [
                        "iptables", "-D", "OUTPUT", "-d", ip_address, "-j", "DROP"
                    ],
                    check=False
                )
                logger.info(f"Successfully unblocked IP: {ip_address}")

            self.blocked_ips.discard(ip_address)
            self._remove_from_blocklist(ip_address)
            action.status = "SUCCESS"

        except Exception as e:
            logger.error(f"IP unblocking failed for {ip_address}: {e}")
            action.status = "FAILED"
            action.details["error"] = str(e)

        return action

    def _iptables_block(self, ip_address: str, chain: str) -> None:
        """
        Execute iptables command to block IP.

        Args:
            ip_address: IP to block
            chain: iptables chain (INPUT, OUTPUT, FORWARD)
        """
        if chain == "INPUT":
            cmd = ["iptables", "-A", "INPUT", "-s", ip_address, "-j", "DROP"]
        elif chain == "OUTPUT":
            cmd = ["iptables", "-A", "OUTPUT", "-d", ip_address, "-j", "DROP"]
        else:
            cmd = ["iptables", "-A", "FORWARD", "-s", ip_address, "-j", "DROP"]

        subprocess.run(cmd, check=True, capture_output=True)

    def _add_to_blocklist(self, ip_address: str) -> None:
        """
        Add IP to the blocklist file.

        Args:
            ip_address: IP to add
        """
        with open(self.blocklist_file, "a") as f:
            f.write(f"{ip_address}\n")
        logger.debug(f"Added {ip_address} to blocklist file")

    def _remove_from_blocklist(self, ip_address: str) -> None:
        """
        Remove IP from the blocklist file.

        Args:
            ip_address: IP to remove
        """
        try:
            with open(self.blocklist_file, "r") as f:
                lines = f.readlines()

            with open(self.blocklist_file, "w") as f:
                for line in lines:
                    if line.strip() != ip_address:
                        f.write(line)

            logger.debug(f"Removed {ip_address} from blocklist file")
        except FileNotFoundError:
            pass

    def get_blocklist(self) -> List[str]:
        """
        Get current blocklist.

        Returns:
            List of blocked IPs
        """
        try:
            with open(self.blocklist_file, "r") as f:
                return [line.strip() for line in f if line.strip()]
        except FileNotFoundError:
            return []


class AlertManager:
    """
    Manages alert delivery via Slack, webhooks, or email.
    """

    def __init__(
        self,
        slack_webhook: Optional[str] = None,
        webhook_urls: Optional[List[str]] = None,
        dry_run: bool = False
    ):
        """
        Initialize alert manager.

        Args:
            slack_webhook: Slack webhook URL
            webhook_urls: List of custom webhook URLs
            dry_run: If True, log actions without sending
        """
        self.slack_webhook = slack_webhook or os.getenv("SLACK_WEBHOOK_URL")
        self.webhook_urls = webhook_urls or []
        self.dry_run = dry_run
        self.alerts_sent = 0

        logger.info(
            f"AlertManager initialized "
            f"(Slack: {bool(self.slack_webhook)}, "
            f"Webhooks: {len(self.webhook_urls)}, "
            f"dry_run: {self.dry_run})"
        )

    def send_alert(
        self,
        title: str,
        threat_level: str,
        details: Dict[str, Any]
    ) -> ResponseAction:
        """
        Send an alert about detected threat.

        Args:
            title: Alert title
            threat_level: "LOW", "MEDIUM", "HIGH", "CRITICAL"
            details: Additional alert details

        Returns:
            ResponseAction with status
        """
        action = ResponseAction(
            timestamp=datetime.utcnow().isoformat(),
            action_type="ALERT",
            target=details.get("src_ip", "unknown"),
            status="PENDING",
            details={"title": title, "level": threat_level}
        )

        if self.dry_run:
            logger.info(
                f"[DRY RUN] Alert: {title} (Level: {threat_level})"
            )
            action.status = "SUCCESS"
            return action

        # Send to Slack
        if self.slack_webhook:
            slack_status = self._send_slack_alert(
                title, threat_level, details
            )
            action.details["slack"] = slack_status

        # Send to custom webhooks
        for webhook_url in self.webhook_urls:
            webhook_status = self._send_webhook_alert(
                webhook_url, title, threat_level, details
            )
            action.details[f"webhook_{self.webhook_urls.index(webhook_url)}"] = webhook_status

        action.status = "SUCCESS"
        self.alerts_sent += 1
        return action

    def _send_slack_alert(
        self,
        title: str,
        threat_level: str,
        details: Dict[str, Any]
    ) -> Dict[str, Any]:
        """
        Send alert to Slack.

        Args:
            title: Alert title
            threat_level: Threat level
            details: Alert details

        Returns:
            Status dictionary
        """
        try:
            # Color based on threat level
            color_map = {
                "LOW": "#36a64f",
                "MEDIUM": "#ff9900",
                "HIGH": "#ff6600",
                "CRITICAL": "#cc0000"
            }

            payload = {
                "attachments": [
                    {
                        "color": color_map.get(threat_level, "#808080"),
                        "title": title,
                        "fields": [
                            {
                                "title": "Threat Level",
                                "value": threat_level,
                                "short": True
                            },
                            {
                                "title": "Source IP",
                                "value": details.get("src_ip", "N/A"),
                                "short": True
                            },
                            {
                                "title": "Destination IP",
                                "value": details.get("dst_ip", "N/A"),
                                "short": True
                            },
                            {
                                "title": "Attack Type",
                                "value": details.get("attack_type", "N/A"),
                                "short": True
                            },
                            {
                                "title": "Reasoning",
                                "value": details.get("reasoning", "No reasoning provided")
                            }
                        ],
                        "ts": int(datetime.utcnow().timestamp())
                    }
                ]
            }

            response = requests.post(
                self.slack_webhook,
                json=payload,
                timeout=5
            )

            if response.status_code == 200:
                logger.info("Slack alert sent successfully")
                return {"status": "sent", "code": 200}
            else:
                logger.warning(f"Slack alert failed with code {response.status_code}")
                return {"status": "failed", "code": response.status_code}

        except requests.RequestException as e:
            logger.error(f"Failed to send Slack alert: {e}")
            return {"status": "error", "error": str(e)}

    def _send_webhook_alert(
        self,
        webhook_url: str,
        title: str,
        threat_level: str,
        details: Dict[str, Any]
    ) -> Dict[str, Any]:
        """
        Send alert to custom webhook.

        Args:
            webhook_url: Webhook URL
            title: Alert title
            threat_level: Threat level
            details: Alert details

        Returns:
            Status dictionary
        """
        try:
            payload = {
                "timestamp": datetime.utcnow().isoformat(),
                "title": title,
                "threat_level": threat_level,
                "details": details
            }

            response = requests.post(
                webhook_url,
                json=payload,
                timeout=5
            )

            if response.status_code in (200, 201):
                logger.info(f"Webhook alert sent to {webhook_url}")
                return {"status": "sent", "code": response.status_code}
            else:
                logger.warning(f"Webhook failed with code {response.status_code}")
                return {"status": "failed", "code": response.status_code}

        except requests.RequestException as e:
            logger.error(f"Failed to send webhook alert: {e}")
            return {"status": "error", "error": str(e)}


class ResponseAgent:
    """
    Main Response Agent coordinating automated security responses.
    """

    def __init__(
        self,
        dry_run: bool = False,
        slack_webhook: Optional[str] = None,
        webhook_urls: Optional[List[str]] = None
    ):
        """
        Initialize Response Agent.

        Args:
            dry_run: If True, log actions without executing
            slack_webhook: Slack webhook URL
            webhook_urls: List of custom webhook URLs
        """
        self.ip_blocker = IPBlockManager(dry_run=dry_run)
        self.alert_manager = AlertManager(
            slack_webhook=slack_webhook,
            webhook_urls=webhook_urls,
            dry_run=dry_run
        )
        self.action_history: List[ResponseAction] = []
        self.dry_run = dry_run

        logger.info(f"Response Agent initialized (dry_run={self.dry_run})")

    def respond_to_detection(
        self,
        detection_result: Dict[str, Any]
    ) -> List[ResponseAction]:
        """
        Execute response playbook for a detection.

        Args:
            detection_result: Result from detection agent

        Returns:
            List of ResponseActions executed
        """
        actions = []
        threat_level = detection_result.get("threat_level", "MEDIUM")
        src_ip = detection_result.get("src_ip", "unknown")

        logger.info(f"Executing response for {src_ip} (Level: {threat_level})")

        # CRITICAL: Block IP immediately
        if threat_level == "CRITICAL":
            block_action = self.ip_blocker.block_ip(src_ip, "both")
            actions.append(block_action)

        # HIGH: Send alert
        if threat_level in ("HIGH", "CRITICAL"):
            alert_action = self.alert_manager.send_alert(
                title=f"Security Alert: {detection_result.get('attack_type', 'Unknown')}",
                threat_level=threat_level,
                details=detection_result
            )
            actions.append(alert_action)

        # All levels: Log
        log_action = ResponseAction(
            timestamp=datetime.utcnow().isoformat(),
            action_type="LOG",
            target=src_ip,
            status="SUCCESS",
            details=detection_result
        )
        actions.append(log_action)

        self.action_history.extend(actions)
        return actions

    def get_action_history(self) -> List[Dict[str, Any]]:
        """Get all response actions as JSON-serializable dicts."""
        return [
            {
                "timestamp": a.timestamp,
                "action_type": a.action_type,
                "target": a.target,
                "status": a.status,
                "details": a.details
            }
            for a in self.action_history
        ]

    def get_blocklist(self) -> List[str]:
        """Get current blocklist."""
        return self.ip_blocker.get_blocklist()


# ==================== Example Usage ====================
if __name__ == "__main__":
    # Initialize response agent (dry-run mode)
    response_agent = ResponseAgent(dry_run=True)

    # Simulate detection result
    detection_result = {
        "timestamp": datetime.utcnow().isoformat(),
        "src_ip": "192.168.1.100",
        "dst_ip": "8.8.8.8",
        "threat_level": "CRITICAL",
        "attack_type": "Reverse Shell",
        "confidence": 0.95,
        "mitre_techniques": ["T1571", "T1090"],
        "reasoning": "High-volume bidirectional traffic on non-standard port suggests reverse shell activity.",
    }

    # Execute response
    actions = response_agent.respond_to_detection(detection_result)

    print("\n" + "="*60)
    print("RESPONSE ACTIONS")
    print("="*60)
    for action in actions:
        print(f"\n{action.action_type}:")
        print(f"  Target: {action.target}")
        print(f"  Status: {action.status}")
        print(f"  Details: {action.details}")
    print("="*60)

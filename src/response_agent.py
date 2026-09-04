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

import ipaddress
import json
import logging
import subprocess
import os
import tempfile
import threading
from typing import Any, Dict, Iterable, List, Optional, Union
from datetime import datetime
from dataclasses import dataclass
from urllib.parse import urlsplit
import requests

logger = logging.getLogger(__name__)


@dataclass
class ResponseAction:
    """Record of a response action executed."""
    timestamp: str
    action_type: str  # "BLOCK_IP", "ALERT", "LOG", "ISOLATE"
    target: str  # IP, hostname, etc.
    status: str  # "SUCCESS", "PARTIAL", "FAILED", "SKIPPED", "PENDING"
    details: Dict[str, Any]


class IPBlockManager:
    """
    Manages IP blocking using iptables (Linux) or Windows Firewall.
    """

    VALID_DIRECTIONS = ("inbound", "outbound", "both")
    # Upper bound when deleting duplicate rules, so a failing -D can't loop forever
    MAX_DUPLICATE_RULES = 100

    def __init__(
        self,
        dry_run: bool = False,
        allowlist: Optional[Iterable[str]] = None,
        blocklist_file: Optional[str] = None
    ):
        """
        Initialize IP block manager.

        Args:
            dry_run: If True, log actions without executing them
            allowlist: IPs or CIDR ranges that must never be blocked
                (e.g. gateway, DNS servers, management hosts). Entries from
                the BLOCK_ALLOWLIST env var (comma-separated) are added too.
            blocklist_file: Path to the blocklist file. Falls back to the
                BLOCKLIST_FILE env var, then default_blocklist_path().
        """
        self.dry_run = dry_run
        self.allowlist = self._parse_allowlist(allowlist)
        self.blocked_ips = set()
        # Serializes read-modify-write of the blocklist file across threads
        self._blocklist_lock = threading.Lock()
        self.blocklist_file = (
            blocklist_file
            or os.getenv("BLOCKLIST_FILE")
            or self.default_blocklist_path()
        )

        if not self.dry_run:
            # Owner-only directory: other local users must not be able to
            # read the blocklist or plant files/symlinks next to it
            os.makedirs(os.path.dirname(self.blocklist_file), mode=0o700, exist_ok=True)

        logger.info(
            f"IPBlockManager initialized (dry_run={self.dry_run}, "
            f"blocklist={self.blocklist_file})"
        )

    @staticmethod
    def default_blocklist_path() -> str:
        """
        Return the default blocklist location.

        Root uses /var/lib (system state); other users get a per-user state
        directory. Both avoid world-writable /tmp.
        """
        if os.geteuid() == 0:
            base = "/var/lib"
        else:
            base = os.getenv(
                "XDG_STATE_HOME", os.path.join(os.path.expanduser("~"), ".local", "state")
            )
        return os.path.join(base, "network-security-ai-agent", "blocklist.txt")

    @staticmethod
    def _validate_ip(ip_address: str) -> str:
        """
        Validate that the target is a single host IP address.

        Rejects CIDR ranges (e.g. "0.0.0.0/0"), hostnames and any other
        string before it can reach iptables or the blocklist file.

        Args:
            ip_address: Candidate IP address

        Returns:
            Canonical string form of the IP

        Raises:
            ValueError: If the value is not a valid IPv4/IPv6 address
        """
        try:
            return str(ipaddress.ip_address(str(ip_address).strip()))
        except ValueError:
            raise ValueError(f"Invalid IP address: {ip_address!r}") from None

    @staticmethod
    def _parse_allowlist(
        allowlist: Optional[Iterable[str]]
    ) -> List[Union[ipaddress.IPv4Network, ipaddress.IPv6Network]]:
        """
        Build the list of protected networks from arguments and environment.

        Args:
            allowlist: IPs or CIDR ranges passed by the caller

        Returns:
            List of ip_network objects

        Raises:
            ValueError: If an entry is not a valid IP or CIDR range
        """
        entries = list(allowlist or [])
        entries += [e for e in os.getenv("BLOCK_ALLOWLIST", "").split(",") if e.strip()]

        networks = []
        for entry in entries:
            try:
                networks.append(ipaddress.ip_network(entry.strip(), strict=False))
            except ValueError:
                raise ValueError(f"Invalid allowlist entry: {entry!r}") from None
        return networks

    def is_protected(self, ip_address: str) -> Optional[str]:
        """
        Check whether an IP must never be blocked.

        Args:
            ip_address: Validated IP address

        Returns:
            Reason string if the IP is protected, otherwise None
        """
        ip = ipaddress.ip_address(ip_address)
        if ip.is_loopback:
            return "loopback address"
        if ip.is_unspecified:
            return "unspecified address"
        if ip.is_multicast:
            return "multicast address"
        if ip.is_link_local:
            return "link-local address"
        if ip == ipaddress.ip_address("255.255.255.255"):
            return "broadcast address"
        for network in self.allowlist:
            if ip in network:
                return f"allowlisted ({network})"
        return None

    @staticmethod
    def _firewall_binary(ip_address: str) -> str:
        """Return iptables for IPv4 or ip6tables for IPv6 addresses."""
        return "ip6tables" if ipaddress.ip_address(ip_address).version == 6 else "iptables"

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
            if direction not in self.VALID_DIRECTIONS:
                raise ValueError(
                    f"Invalid direction {direction!r}; "
                    f"expected one of {self.VALID_DIRECTIONS}"
                )
            ip_address = self._validate_ip(ip_address)
            action.target = ip_address

            protected_reason = self.is_protected(ip_address)
            if protected_reason:
                logger.warning(f"Refusing to block {ip_address}: {protected_reason}")
                action.status = "SKIPPED"
                action.details["message"] = f"Protected IP: {protected_reason}"
                return action

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
            ip_address = self._validate_ip(ip_address)
            action.target = ip_address

            if self.dry_run:
                logger.info(f"[DRY RUN] Would unblock {ip_address}")
                action.status = "SUCCESS"
                action.details["message"] = "Dry-run successful"
                return action

            if os.geteuid() == 0:
                # Remove from iptables, including duplicates left by older
                # versions that appended a rule on every detection
                binary = self._firewall_binary(ip_address)
                for chain in ("INPUT", "OUTPUT"):
                    rule = self._drop_rule(ip_address, chain)
                    for _ in range(self.MAX_DUPLICATE_RULES):
                        if not self._rule_exists(binary, rule):
                            break
                        subprocess.run(
                            [binary, "-D", *rule], check=True, capture_output=True
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
        binary = self._firewall_binary(ip_address)
        rule = self._drop_rule(ip_address, chain)

        if self._rule_exists(binary, rule):
            logger.debug(f"{binary} {chain} DROP rule for {ip_address} already exists")
            return

        subprocess.run([binary, "-A", *rule], check=True, capture_output=True)

    @staticmethod
    def _drop_rule(ip_address: str, chain: str) -> List[str]:
        """
        Build the iptables rule spec (without the -A/-C/-D verb).

        Args:
            ip_address: IP to match
            chain: iptables chain (INPUT, OUTPUT, FORWARD)

        Returns:
            Rule arguments, e.g. ["INPUT", "-s", ip, "-j", "DROP"]
        """
        match = "-d" if chain == "OUTPUT" else "-s"
        return [chain, match, ip_address, "-j", "DROP"]

    @staticmethod
    def _rule_exists(binary: str, rule: List[str]) -> bool:
        """Return True if the rule is already present (iptables -C)."""
        result = subprocess.run([binary, "-C", *rule], capture_output=True)
        return result.returncode == 0

    def _add_to_blocklist(self, ip_address: str) -> None:
        """
        Add IP to the blocklist file.

        Args:
            ip_address: IP to add
        """
        with self._blocklist_lock:
            current = self.get_blocklist()
            if ip_address in current:
                logger.debug(f"{ip_address} already in blocklist file")
                return

            self._write_blocklist(current + [ip_address])
        logger.debug(f"Added {ip_address} to blocklist file")

    def _remove_from_blocklist(self, ip_address: str) -> None:
        """
        Remove IP from the blocklist file.

        Args:
            ip_address: IP to remove
        """
        with self._blocklist_lock:
            current = self.get_blocklist()
            if ip_address not in current:
                return

            self._write_blocklist([ip for ip in current if ip != ip_address])
        logger.debug(f"Removed {ip_address} from blocklist file")

    def _write_blocklist(self, ips: List[str]) -> None:
        """
        Atomically replace the blocklist file.

        Writes to a temp file in the same directory, fsyncs it, then
        os.replace()s it over the old file. Readers see either the old or
        the new list, never a truncated one, even if the process crashes
        mid-write. os.replace() also swaps out a planted symlink instead of
        writing through it.

        Args:
            ips: Full list of IPs to store
        """
        directory = os.path.dirname(self.blocklist_file) or "."
        fd, tmp_path = tempfile.mkstemp(dir=directory, prefix=".blocklist-", suffix=".tmp")
        try:
            with os.fdopen(fd, "w") as f:  # mkstemp creates the file as 0600
                f.writelines(f"{ip}\n" for ip in ips)
                f.flush()
                os.fsync(f.fileno())
            os.replace(tmp_path, self.blocklist_file)
        except BaseException:
            try:
                os.unlink(tmp_path)
            except FileNotFoundError:
                pass
            raise

    def get_blocklist(self) -> List[str]:
        """
        Get current blocklist.

        Returns:
            List of blocked IPs (unique, in the order they were added)
        """
        try:
            with open(self.blocklist_file, "r") as f:
                # dict.fromkeys de-duplicates while keeping order, which also
                # hides duplicates written by older versions
                return list(dict.fromkeys(line.strip() for line in f if line.strip()))
        except FileNotFoundError:
            return []


class AlertManager:
    """
    Manages alert delivery via Slack, webhooks, or email.
    """

    # Only these detection fields leave the host. Everything else (raw flow
    # features, internal state, fields added by future callers) stays local.
    SHAREABLE_FIELDS = (
        "timestamp", "src_ip", "dst_ip", "threat_level", "attack_type",
        "confidence", "mitre_techniques", "reasoning", "ml_score",
    )
    MAX_REASONING_CHARS = 1000

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

        for url in filter(None, [self.slack_webhook, *self.webhook_urls]):
            self._validate_webhook_url(url)

        self.dry_run = dry_run
        self.alerts_sent = 0

        logger.info(
            f"AlertManager initialized "
            f"(Slack: {bool(self.slack_webhook)}, "
            f"Webhooks: {len(self.webhook_urls)}, "
            f"dry_run: {self.dry_run})"
        )

    @staticmethod
    def _validate_webhook_url(url: str) -> None:
        """
        Require HTTPS so alert contents (internal IPs, attack details) and
        the webhook secret are never sent in cleartext. Plain HTTP is only
        allowed to loopback hosts, for local testing.

        Args:
            url: Webhook URL

        Raises:
            ValueError: If the URL is not HTTPS (or HTTP to localhost)
        """
        parts = urlsplit(url)
        host = parts.hostname or ""
        if parts.scheme == "https" and host:
            return
        if parts.scheme == "http" and host in ("localhost", "127.0.0.1", "::1"):
            return
        raise ValueError(
            f"Webhook URL must use https:// (got {AlertManager._redact_url(url)})"
        )

    @staticmethod
    def _redact_url(url: str) -> str:
        """
        Strip the path and query from a URL for logging. Webhook URLs carry
        their secret token in the path (e.g. hooks.slack.com/services/...).
        """
        parts = urlsplit(url)
        return f"{parts.scheme}://{parts.netloc}/<redacted>"

    @staticmethod
    def _redact_error(error: Exception, url: str) -> str:
        """Return the error message with the URL's secret path removed."""
        message = str(error)
        parts = urlsplit(url)
        for secret in (parts.path, parts.query):
            if secret and secret != "/":
                message = message.replace(secret, "/<redacted>")
        return message

    @classmethod
    def _shareable_details(cls, details: Dict[str, Any]) -> Dict[str, Any]:
        """
        Reduce detection details to the fields that are safe to send to
        external services, truncating long free text.

        Args:
            details: Full detection details

        Returns:
            Filtered copy of the details
        """
        shared = {k: details[k] for k in cls.SHAREABLE_FIELDS if k in details}
        reasoning = shared.get("reasoning")
        if isinstance(reasoning, str) and len(reasoning) > cls.MAX_REASONING_CHARS:
            shared["reasoning"] = reasoning[:cls.MAX_REASONING_CHARS] + "..."
        return shared

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
            target=details.get("src_ip") or "unknown",
            status="PENDING",
            details={"title": title, "level": threat_level}
        )

        if self.dry_run:
            logger.info(
                f"[DRY RUN] Alert: {title} (Level: {threat_level})"
            )
            action.status = "SUCCESS"
            return action

        deliveries = []
        details = self._shareable_details(details)

        # Send to Slack
        if self.slack_webhook:
            slack_status = self._send_slack_alert(
                title, threat_level, details
            )
            action.details["slack"] = slack_status
            deliveries.append(slack_status)

        # Send to custom webhooks
        for i, webhook_url in enumerate(self.webhook_urls):
            webhook_status = self._send_webhook_alert(
                webhook_url, title, threat_level, details
            )
            action.details[f"webhook_{i}"] = webhook_status
            deliveries.append(webhook_status)

        delivered = sum(1 for d in deliveries if d.get("status") == "sent")

        if not deliveries:
            logger.warning(f"No alert channels configured; alert not sent: {title}")
            action.status = "SKIPPED"
        elif delivered == len(deliveries):
            action.status = "SUCCESS"
        elif delivered > 0:
            action.status = "PARTIAL"
        else:
            logger.error(f"All {len(deliveries)} alert deliveries failed: {title}")
            action.status = "FAILED"

        if delivered:
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
            error = self._redact_error(e, self.slack_webhook)
            logger.error(f"Failed to send Slack alert: {error}")
            return {"status": "error", "error": error}

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
                logger.info(f"Webhook alert sent to {self._redact_url(webhook_url)}")
                return {"status": "sent", "code": response.status_code}
            else:
                logger.warning(f"Webhook failed with code {response.status_code}")
                return {"status": "failed", "code": response.status_code}

        except requests.RequestException as e:
            error = self._redact_error(e, webhook_url)
            logger.error(f"Failed to send webhook alert: {error}")
            return {"status": "error", "error": error}


class ResponseAgent:
    """
    Main Response Agent coordinating automated security responses.
    """

    def __init__(
        self,
        dry_run: bool = False,
        slack_webhook: Optional[str] = None,
        webhook_urls: Optional[List[str]] = None,
        allowlist: Optional[Iterable[str]] = None,
        blocklist_file: Optional[str] = None
    ):
        """
        Initialize Response Agent.

        Args:
            dry_run: If True, log actions without executing
            slack_webhook: Slack webhook URL
            webhook_urls: List of custom webhook URLs
            allowlist: IPs or CIDR ranges that must never be blocked
            blocklist_file: Path to the blocklist file
        """
        self.ip_blocker = IPBlockManager(
            dry_run=dry_run,
            allowlist=allowlist,
            blocklist_file=blocklist_file
        )
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
        raw_src_ip = detection_result.get("src_ip")

        try:
            src_ip = IPBlockManager._validate_ip(raw_src_ip)
            has_valid_ip = True
        except ValueError:
            src_ip = "unknown"
            has_valid_ip = False
            logger.warning(
                f"Detection has no valid source IP ({raw_src_ip!r}); "
                "blocking will be skipped"
            )

        logger.info(f"Executing response for {src_ip} (Level: {threat_level})")

        # CRITICAL: Block IP immediately (only if we know who to block)
        if threat_level == "CRITICAL":
            if has_valid_ip:
                block_action = self.ip_blocker.block_ip(src_ip, "both")
            else:
                block_action = ResponseAction(
                    timestamp=datetime.utcnow().isoformat(),
                    action_type="BLOCK_IP",
                    target=src_ip,
                    status="SKIPPED",
                    details={"message": f"No valid source IP: {raw_src_ip!r}"}
                )
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
    logging.basicConfig(
        level=logging.INFO,
        format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
    )
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

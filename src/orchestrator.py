"""
Main Orchestrator for Network-Security-AI-Agent

Coordinates detection and response agents in a unified system.
Provides API for real-time analysis and dashboard integration.
"""

import json
import logging
from typing import Dict, Any, List, Optional
from datetime import datetime, timezone
from pathlib import Path

import numpy as np

from src.detection_agent import DetectionAgent, FlowFeatures
from src.response_agent import ResponseAgent
from src.packet_capture import PacketCapture
from src.threat import ThreatLevel

logger = logging.getLogger(__name__)


def _json_default(obj: Any) -> Any:
    """
    Fallback JSON encoder for values json doesn't handle natively.

    Args:
        obj: Object json.dump couldn't serialize

    Returns:
        A JSON-serializable equivalent

    Raises:
        TypeError: For types with no sensible JSON form
    """
    if isinstance(obj, np.generic):  # np.int64, np.float32, np.bool_, ...
        return obj.item()
    if isinstance(obj, np.ndarray):
        return obj.tolist()
    if isinstance(obj, (set, frozenset)):
        return sorted(obj)
    raise TypeError(f"Object of type {type(obj).__name__} is not JSON serializable")


class SOCAgent:
    """
    Autonomous SOC Analyst Agent that continuously monitors network traffic,
    detects threats, and responds automatically.
    """

    def __init__(
        self,
        dry_run: bool = False,
        slack_webhook: Optional[str] = None,
        webhook_urls: Optional[List[str]] = None,
        model_path: Optional[str] = None,
        allowlist: Optional[List[str]] = None,
        blocklist_file: Optional[str] = None,
        alert_cooldown_seconds: float = 300.0
    ):
        """
        Initialize the SOC Agent.

        Args:
            dry_run: If True, don't execute blocking/alerts
            slack_webhook: Slack webhook URL
            webhook_urls: List of custom webhook URLs
            model_path: Path to a model saved with save_model(); skips retraining
            allowlist: IPs or CIDR ranges that must never be blocked
            blocklist_file: Path to the blocklist file
            alert_cooldown_seconds: Minimum seconds between alerts for the
                same source and attack type (0 disables throttling)
        """
        self.detection_agent = DetectionAgent(model_path=model_path)
        self.response_agent = ResponseAgent(
            dry_run=dry_run,
            slack_webhook=slack_webhook,
            webhook_urls=webhook_urls,
            allowlist=allowlist,
            blocklist_file=blocklist_file,
            alert_cooldown_seconds=alert_cooldown_seconds
        )
        self.packet_capture = PacketCapture()

        self.stats = {
            "packets_analyzed": 0,
            "flows_analyzed": 0,
            "threats_detected": 0,
            "critical_alerts": 0,
            "ips_blocked": 0,
            "start_time": datetime.now(timezone.utc).isoformat()
        }

        logger.info("SOC Agent initialized")

    def train_on_benign_traffic(self, pcap_file: str) -> None:
        """
        Train detection model on benign traffic.

        Args:
            pcap_file: Path to pcap with known-benign traffic
        """
        logger.info(f"Training on benign traffic: {pcap_file}")

        training_data = []
        flow_count = 0

        for features, _, _ in self.packet_capture.read_pcap(pcap_file):
            training_data.append(features.to_array()[0])
            flow_count += 1

        if training_data:
            training_array = np.array(training_data)
            self.detection_agent.train(training_array)
            logger.info(f"Trained on {flow_count} benign flows")
        else:
            logger.warning("No training data extracted")

    def save_model(self, path: str) -> None:
        """
        Save the trained detection model.

        Reload it later with SOCAgent(model_path=path) instead of retraining.

        Args:
            path: Destination file path
        """
        self.detection_agent.save_model(path)

    def analyze_pcap(
        self,
        pcap_file: str,
        auto_block_critical: bool = False
    ) -> Dict[str, Any]:
        """
        Analyze a pcap file for threats.

        Args:
            pcap_file: Path to pcap file
            auto_block_critical: If True, automatically block critical IPs

        Returns:
            Analysis results summary
        """
        logger.info(f"Analyzing pcap: {pcap_file}")

        detections = []
        responses = []
        flow_count = 0

        for features, src_ip, dst_ip in self.packet_capture.read_pcap(pcap_file):
            flow_count += 1
            self.stats["flows_analyzed"] += 1

            # Perform detection
            detection = self.detection_agent.detect(features, src_ip, dst_ip)

            if detection.threat_level > ThreatLevel.LOW:
                detections.append(detection)
                self.stats["threats_detected"] += 1

                if detection.threat_level == ThreatLevel.CRITICAL:
                    self.stats["critical_alerts"] += 1

                    if auto_block_critical:
                        # Execute response (features kept for the local log;
                        # AlertManager strips them before anything is sent)
                        actions = self.response_agent.respond_to_detection(
                            detection.to_dict(include_features=True)
                        )
                        responses.extend(actions)

                        if any(a.action_type == "BLOCK_IP" and a.status == "SUCCESS" for a in actions):
                            self.stats["ips_blocked"] += 1

        logger.info(f"Analysis complete: {flow_count} flows, {len(detections)} threats")

        return {
            "file": pcap_file,
            "flows_analyzed": flow_count,
            "threats_detected": len(detections),
            "detections": [d.to_dict() for d in detections],
            "responses": [a.to_dict() for a in responses],
            "stats": dict(self.stats)
        }

    def get_dashboard_data(self) -> Dict[str, Any]:
        """
        Get current state for dashboard display.

        Returns:
            Dictionary with all dashboard data
        """
        return {
            "stats": dict(self.stats),
            "recent_detections": [
                d.to_dict() for d in list(self.detection_agent.detection_history)[-50:]
            ],
            "recent_responses": self.response_agent.get_action_history()[-50:],
            "blocklist": self.response_agent.get_blocklist()
        }

    def export_results(self, output_file: str) -> None:
        """
        Export analysis results to JSON.

        Args:
            output_file: Path to output JSON file
        """
        data = {
            "export_time": datetime.now(timezone.utc).isoformat(),
            "stats": self.stats,
            "detections": self.detection_agent.get_alerts(),
            "responses": self.response_agent.get_action_history(),
            "blocklist": self.response_agent.get_blocklist()
        }

        with open(output_file, "w") as f:
            json.dump(data, f, indent=2, default=_json_default)

        logger.info(f"Results exported to {output_file}")


# ==================== Example Usage ====================
if __name__ == "__main__":
    logging.basicConfig(
        level=logging.INFO,
        format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
    )
    # Initialize SOC agent
    soc = SOCAgent(dry_run=True)

    # Example: If you have sample pcap files, train and analyze
    sample_benign_pcap = "/tmp/benign.pcap"
    sample_attack_pcap = "/tmp/attack.pcap"

    if Path(sample_benign_pcap).exists():
        soc.train_on_benign_traffic(sample_benign_pcap)

    if Path(sample_attack_pcap).exists():
        results = soc.analyze_pcap(sample_attack_pcap, auto_block_critical=False)

        print("\n" + "="*70)
        print("SOC AGENT ANALYSIS RESULTS")
        print("="*70)
        print(json.dumps(results, indent=2))
        print("="*70)

        # Export results
        soc.export_results("/tmp/soc_results.json")
        print("Results exported to /tmp/soc_results.json")
    else:
        print("Sample pcap files not found. To test:")
        print("1. Download CIC-IDS2017 or Malware-Traffic-Classification pcaps")
        print("2. Place them in /tmp/")
        print("3. Run this script again")

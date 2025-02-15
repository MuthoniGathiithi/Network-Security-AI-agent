"""
Main Orchestrator for Network-Security-AI-Agent

Coordinates detection and response agents in a unified system.
Provides API for real-time analysis and dashboard integration.
"""

import json
import logging
from typing import Dict, Any, List, Optional
from datetime import datetime
from pathlib import Path

import numpy as np

from src.detection_agent import DetectionAgent, FlowFeatures
from src.response_agent import ResponseAgent
from src.packet_capture import PacketCapture

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)


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
        model_path: Optional[str] = None
    ):
        """
        Initialize the SOC Agent.

        Args:
            dry_run: If True, don't execute blocking/alerts
            slack_webhook: Slack webhook URL
            webhook_urls: List of custom webhook URLs
            model_path: Path to pre-trained ML model
        """
        self.detection_agent = DetectionAgent(model_path=model_path)
        self.response_agent = ResponseAgent(
            dry_run=dry_run,
            slack_webhook=slack_webhook,
            webhook_urls=webhook_urls
        )
        self.packet_capture = PacketCapture()

        self.stats = {
            "packets_analyzed": 0,
            "flows_analyzed": 0,
            "threats_detected": 0,
            "critical_alerts": 0,
            "ips_blocked": 0,
            "start_time": datetime.utcnow().isoformat()
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

            if detection.threat_level != "LOW":
                detections.append(detection)
                self.stats["threats_detected"] += 1

                if detection.threat_level == "CRITICAL":
                    self.stats["critical_alerts"] += 1

                    if auto_block_critical:
                        # Execute response
                        detection_dict = {
                            "timestamp": detection.timestamp,
                            "src_ip": detection.src_ip,
                            "dst_ip": detection.dst_ip,
                            "threat_level": detection.threat_level,
                            "attack_type": detection.attack_type,
                            "confidence": detection.confidence,
                            "mitre_techniques": detection.mitre_techniques,
                            "reasoning": detection.reasoning,
                        }

                        actions = self.response_agent.respond_to_detection(detection_dict)
                        responses.extend(actions)

                        if any(a.action_type == "BLOCK_IP" and a.status == "SUCCESS" for a in actions):
                            self.stats["ips_blocked"] += 1

        logger.info(f"Analysis complete: {flow_count} flows, {len(detections)} threats")

        return {
            "file": pcap_file,
            "flows_analyzed": flow_count,
            "threats_detected": len(detections),
            "detections": [
                {
                    "timestamp": d.timestamp,
                    "src_ip": d.src_ip,
                    "dst_ip": d.dst_ip,
                    "threat_level": d.threat_level,
                    "attack_type": d.attack_type,
                    "confidence": d.confidence,
                    "mitre_techniques": d.mitre_techniques,
                    "reasoning": d.reasoning,
                    "ml_score": d.ml_score,
                }
                for d in detections
            ],
            "responses": [
                {
                    "timestamp": a.timestamp,
                    "action_type": a.action_type,
                    "target": a.target,
                    "status": a.status,
                }
                for a in responses
            ],
            "stats": self.stats
        }

    def get_dashboard_data(self) -> Dict[str, Any]:
        """
        Get current state for dashboard display.

        Returns:
            Dictionary with all dashboard data
        """
        return {
            "stats": self.stats,
            "recent_detections": [
                {
                    "timestamp": d.timestamp,
                    "src_ip": d.src_ip,
                    "dst_ip": d.dst_ip,
                    "threat_level": d.threat_level,
                    "attack_type": d.attack_type,
                    "confidence": d.confidence,
                    "reasoning": d.reasoning,
                }
                for d in self.detection_agent.detection_history[-50:]
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
            "export_time": datetime.utcnow().isoformat(),
            "stats": self.stats,
            "detections": self.detection_agent.get_alerts(),
            "responses": self.response_agent.get_action_history(),
            "blocklist": self.response_agent.get_blocklist()
        }

        with open(output_file, "w") as f:
            json.dump(data, f, indent=2)

        logger.info(f"Results exported to {output_file}")


# ==================== Example Usage ====================
if __name__ == "__main__":
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

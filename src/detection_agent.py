"""
Detection Agent for Network-Security-AI-Agent

This agent analyzes network traffic patterns and uses ML models (TabNet, Isolation Forest)
combined with MITRE ATT&CK knowledge to detect malicious behavior in real-time.

Uses CrewAI framework for multi-agent orchestration.
"""

import json
import logging
from typing import Any, Dict, List, Optional
from datetime import datetime
from dataclasses import dataclass, asdict

import numpy as np
from sklearn.ensemble import IsolationForest
from sklearn.preprocessing import StandardScaler

try:
    from crewai import Agent, Task, Crew
except ImportError:
    raise ImportError("CrewAI not installed. Install with: pip install crewai")

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)


@dataclass
class FlowFeatures:
    """
    NetFlow-style features extracted from network packets.
    Compatible with CIC-IDS2017 and common ML models.
    """
    duration: float
    protocol: int
    src_port: int
    dst_port: int
    flow_duration: float
    total_fwd_packets: int
    total_bwd_packets: int
    total_length_of_fwd_packets: int
    total_length_of_bwd_packets: int
    fwd_packet_length_max: float
    fwd_packet_length_min: float
    fwd_packet_length_mean: float
    fwd_packet_length_std: float
    bwd_packet_length_max: float
    bwd_packet_length_min: float
    bwd_packet_length_mean: float
    bwd_packet_length_std: float
    flow_iat_mean: float
    flow_iat_std: float
    flow_iat_max: float
    flow_iat_min: float
    fwd_iat_total: float
    fwd_iat_mean: float
    fwd_iat_std: float
    fwd_iat_max: float
    fwd_iat_min: float
    bwd_iat_total: float
    bwd_iat_mean: float
    bwd_iat_std: float
    bwd_iat_max: float
    bwd_iat_min: float
    fwd_psh_flags: int
    bwd_psh_flags: int
    fwd_urg_flags: int
    bwd_urg_flags: int
    fwd_rst_flags: int
    bwd_rst_flags: int
    fwd_syn_flags: int
    bwd_syn_flags: int
    fwd_fin_flags: int
    bwd_fin_flags: int
    fwd_cwr_flags: int
    bwd_cwr_flags: int
    fwd_ece_flags: int
    bwd_ece_flags: int
    fwd_ack_flags: int
    bwd_ack_flags: int
    down_up_ratio: float
    pkt_size_avg: float
    init_fwd_win_byts: int
    init_bwd_win_byts: int
    active_mean: float
    active_std: float
    active_max: float
    active_min: float
    idle_mean: float
    idle_std: float
    idle_max: float
    idle_min: float

    def to_array(self) -> np.ndarray:
        """Convert all features to a 1D numpy array for ML model input."""
        values = [
            self.duration, self.protocol, self.src_port, self.dst_port,
            self.flow_duration, self.total_fwd_packets, self.total_bwd_packets,
            self.total_length_of_fwd_packets, self.total_length_of_bwd_packets,
            self.fwd_packet_length_max, self.fwd_packet_length_min,
            self.fwd_packet_length_mean, self.fwd_packet_length_std,
            self.bwd_packet_length_max, self.bwd_packet_length_min,
            self.bwd_packet_length_mean, self.bwd_packet_length_std,
            self.flow_iat_mean, self.flow_iat_std, self.flow_iat_max,
            self.flow_iat_min, self.fwd_iat_total, self.fwd_iat_mean,
            self.fwd_iat_std, self.fwd_iat_max, self.fwd_iat_min,
            self.bwd_iat_total, self.bwd_iat_mean, self.bwd_iat_std,
            self.bwd_iat_max, self.bwd_iat_min, self.fwd_psh_flags,
            self.bwd_psh_flags, self.fwd_urg_flags, self.bwd_urg_flags,
            self.fwd_rst_flags, self.bwd_rst_flags, self.fwd_syn_flags,
            self.bwd_syn_flags, self.fwd_fin_flags, self.bwd_fin_flags,
            self.fwd_cwr_flags, self.bwd_cwr_flags, self.fwd_ece_flags,
            self.bwd_ece_flags, self.fwd_ack_flags, self.bwd_ack_flags,
            self.down_up_ratio, self.pkt_size_avg, self.init_fwd_win_byts,
            self.init_bwd_win_byts, self.active_mean, self.active_std,
            self.active_max, self.active_min, self.idle_mean, self.idle_std,
            self.idle_max, self.idle_min
        ]
        return np.array(values, dtype=np.float32).reshape(1, -1)


@dataclass
class DetectionResult:
    """Result from threat detection analysis."""
    timestamp: str
    src_ip: str
    dst_ip: str
    threat_level: str  # "LOW", "MEDIUM", "HIGH", "CRITICAL"
    attack_type: str  # e.g., "DDoS", "Port Scan", "Data Exfiltration"
    confidence: float  # 0.0 - 1.0
    mitre_techniques: List[str]  # e.g., ["T1571", "T1041"]
    reasoning: str  # AI-generated explanation
    raw_features: Dict[str, Any]
    ml_score: float


class MLDetectionModel:
    """
    Lightweight ML model for anomaly detection.
    Uses Isolation Forest for unsupervised anomaly detection.
    """

    def __init__(self, contamination: float = 0.1):
        """
        Initialize the ML detection model.

        Args:
            contamination: Expected proportion of anomalies in the dataset
        """
        self.model = IsolationForest(
            contamination=contamination,
            n_estimators=100,
            random_state=42,
            n_jobs=-1
        )
        self.scaler = StandardScaler()
        self.is_fitted = False
        logger.info("MLDetectionModel initialized with Isolation Forest")

    def fit(self, features: np.ndarray) -> None:
        """
        Train the model on benign network flow data.

        Args:
            features: Array of shape (n_samples, n_features)
        """
        try:
            scaled_features = self.scaler.fit_transform(features)
            self.model.fit(scaled_features)
            self.is_fitted = True
            logger.info(f"Model trained on {len(features)} samples")
        except Exception as e:
            logger.error(f"Model training failed: {e}")
            raise

    def predict(self, features: np.ndarray) -> tuple[int, float]:
        """
        Predict if a flow is anomalous.

        Args:
            features: Array of shape (1, n_features)

        Returns:
            Tuple of (prediction, anomaly_score)
            prediction: -1 for anomaly, 1 for normal
            anomaly_score: Raw anomaly score (higher = more anomalous)
        """
        if not self.is_fitted:
            logger.warning("Model not fitted. Returning neutral prediction.")
            return 1, 0.0

        try:
            scaled = self.scaler.transform(features)
            prediction = self.model.predict(scaled)[0]
            score = -self.model.score_samples(scaled)[0]  # Negate for intuitive scale
            return int(prediction), float(score)
        except Exception as e:
            logger.error(f"Prediction failed: {e}")
            return 1, 0.0


class MitreAttackRAG:
    """
    Retrieval-Augmented Generation over MITRE ATT&CK framework.
    Maps detected behaviors to attack techniques and tactics.
    """

    # Simplified MITRE ATT&CK mapping (production would use full KB)
    ATTACK_MAPPING = {
        "port_scan": {
            "techniques": ["T1046"],
            "tactics": ["Discovery"],
            "description": "Network Service Discovery"
        },
        "ddos": {
            "techniques": ["T1498", "T1499"],
            "tactics": ["Impact"],
            "description": "Network Denial of Service"
        },
        "data_exfiltration": {
            "techniques": ["T1041", "T1020"],
            "tactics": ["Exfiltration"],
            "description": "Exfiltration Over Alternative Protocol"
        },
        "reverse_shell": {
            "techniques": ["T1571", "T1090"],
            "tactics": ["Command and Control", "Defense Evasion"],
            "description": "Non-Standard Port Communication"
        },
        "brute_force": {
            "techniques": ["T1110", "T1021"],
            "tactics": ["Credential Access", "Lateral Movement"],
            "description": "Brute Force Authentication Attack"
        },
    }

    @staticmethod
    def map_attack_type(attack_type: str) -> Dict[str, Any]:
        """
        Map detected attack type to MITRE ATT&CK framework.

        Args:
            attack_type: Detected attack classification

        Returns:
            Dictionary with MITRE techniques, tactics, and description
        """
        key = attack_type.lower().replace(" ", "_")
        return MitreAttackRAG.ATTACK_MAPPING.get(
            key,
            {
                "techniques": ["T1595"],  # Active Scanning (fallback)
                "tactics": ["Reconnaissance"],
                "description": "Unknown Attack Pattern"
            }
        )


class DetectionAgent:
    """
    Main Detection Agent using CrewAI.
    Orchestrates ML analysis, threat correlation, and reasoning.
    """

    def __init__(self, model_path: Optional[str] = None):
        """
        Initialize the Detection Agent.

        Args:
            model_path: Path to pre-trained ML model (optional)
        """
        self.ml_model = MLDetectionModel()
        self.mitre_rag = MitreAttackRAG()
        self.detection_history: List[DetectionResult] = []

        logger.info("Detection Agent initialized")

        # Initialize CrewAI crew
        self._setup_crew()

    def _setup_crew(self) -> None:
        """Setup CrewAI agents and crew for coordinated detection."""
        try:
            # Define ML Analysis Agent
            self.ml_analyst = Agent(
                role="ML Analyst",
                goal="Analyze network flows using machine learning anomaly detection",
                backstory="Expert in network anomaly detection with deep ML knowledge",
                verbose=True,
                allow_delegation=False
            )

            # Define Threat Correlation Agent
            self.threat_analyst = Agent(
                role="Threat Analyst",
                goal="Correlate detected anomalies with known attack patterns from MITRE ATT&CK",
                backstory="Cybersecurity expert familiar with attack tactics and techniques",
                verbose=True,
                allow_delegation=False
            )

            logger.info("CrewAI crew setup complete")
        except Exception as e:
            logger.warning(f"CrewAI setup failed (non-critical): {e}")

    def train(self, training_data: np.ndarray) -> None:
        """
        Train the ML model on benign traffic.

        Args:
            training_data: Array of shape (n_samples, n_features) containing benign flows
        """
        self.ml_model.fit(training_data)
        logger.info("Detection Agent ML model trained")

    def detect(
        self,
        flow_features: FlowFeatures,
        src_ip: str,
        dst_ip: str
    ) -> DetectionResult:
        """
        Analyze a network flow for malicious behavior.

        Args:
            flow_features: FlowFeatures object with network metrics
            src_ip: Source IP address
            dst_ip: Destination IP address

        Returns:
            DetectionResult with threat assessment and reasoning
        """
        # 1. ML-based anomaly detection
        features_array = flow_features.to_array()
        prediction, ml_score = self.ml_model.predict(features_array)
        is_anomaly = prediction == -1

        # 2. Heuristic-based attack type classification
        attack_type = self._classify_attack_type(flow_features)

        # 3. Determine threat level
        if not is_anomaly:
            threat_level = "LOW"
            confidence = 0.1
        else:
            if ml_score > 0.8:
                threat_level = "CRITICAL"
                confidence = 0.95
            elif ml_score > 0.6:
                threat_level = "HIGH"
                confidence = 0.85
            elif ml_score > 0.4:
                threat_level = "MEDIUM"
                confidence = 0.70
            else:
                threat_level = "LOW"
                confidence = 0.50

        # 4. Map to MITRE ATT&CK
        mitre_info = self.mitre_rag.map_attack_type(attack_type)

        # 5. Generate AI reasoning
        reasoning = self._generate_reasoning(
            flow_features, ml_score, attack_type, mitre_info
        )

        # 6. Create detection result
        result = DetectionResult(
            timestamp=datetime.utcnow().isoformat(),
            src_ip=src_ip,
            dst_ip=dst_ip,
            threat_level=threat_level,
            attack_type=attack_type,
            confidence=confidence,
            mitre_techniques=mitre_info["techniques"],
            reasoning=reasoning,
            raw_features=asdict(flow_features),
            ml_score=ml_score
        )

        self.detection_history.append(result)
        logger.info(
            f"Detection: {src_ip} -> {dst_ip} | "
            f"Threat: {threat_level} | Attack: {attack_type}"
        )

        return result

    def _classify_attack_type(self, features: FlowFeatures) -> str:
        """
        Classify the type of attack using heuristics.

        Args:
            features: FlowFeatures object

        Returns:
            Attack type string
        """
        # Port scanning: many packets to different ports, short duration
        if (features.total_fwd_packets > 20 and
            features.fwd_packet_length_mean < 100 and
            features.flow_duration < 5):
            return "Port Scan"

        # DDoS: high packet volume, many connections
        if (features.total_fwd_packets > 1000 or
            features.total_length_of_fwd_packets > 1000000):
            return "DDoS"

        # Data exfiltration: high bwd packet volume, long duration
        if (features.total_length_of_bwd_packets > 500000 and
            features.flow_duration > 30):
            return "Data Exfiltration"

        # Reverse shell: non-standard ports, bidirectional activity
        if (features.dst_port > 10000 and
            features.total_bwd_packets > 50 and
            features.total_fwd_packets > 50):
            return "Reverse Shell"

        # Brute force: many failed connections
        if (features.fwd_syn_flags > 20 and
            features.bwd_rst_flags > 10):
            return "Brute Force"

        return "Suspicious Behavior"

    def _generate_reasoning(
        self,
        features: FlowFeatures,
        ml_score: float,
        attack_type: str,
        mitre_info: Dict[str, Any]
    ) -> str:
        """
        Generate human-readable reasoning for the detection.

        Args:
            features: Network flow features
            ml_score: ML anomaly score
            attack_type: Classified attack type
            mitre_info: MITRE ATT&CK mapping

        Returns:
            Reasoning string
        """
        reasoning_parts = []

        # ML analysis
        if ml_score > 0.6:
            reasoning_parts.append(
                f"ML model flagged as anomalous (score: {ml_score:.2f}). "
                f"Pattern significantly deviates from benign traffic."
            )
        else:
            reasoning_parts.append(
                f"ML model detected subtle anomaly (score: {ml_score:.2f})."
            )

        # Behavioral analysis
        if features.total_fwd_packets > 500:
            reasoning_parts.append(
                f"Unusually high forward packet count ({features.total_fwd_packets})."
            )

        if features.dst_port > 10000:
            reasoning_parts.append(
                f"Non-standard destination port ({features.dst_port}) detected."
            )

        if features.flow_duration > 300:
            reasoning_parts.append(
                f"Extended flow duration ({features.flow_duration}s) suggests "
                "persistent connection or data transfer."
            )

        # MITRE mapping
        techniques_str = ", ".join(mitre_info["techniques"])
        reasoning_parts.append(
            f"Behavior maps to MITRE ATT&CK techniques: {techniques_str} "
            f"({mitre_info['description']})."
        )

        return " ".join(reasoning_parts)

    def get_alerts(self) -> List[Dict[str, Any]]:
        """Return all detection alerts as JSON-serializable dicts."""
        return [asdict(r) for r in self.detection_history]

    def clear_history(self) -> None:
        """Clear detection history."""
        self.detection_history.clear()
        logger.info("Detection history cleared")


# ==================== Example Usage ====================
if __name__ == "__main__":
    # Initialize agent
    agent = DetectionAgent()

    # Generate synthetic benign training data
    n_samples = 100
    n_features = 60

    np.random.seed(42)
    benign_data = np.random.randn(n_samples, n_features) * 0.5 + 0.1

    # Train the model
    agent.train(benign_data)

    # Create a suspicious flow
    suspicious_flow = FlowFeatures(
        duration=0.5, protocol=6, src_port=12345, dst_port=443,
        flow_duration=2.0, total_fwd_packets=150, total_bwd_packets=100,
        total_length_of_fwd_packets=50000, total_length_of_bwd_packets=40000,
        fwd_packet_length_max=1000, fwd_packet_length_min=10,
        fwd_packet_length_mean=333, fwd_packet_length_std=250,
        bwd_packet_length_max=1000, bwd_packet_length_min=10,
        bwd_packet_length_mean=400, bwd_packet_length_std=300,
        flow_iat_mean=10, flow_iat_std=5, flow_iat_max=50, flow_iat_min=1,
        fwd_iat_total=1500, fwd_iat_mean=10, fwd_iat_std=5,
        fwd_iat_max=50, fwd_iat_min=1, bwd_iat_total=1200, bwd_iat_mean=12,
        bwd_iat_std=6, bwd_iat_max=60, bwd_iat_min=1, fwd_psh_flags=0,
        bwd_psh_flags=0, fwd_urg_flags=0, bwd_urg_flags=0, fwd_rst_flags=0,
        bwd_rst_flags=0, fwd_syn_flags=1, bwd_syn_flags=1, fwd_fin_flags=0,
        bwd_fin_flags=0, fwd_cwr_flags=0, bwd_cwr_flags=0, fwd_ece_flags=0,
        bwd_ece_flags=0, fwd_ack_flags=100, bwd_ack_flags=80, down_up_ratio=0.8,
        pkt_size_avg=400, init_fwd_win_byts=65535, init_bwd_win_byts=65535,
        active_mean=1.0, active_std=0.5, active_max=5, active_min=0.1,
        idle_mean=2.0, idle_std=1.0, idle_max=10, idle_min=0.1
    )

    # Perform detection
    result = agent.detect(suspicious_flow, "192.168.1.100", "8.8.8.8")

    print("\n" + "="*60)
    print("DETECTION RESULT")
    print("="*60)
    print(f"Threat Level: {result.threat_level}")
    print(f"Attack Type: {result.attack_type}")
    print(f"Confidence: {result.confidence:.2%}")
    print(f"MITRE Techniques: {', '.join(result.mitre_techniques)}")
    print(f"\nReasoning:\n{result.reasoning}")
    print("="*60)

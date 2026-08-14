"""
Detection Agent for Network-Security-AI-Agent

This agent analyzes network traffic patterns and uses ML models (TabNet, Isolation Forest)
combined with MITRE ATT&CK knowledge to detect malicious behavior in real-time.

CrewAI agents are optional (enable_crew=True); detection itself runs on
the local ML model and heuristics and needs no LLM.
"""

import json
import logging
import os
import stat
import tempfile
import time
from collections import OrderedDict, deque
from typing import Any, Callable, Deque, Dict, List, Optional, Tuple
from datetime import datetime, timezone
from dataclasses import dataclass, asdict, fields

import joblib
import numpy as np
import sklearn
from sklearn.ensemble import IsolationForest
from sklearn.preprocessing import StandardScaler

from src.threat import ThreatLevel

try:
    from crewai import Agent
    CREWAI_AVAILABLE = True
except ImportError:
    CREWAI_AVAILABLE = False

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

    def __post_init__(self) -> None:
        """
        Coerce every field to its declared Python type.

        Feature extraction produces numpy scalars (np.float64, np.int64),
        which json can't serialize. Normalizing here means every consumer
        (export, API, dashboard) gets plain int/float values.
        """
        for f in fields(self):
            setattr(self, f.name, f.type(getattr(self, f.name)))

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
    threat_level: ThreatLevel
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
        self.n_features: Optional[int] = None
        self.n_samples: Optional[int] = None
        self.trained_at: Optional[str] = None
        self._warned_unfitted = False
        logger.info("MLDetectionModel initialized with Isolation Forest")

    # Bump when the saved bundle layout changes
    MODEL_FORMAT_VERSION = 1

    def save(self, path: str) -> None:
        """
        Save the fitted model and scaler to a single joblib file.

        The file is written atomically with owner-only permissions (0600).

        Args:
            path: Destination file path

        Raises:
            RuntimeError: If the model hasn't been trained
        """
        if not self.is_fitted:
            raise RuntimeError("Cannot save an untrained model; call fit() first")

        bundle = {
            "format_version": self.MODEL_FORMAT_VERSION,
            "model": self.model,
            "scaler": self.scaler,
            "n_features": self.n_features,
            "n_samples": self.n_samples,
            "trained_at": self.trained_at,
            "sklearn_version": sklearn.__version__,
        }

        directory = os.path.dirname(os.path.abspath(path))
        os.makedirs(directory, mode=0o700, exist_ok=True)
        fd, tmp_path = tempfile.mkstemp(dir=directory, prefix=".model-", suffix=".tmp")
        try:
            with os.fdopen(fd, "wb") as f:
                joblib.dump(bundle, f)
            os.replace(tmp_path, path)
        except BaseException:
            try:
                os.unlink(tmp_path)
            except FileNotFoundError:
                pass
            raise
        logger.info(f"Model saved to {path}")

    @classmethod
    def load(cls, path: str) -> "MLDetectionModel":
        """
        Load a model saved with save().

        joblib files are pickles, and unpickling can execute arbitrary code,
        so only load models you created. As a guard, files that other users
        can modify are refused.

        Args:
            path: Path to the saved model

        Returns:
            A fitted MLDetectionModel

        Raises:
            FileNotFoundError: If the file doesn't exist
            PermissionError: If the file is writable by group or others
            ValueError: If the file isn't a model saved by this class
        """
        if not os.path.isfile(path):
            raise FileNotFoundError(f"Model file not found: {path}")
        if os.stat(path).st_mode & (stat.S_IWGRP | stat.S_IWOTH):
            raise PermissionError(
                f"Refusing to load {path}: it is writable by other users and "
                f"could have been tampered with (chmod 600 it if you trust it)"
            )

        bundle = joblib.load(path)

        if (not isinstance(bundle, dict)
                or bundle.get("format_version") != cls.MODEL_FORMAT_VERSION
                or not isinstance(bundle.get("model"), IsolationForest)
                or not isinstance(bundle.get("scaler"), StandardScaler)):
            raise ValueError(
                f"{path} is not a model saved by MLDetectionModel.save() "
                f"(format version {cls.MODEL_FORMAT_VERSION})"
            )

        if bundle.get("sklearn_version") != sklearn.__version__:
            logger.warning(
                f"Model was saved with scikit-learn {bundle.get('sklearn_version')} "
                f"but {sklearn.__version__} is installed; consider retraining"
            )

        instance = cls()
        instance.model = bundle["model"]
        instance.scaler = bundle["scaler"]
        instance.n_features = bundle["n_features"]
        instance.n_samples = bundle.get("n_samples")
        instance.trained_at = bundle.get("trained_at")
        instance.is_fitted = True
        logger.info(
            f"Model loaded from {path} (trained {instance.trained_at} "
            f"on {instance.n_samples} samples)"
        )
        return instance

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
            self.n_samples, self.n_features = features.shape
            self.trained_at = datetime.now(timezone.utc).isoformat()
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

        Raises:
            ValueError: If the features don't match what the model was
                trained on. Errors are raised rather than reported as
                "normal", so a broken model can't silently hide attacks.
        """
        if not self.is_fitted:
            if not self._warned_unfitted:
                logger.warning(
                    "Model not fitted; all flows will be rated normal until "
                    "train() is called. (This warning is shown once.)"
                )
                self._warned_unfitted = True
            return 1, 0.0

        scaled = self.scaler.transform(features)
        prediction = self.model.predict(scaled)[0]
        score = -self.model.score_samples(scaled)[0]  # Negate for intuitive scale
        return int(prediction), float(score)


@dataclass
class ScanFinding:
    """A port scan or host sweep observed across multiple flows."""
    kind: str  # "vertical" (many ports, one host) or "horizontal" (one port, many hosts)
    targets: int  # distinct ports (vertical) or hosts (horizontal) probed
    window_seconds: float

    def describe(self) -> str:
        what = "ports on one host" if self.kind == "vertical" else "hosts on one port"
        return (
            f"Source sent failed probes to {self.targets} distinct {what} "
            f"within {self.window_seconds:.0f}s ({self.kind} scan)."
        )


class PortScanTracker:
    """
    Detects port scans across flows.

    A single flow can't reveal a scan; a scan is many short flows from one
    source. Only failed probes count (few packets, and no reply or an RST
    back), so normal clients talking to many servers on :443 don't trigger it.
    """

    def __init__(
        self,
        window_seconds: float = 60.0,
        threshold: int = 15,
        max_sources: int = 10_000,
        clock: Callable[[], float] = time.monotonic
    ):
        """
        Args:
            window_seconds: Sliding window for counting probes
            threshold: Distinct ports (or hosts) that constitute a scan
            max_sources: Sources tracked at once; least recently seen are
                evicted, bounding memory under spoofed-source floods
            clock: Time source (injectable for tests)
        """
        self.window_seconds = window_seconds
        self.threshold = threshold
        self.max_sources = max_sources
        self.clock = clock
        # src_ip -> deque of (time, dst_ip, dst_port)
        self._probes: "OrderedDict[str, Deque[Tuple[float, str, int]]]" = OrderedDict()

    @staticmethod
    def is_probe(features: "FlowFeatures") -> bool:
        """A short flow that got no reply or was refused with RST."""
        return (
            features.total_fwd_packets <= 3
            and (features.total_bwd_packets == 0 or features.bwd_rst_flags > 0)
        )

    def observe(
        self,
        src_ip: str,
        dst_ip: str,
        features: "FlowFeatures"
    ) -> Optional[ScanFinding]:
        """
        Record a flow and report a scan if the source crossed the threshold.

        Args:
            src_ip: Flow initiator
            dst_ip: Flow responder
            features: Flow features

        Returns:
            ScanFinding if this source is scanning, else None
        """
        if not self.is_probe(features):
            return None

        now = self.clock()
        probes = self._probes.pop(src_ip, None) or deque()
        probes.append((now, dst_ip, features.dst_port))
        while probes and now - probes[0][0] > self.window_seconds:
            probes.popleft()
        self._probes[src_ip] = probes  # re-insert as most recently seen
        if len(self._probes) > self.max_sources:
            self._probes.popitem(last=False)

        ports_on_this_host = {port for _, dst, port in probes if dst == dst_ip}
        if len(ports_on_this_host) >= self.threshold:
            return ScanFinding("vertical", len(ports_on_this_host), self.window_seconds)

        hosts_on_this_port = {
            dst for _, dst, port in probes if port == features.dst_port
        }
        if len(hosts_on_this_port) >= self.threshold:
            return ScanFinding("horizontal", len(hosts_on_this_port), self.window_seconds)

        return None


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

    DEFAULT_MAX_HISTORY = 10_000

    def __init__(
        self,
        model_path: Optional[str] = None,
        max_history: int = DEFAULT_MAX_HISTORY,
        enable_crew: bool = False
    ):
        """
        Initialize the Detection Agent.

        Args:
            model_path: Path to a model saved with save_model() (optional)
            max_history: Maximum detections kept in memory. Oldest are
                dropped first, so long-running live capture can't exhaust
                memory. Use export_results() to persist them.
            enable_crew: Set up CrewAI analyst agents. Off by default: they
                need the crewai package and an LLM API key, and detection
                doesn't depend on them.
        """
        if max_history < 1:
            raise ValueError("max_history must be at least 1")

        if model_path:
            self.ml_model = MLDetectionModel.load(model_path)
            expected = len(fields(FlowFeatures))
            if self.ml_model.n_features != expected:
                raise ValueError(
                    f"Model at {model_path} expects {self.ml_model.n_features} "
                    f"features but FlowFeatures has {expected}; retrain it"
                )
        else:
            self.ml_model = MLDetectionModel()
        self.mitre_rag = MitreAttackRAG()
        self.scan_tracker = PortScanTracker()
        self.detection_history: Deque[DetectionResult] = deque(maxlen=max_history)

        self.ml_analyst = None
        self.threat_analyst = None

        logger.info("Detection Agent initialized")

        if enable_crew:
            self._setup_crew()

    def _setup_crew(self) -> None:
        """Setup CrewAI agents and crew for coordinated detection."""
        if not CREWAI_AVAILABLE:
            logger.warning(
                "enable_crew=True but CrewAI is not installed "
                "(pip install crewai); continuing without it"
            )
            return

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

        Raises:
            ValueError: If the column count doesn't match FlowFeatures
        """
        expected = len(fields(FlowFeatures))
        if training_data.ndim != 2 or training_data.shape[1] != expected:
            raise ValueError(
                f"Training data must have shape (n_samples, {expected}) to match "
                f"FlowFeatures; got {training_data.shape}"
            )
        self.ml_model.fit(training_data)
        logger.info("Detection Agent ML model trained")

    def save_model(self, path: str) -> None:
        """
        Save the trained ML model so it can be reloaded via model_path.

        Args:
            path: Destination file path
        """
        self.ml_model.save(path)

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

        # 2. Attack type: cross-flow scan detection first, then single-flow
        # heuristics
        scan = self.scan_tracker.observe(src_ip, dst_ip, flow_features)
        attack_type = "Port Scan" if scan else self._classify_attack_type(flow_features)

        # 3. Determine threat level
        if not is_anomaly:
            threat_level = ThreatLevel.LOW
            confidence = 0.1
        else:
            if ml_score > 0.8:
                threat_level = ThreatLevel.CRITICAL
                confidence = 0.95
            elif ml_score > 0.6:
                threat_level = ThreatLevel.HIGH
                confidence = 0.85
            elif ml_score > 0.4:
                threat_level = ThreatLevel.MEDIUM
                confidence = 0.70
            else:
                threat_level = ThreatLevel.LOW
                confidence = 0.50

        # Individual scan probes look harmless to the ML model, so a scan
        # seen across flows raises the level on its own. HIGH alerts but
        # doesn't auto-block: scans are reconnaissance and often spoofed.
        if scan:
            threat_level = max(threat_level, ThreatLevel.HIGH)
            confidence = max(confidence, min(0.95, 0.6 + 0.01 * scan.targets))

        # 4. Map to MITRE ATT&CK
        mitre_info = self.mitre_rag.map_attack_type(attack_type)

        # 5. Generate AI reasoning
        reasoning = self._generate_reasoning(
            flow_features, ml_score, is_anomaly, attack_type, mitre_info,
            confirmed_by_heuristics=scan is not None
        )
        if scan:
            reasoning = f"{scan.describe()} {reasoning}"

        # 6. Create detection result
        result = DetectionResult(
            timestamp=datetime.now(timezone.utc).isoformat(),
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
        # Port scans span many flows and are detected by PortScanTracker,
        # not by looking at one flow

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
        is_anomaly: bool,
        attack_type: str,
        mitre_info: Dict[str, Any],
        confirmed_by_heuristics: bool = False
    ) -> str:
        """
        Generate human-readable reasoning for the detection.

        Args:
            features: Network flow features
            ml_score: ML anomaly score
            is_anomaly: Whether the ML model classified the flow as anomalous
            attack_type: Classified attack type
            mitre_info: MITRE ATT&CK mapping
            confirmed_by_heuristics: True when cross-flow evidence (e.g. a
                port scan) confirms the attack even without an ML anomaly

        Returns:
            Reasoning string
        """
        reasoning_parts = []

        # ML analysis
        if not self.ml_model.is_fitted:
            reasoning_parts.append(
                "ML model is not trained, so no anomaly assessment was made."
            )
        elif not is_anomaly:
            reasoning_parts.append(
                f"ML model rated this flow as normal (score: {ml_score:.2f})."
            )
        elif ml_score > 0.6:
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
        if is_anomaly or confirmed_by_heuristics:
            reasoning_parts.append(
                f"Behavior maps to MITRE ATT&CK techniques: {techniques_str} "
                f"({mitre_info['description']})."
            )
        else:
            reasoning_parts.append(
                f"Heuristics matched '{attack_type}' "
                f"(MITRE ATT&CK {techniques_str}), but without an ML anomaly "
                f"this is informational only."
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
    logging.basicConfig(
        level=logging.INFO,
        format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
    )
    # Initialize agent
    agent = DetectionAgent()

    # Generate synthetic benign training data
    n_samples = 100
    n_features = len(fields(FlowFeatures))

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

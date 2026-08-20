#!/usr/bin/env python3
"""
Train the anomaly detection model for the Network Security AI Agent.

The model is trained on the same 59 FlowFeatures the agent extracts at
runtime and saved in the format SOCAgent(model_path=...) loads.

Examples:
    # From benign packet captures (recommended: features match live traffic)
    python scripts/train_model.py --pcap benign-monday.pcap --output models/model.joblib

    # From a CSV whose columns are the FlowFeatures names
    python scripts/train_model.py --csv flows.csv --output models/model.joblib
"""

import argparse
import json
import logging
import os
import sys
from typing import List

import numpy as np
from sklearn.model_selection import train_test_split

# Make `src` importable when run as a script
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from src.detection_agent import FlowFeatures, MLDetectionModel  # noqa: E402
from src.packet_capture import PacketCapture  # noqa: E402
from src.threat import ThreatLevel  # noqa: E402

logger = logging.getLogger("train_model")

FEATURE_NAMES = FlowFeatures.feature_names()
BENIGN_LABELS = {"benign", "normal", "0"}


def load_pcaps(paths: List[str]) -> np.ndarray:
    """
    Extract FlowFeatures from benign packet captures.

    Args:
        paths: pcap/pcapng files containing known-benign traffic

    Returns:
        Array of shape (n_flows, n_features)
    """
    rows = []
    for path in paths:
        before = len(rows)
        for features, _, _ in PacketCapture().read_pcap(path):
            rows.append(features.to_array()[0])
        logger.info(f"Extracted {len(rows) - before} flows from {path}")
    return np.array(rows, dtype=np.float64).reshape(-1, len(FEATURE_NAMES))


def load_csv(path: str) -> np.ndarray:
    """
    Load flows from a CSV with one column per FlowFeatures field.

    If a 'label' column exists, only benign rows are kept, since the model
    must learn what normal traffic looks like.

    Args:
        path: CSV file

    Returns:
        Array of shape (n_flows, n_features)

    Raises:
        ValueError: If required feature columns are missing
    """
    import pandas as pd  # only needed for CSV input

    df = pd.read_csv(path)
    df.columns = [c.strip() for c in df.columns]

    missing = [name for name in FEATURE_NAMES if name not in df.columns]
    if missing:
        raise ValueError(
            f"{path} is missing {len(missing)} FlowFeatures columns "
            f"(e.g. {', '.join(missing[:5])}). The CSV must use the agent's "
            f"feature names; train from --pcap to extract them automatically."
        )

    if "label" in df.columns:
        is_benign = df["label"].astype(str).str.strip().str.lower().isin(BENIGN_LABELS)
        logger.info(f"Keeping {int(is_benign.sum())} benign of {len(df)} labeled rows")
        df = df[is_benign]

    X = df[FEATURE_NAMES].apply(pd.to_numeric, errors="coerce")
    X = X.replace([np.inf, -np.inf], np.nan)
    dropped = int(X.isna().any(axis=1).sum())
    if dropped:
        logger.warning(f"Dropping {dropped} rows with missing or non-numeric values")
    return X.dropna().to_numpy(dtype=np.float64)


def evaluate(model: MLDetectionModel, X_test: np.ndarray) -> dict:
    """
    Score held-out benign flows against the calibrated thresholds.

    On benign data, the MEDIUM rate should be around 1% and HIGH/CRITICAL
    close to 0%; much higher rates mean the training data didn't cover
    normal traffic well.

    Args:
        model: Fitted model
        X_test: Held-out benign flows

    Returns:
        Dictionary of evaluation metrics
    """
    scaled = model.scaler.transform(X_test)
    scores = -model.model.score_samples(scaled)
    t = model.thresholds
    return {
        "test_samples": int(len(X_test)),
        "thresholds": {level.value: value for level, value in t.items()},
        "false_positive_rate": float(np.mean(scores > t[ThreatLevel.MEDIUM])),
        "high_or_above_rate": float(np.mean(scores > t[ThreatLevel.HIGH])),
        "critical_rate": float(np.mean(scores > t[ThreatLevel.CRITICAL])),
        "score_mean": float(np.mean(scores)),
        "score_std": float(np.std(scores)),
        "score_p95": float(np.percentile(scores, 95)),
        "score_max": float(np.max(scores)),
    }


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Train the anomaly detection model on benign traffic"
    )
    source = parser.add_argument_group("training data (at least one)")
    source.add_argument("--pcap", action="append", default=[],
                        help="Benign pcap/pcapng file (repeatable)")
    source.add_argument("--csv", help="CSV with one column per FlowFeatures field")
    parser.add_argument("--output", default="models/model.joblib",
                        help="Where to save the model (default: models/model.joblib)")
    parser.add_argument("--contamination", type=float, default=0.1,
                        help="Expected proportion of anomalies (default: 0.1)")
    parser.add_argument("--test-size", type=float, default=0.2,
                        help="Fraction of flows held out for evaluation (default: 0.2)")
    parser.add_argument("--seed", type=int, default=42,
                        help="Random seed for the train/test split")
    args = parser.parse_args()

    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s - %(name)s - %(levelname)s - %(message)s"
    )

    if not args.pcap and not args.csv:
        parser.error("provide at least one --pcap or --csv")
    if not 0 < args.contamination <= 0.5:
        parser.error("--contamination must be in (0, 0.5]")
    if not 0 < args.test_size < 1:
        parser.error("--test-size must be between 0 and 1")

    try:
        parts = []
        if args.pcap:
            parts.append(load_pcaps(args.pcap))
        if args.csv:
            parts.append(load_csv(args.csv))
        X = np.vstack(parts)

        min_flows = 10
        if len(X) < min_flows:
            logger.error(f"Only {len(X)} flows found; need at least {min_flows} to train")
            return 1

        X_train, X_test = train_test_split(
            X, test_size=args.test_size, random_state=args.seed
        )
        logger.info(f"Training on {len(X_train)} flows, evaluating on {len(X_test)}")

        model = MLDetectionModel(contamination=args.contamination)
        model.fit(X_train, feature_names=FEATURE_NAMES)

        metrics = evaluate(model, X_test)
        logger.info(f"Evaluation: {metrics}")

        model.save(args.output)
        metrics_path = os.path.splitext(args.output)[0] + ".metrics.json"
        with open(metrics_path, "w") as f:
            json.dump(metrics, f, indent=2)

        logger.info(f"Done. Load it with SOCAgent(model_path={args.output!r})")
        return 0

    except Exception as e:
        logger.error(f"Training failed: {e}")
        return 1


if __name__ == "__main__":
    sys.exit(main())

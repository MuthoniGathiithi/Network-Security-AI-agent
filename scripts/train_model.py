#!/usr/bin/env python3
"""
Script to train the ML model for the Network Security AI Agent.
"""

import os
import sys
import logging
import argparse
import numpy as np
import pandas as pd
from sklearn.model_selection import train_test_split
from sklearn.preprocessing import StandardScaler
from sklearn.ensemble import IsolationForest
import joblib

# Add src to path
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from src.detection_agent import MLDetectionModel

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

def load_data(file_path: str) -> pd.DataFrame:
    """
    Load training data from CSV file.
    
    Args:
        file_path: Path to CSV file
        
    Returns:
        DataFrame with training data
    """
    logger.info(f"Loading data from {file_path}")
    try:
        df = pd.read_csv(file_path)
        logger.info(f"Loaded {len(df)} samples with {df.shape[1]} features")
        return df
    except Exception as e:
        logger.error(f"Error loading data: {e}")
        raise

def preprocess_data(df: pd.DataFrame) -> tuple:
    """
    Preprocess the training data.
    
    Args:
        df: Input DataFrame
        
    Returns:
        Tuple of (X, y) where X is the feature matrix and y is the target
    """
    # Drop non-numeric columns and columns with too many missing values
    df = df.select_dtypes(include=[np.number])
    df = df.dropna(axis=1, thresh=0.8*len(df))
    
    # Fill remaining missing values with column mean
    df = df.fillna(df.mean())
    
    # Separate features and target if 'label' column exists
    if 'label' in df.columns:
        X = df.drop(columns=['label'])
        y = df['label']
    else:
        X = df
        y = None
    
    return X, y

def train_model(X: np.ndarray, contamination: float = 0.1) -> tuple:
    """
    Train the Isolation Forest model.
    
    Args:
        X: Feature matrix
        contamination: Expected proportion of anomalies
        
    Returns:
        Tuple of (model, scaler)
    """
    logger.info("Training model...")
    
    # Scale features
    scaler = StandardScaler()
    X_scaled = scaler.fit_transform(X)
    
    # Train model
    model = IsolationForest(
        n_estimators=100,
        contamination=contamination,
        random_state=42,
        n_jobs=-1,
        verbose=1
    )
    model.fit(X_scaled)
    
    return model, scaler

def evaluate_model(model, X_test: np.ndarray) -> dict:
    """
    Evaluate the trained model.
    
    Args:
        model: Trained model
        X_test: Test features
        
    Returns:
        Dictionary of evaluation metrics
    """
    logger.info("Evaluating model...")
    
    # Get anomaly scores
    scores = model.decision_function(X_test)
    
    # Calculate metrics
    metrics = {
        'avg_anomaly_score': float(np.mean(scores)),
        'std_anomaly_score': float(np.std(scores)),
        'min_score': float(np.min(scores)),
        'max_score': float(np.max(scores))
    }
    
    logger.info(f"Evaluation metrics: {metrics}")
    return metrics

def save_model(model, scaler, output_dir: str, metrics: dict = None) -> str:
    """
    Save the trained model and scaler.
    
    Args:
        model: Trained model
        scaler: Fitted scaler
        output_dir: Directory to save the model
        metrics: Model evaluation metrics
        
    Returns:
        Path to saved model
    """
    os.makedirs(output_dir, exist_ok=True)
    
    # Save model
    model_path = os.path.join(output_dir, 'model.joblib')
    joblib.dump(model, model_path)
    
    # Save scaler
    scaler_path = os.path.join(output_dir, 'scaler.joblib')
    joblib.dump(scaler, scaler_path)
    
    # Save metrics
    if metrics:
        metrics_path = os.path.join(output_dir, 'metrics.json')
        with open(metrics_path, 'w') as f:
            json.dump(metrics, f, indent=2)
    
    logger.info(f"Model saved to {model_path}")
    return model_path

def main():
    parser = argparse.ArgumentParser(description='Train ML model for Network Security AI Agent')
    parser.add_argument('--input', type=str, required=True,
                        help='Path to input CSV file')
    parser.add_argument('--output-dir', type=str, default='models',
                        help='Directory to save the trained model')
    parser.add_argument('--contamination', type=float, default=0.1,
                        help='Expected proportion of anomalies in the data')
    parser.add_argument('--test-size', type=float, default=0.2,
                        help='Proportion of data to use for testing')
    parser.add_argument('--seed', type=int, default=42,
                        help='Random seed for reproducibility')
    
    args = parser.parse_args()
    
    # Set random seed
    np.random.seed(args.seed)
    
    try:
        # Load and preprocess data
        df = load_data(args.input)
        X, _ = preprocess_data(df)
        
        # Split data
        X_train, X_test = train_test_split(
            X, 
            test_size=args.test_size,
            random_state=args.seed
        )
        
        # Train model
        model, scaler = train_model(X_train, contamination=args.contamination)
        
        # Evaluate model
        X_test_scaled = scaler.transform(X_test)
        metrics = evaluate_model(model, X_test_scaled)
        
        # Save model
        model_path = save_model(model, scaler, args.output_dir, metrics)
        
        logger.info("Training completed successfully!")
        return 0
        
    except Exception as e:
        logger.error(f"Error during training: {e}")
        return 1

if __name__ == "__main__":
    sys.exit(main())

"""
Machine Learning-based Anomaly Detection
"""

import numpy as np
import pandas as pd
from sklearn.ensemble import IsolationForest
from sklearn.preprocessing import StandardScaler
import joblib
from pathlib import Path
import logging
from typing import Dict, List, Tuple, Optional
from datetime import datetime
import threading
import time

from config.settings import ML_CONFIG, MODEL_DIR
from core.utils import FeatureExtractor

class MLAnomalyDetector:
    """Advanced ML-based anomaly detection system"""
    
    def __init__(self):
        self.model = None
        self.scaler = StandardScaler()
        self.feature_extractor = FeatureExtractor()
        self.training_data = []
        self.is_training = False
        self.anomaly_history = []
        self.logger = logging.getLogger(__name__)
        self.last_training_time = 0
        self.model_lock = threading.Lock()
        
        # Load or create model
        self.model_path = MODEL_DIR / 'anomaly_model.pkl'
        self.scaler_path = MODEL_DIR / 'scaler.pkl'
        self.load_model()
        
    def load_model(self):
        """Load pre-trained model if exists"""
        try:
            if self.model_path.exists():
                self.model = joblib.load(self.model_path)
                self.scaler = joblib.load(self.scaler_path)
                self.logger.info("ML model loaded successfully")
            else:
                self._initialize_model()
        except Exception as e:
            self.logger.error(f"Error loading model: {e}")
            self._initialize_model()
            
    def _initialize_model(self):
        """Initialize new model"""
        self.model = IsolationForest(
            contamination=ML_CONFIG['contamination'],
            n_estimators=ML_CONFIG['n_estimators'],
            max_samples=ML_CONFIG['max_samples'],
            random_state=ML_CONFIG['random_state']
        )
        self.logger.info("New ML model initialized")
        
    def train_model(self, training_packets: List[Dict]):
        """Train the ML model on normal traffic"""
        if self.is_training:
            return
            
        self.is_training = True
        try:
            # Extract features from training packets
            features = []
            for packet in training_packets[:1000]:  # Limit training size
                feat = self.feature_extractor.extract_features(packet)
                if feat is not None:
                    features.append(feat.flatten())
                    
            if len(features) > 100:
                features_array = np.array(features)
                # Scale features
                self.scaler.fit(features_array)
                scaled_features = self.scaler.transform(features_array)
                # Train model
                with self.model_lock:
                    self.model.fit(scaled_features)
                # Save model
                joblib.dump(self.model, self.model_path)
                joblib.dump(self.scaler, self.scaler_path)
                self.last_training_time = time.time()
                self.logger.info(f"Model trained with {len(features)} samples")
                
        except Exception as e:
            self.logger.error(f"Training error: {e}")
        finally:
            self.is_training = False
            
    def detect_anomaly(self, packet: Dict) -> Tuple[bool, float]:
        """Detect if packet is anomalous"""
        if self.model is None:
            return False, 0.0
            
        try:
            # Extract features
            features = self.feature_extractor.extract_features(packet)
            if features is None or len(features[0]) == 0:
                return False, 0.0
                
            # Scale features
            scaled_features = self.scaler.transform(features)
            
            # Predict
            with self.model_lock:
                prediction = self.model.predict(scaled_features)
                anomaly_score = self.model.score_samples(scaled_features)
                
            # Convert to confidence (higher score = more anomalous)
            confidence = 1 - (anomaly_score[0] + 0.5)  # Normalize to [0,1]
            confidence = min(max(confidence, 0), 1)
            
            is_anomaly = prediction[0] == -1
            
            if is_anomaly:
                self.anomaly_history.append({
                    'timestamp': datetime.now(),
                    'score': confidence,
                    'packet': packet
                })
                # Keep only last 1000 anomalies
                self.anomaly_history = self.anomaly_history[-1000:]
                
            return is_anomaly, confidence
            
        except Exception as e:
            self.logger.error(f"Detection error: {e}")
            return False, 0.0
            
    def get_anomaly_stats(self) -> Dict:
        """Get anomaly detection statistics"""
        if not self.anomaly_history:
            return {'total_anomalies': 0, 'avg_score': 0}
            
        scores = [a['score'] for a in self.anomaly_history]
        return {
            'total_anomalies': len(self.anomaly_history),
            'avg_score': np.mean(scores),
            'max_score': np.max(scores),
            'recent_rate': len([a for a in self.anomaly_history[-60:]])  # Last minute
        }
        
    def retrain_if_needed(self):
        """Periodic retraining of model"""
        current_time = time.time()
        if (current_time - self.last_training_time > ML_CONFIG['update_interval'] and 
            len(self.training_data) > 100):
            self.train_model(self.training_data)
            self.training_data = []  # Clear training data
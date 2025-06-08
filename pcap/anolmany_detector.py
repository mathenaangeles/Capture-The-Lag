import numpy as np
from collections import defaultdict
from datetime import datetime, timedelta
from sklearn.ensemble import IsolationForest
from sklearn.preprocessing import StandardScaler

class MLAnomalyDetector:
    def __init__(self):
        self.models = {
            'latency': IsolationForest(contamination=0.1, random_state=42),
            'packet_size': IsolationForest(contamination=0.1, random_state=42),
            'order_flow': IsolationForest(contamination=0.15, random_state=42),
            'connection': IsolationForest(contamination=0.1, random_state=42)
        }
        self.scalers = {key: StandardScaler() for key in self.models}
        self.is_trained = False

    def extract_features(self, packet_analyses, trading_stats):
        features = {
            'latency_features': [],
            'packet_size_features': [],
            'order_flow_features': [],
            'connection_features': []
        }
        raw_order_flow = []
        for analysis in packet_analyses:
            packet_info = analysis.get('packet_info', {})
            trading_info = analysis.get('trading_analysis', {})
            latency = trading_info.get('latency_ms')
            timestamp = packet_info.get('timestamp')
            packet_size = packet_info.get('length', 0)
            payload_preview = packet_info.get('payload_preview', '')

            if latency is not None and timestamp is not None:
                time_of_day = timestamp % 86400
                features['latency_features'].append([latency, packet_size, time_of_day])

            features['packet_size_features'].append([
                packet_size,
                1 if trading_info.get('is_trading') else 0,
                len(payload_preview)
            ])

            raw_order_flow.append({
                'timestamp': timestamp,
                'latency': latency,
                'is_order': trading_info.get('is_order', False),
                'is_execution': trading_info.get('is_execution', False),
                'is_rejection': trading_info.get('is_rejection', False),
                'is_cancel': trading_info.get('is_cancel', False),
                'connection_reset': trading_info.get('connection_reset', False)
            })
        time_windows = self._create_time_windows(raw_order_flow, window_size=60)
        features['order_flow_features'] = [
            [
                window['orders_per_minute'],
                window['executions_per_minute'],
                window['rejections_per_minute'],
                window['avg_latency'],
                window['packet_loss_rate']
            ]
            for window in time_windows
        ]

        return features

    def _create_time_windows(self, records, window_size=60):
        if not records:
            return []
        base_time = datetime.utcfromtimestamp(min(r['timestamp'] for r in records))
        windows = defaultdict(lambda: {
            'orders': 0,
            'executions': 0,
            'rejections': 0,
            'latencies': [],
            'resets': 0,
            'total': 0
        })

        for r in records:
            offset = int((r['timestamp'] - base_time.timestamp()) // window_size)
            key_time = base_time + timedelta(seconds=offset * window_size)
            window = windows[key_time]
            window['orders'] += int(r['is_order'])
            window['executions'] += int(r['is_execution'])
            window['rejections'] += int(r['is_rejection'])
            window['resets'] += int(r['connection_reset'])
            if r['latency'] is not None:
                window['latencies'].append(r['latency'])
            window['total'] += 1

        result = []
        for window in sorted(windows):
            data = windows[window]
            total_minutes = 1
            result.append({
                'orders_per_minute': data['orders'] / total_minutes,
                'executions_per_minute': data['executions'] / total_minutes,
                'rejections_per_minute': data['rejections'] / total_minutes,
                'avg_latency': np.mean(data['latencies']) if data['latencies'] else 0,
                'packet_loss_rate': data['resets'] / data['total'] if data['total'] > 0 else 0
            })

        return result

    def train(self, features):
        for feature_type, feature_data in features.items():
            if len(feature_data) > 10:
                X = np.array(feature_data)
                name = feature_type.replace('_features', '')
                X_scaled = self.scalers[name].fit_transform(X)
                self.models[name].fit(X_scaled)
        self.is_trained = True

    def detect_anomalies(self, features):
        if not self.is_trained:
            return {}
        anomalies = {}
        for feature_type, feature_data in features.items():
            if feature_data:
                name = feature_type.replace('_features', '')
                X = np.array(feature_data)
                X_scaled = self.scalers[name].transform(X)
                predictions = self.models[name].predict(X_scaled)
                scores = self.models[name].score_samples(X_scaled)
                anomaly_indices = np.where(predictions == -1)[0]
                anomalies[feature_type] = {
                    'anomaly_count': len(anomaly_indices),
                    'anomaly_indices': anomaly_indices.tolist(),
                    'anomaly_scores': scores[anomaly_indices].tolist(),
                    'total_samples': len(feature_data)
                }
        return anomalies

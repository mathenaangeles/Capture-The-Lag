import re
import yaml
import logging
from typing import Dict, List, Any

class TradingAnalyzer:
    def __init__(self, config_path: str = "config/config.yaml"):
        with open(config_path, 'r') as file:
            self.config = yaml.safe_load(file)
        self.logger = logging.getLogger(__name__)
        self.fix_ports = set(self.config['analysis']['trading']['fix_ports'])
        self.itch_ports = set(self.config['analysis']['trading']['itch_ports'])
        self.latency_threshold = self.config['analysis']['trading']['latency_threshold_ms']
        self.session_data = {
            'orders': [],
            'executions': [],
            'rejections': [],
            'cancellations': [],
            'latencies': [],
            'sequences': {},
            'connections': {}
        }
    
    def is_trading_packet(self, packet_info: Dict[str, Any]) -> bool:
        src_port = packet_info.get('src_port')
        dst_port = packet_info.get('dst_port')
        if src_port in self.fix_ports or dst_port in self.fix_ports:
            return True
        if src_port in self.itch_ports or dst_port in self.itch_ports:
            return True
        payload = packet_info.get('payload_preview', '')
        if self._contains_fix_signature(payload) or self._contains_itch_signature(payload):
            return True
        return False
    
    def analyze_trading_packet(self, packet_info: Dict[str, Any]) -> Dict[str, Any]:
        analysis = {
            'is_trading': self.is_trading_packet(packet_info),
            'protocol': None,
            'message_type': None,
            'trading_data': {},
            'issues': [],
            'latency_impact': False
        }
        if not analysis['is_trading']:
            return analysis
        if self._is_fix_packet(packet_info):
            analysis.update(self._analyze_fix_packet(packet_info))
        elif self._is_itch_packet(packet_info):
            analysis.update(self._analyze_itch_packet(packet_info))
        analysis['issues'] = self._detect_trading_issues(packet_info, analysis)
        return analysis
    
    def _is_fix_packet(self, packet_info: Dict[str, Any]) -> bool:
        src_port = packet_info.get('src_port')
        dst_port = packet_info.get('dst_port')
        payload = packet_info.get('payload_preview', '')
        return (src_port in self.fix_ports or dst_port in self.fix_ports or 
                self._contains_fix_signature(payload))
    
    def _is_itch_packet(self, packet_info: Dict[str, Any]) -> bool:
        src_port = packet_info.get('src_port')
        dst_port = packet_info.get('dst_port')
        payload = packet_info.get('payload_preview', '')
        return (src_port in self.itch_ports or dst_port in self.itch_ports or 
                self._contains_itch_signature(payload))
    
    def _contains_fix_signature(self, payload: str) -> bool:
        if not payload:
            return False
        fix_patterns = [
            r'8=FIX',
            r'35=',
            r'49=',
            r'56=',
        ]
        return any(re.search(pattern, payload) for pattern in fix_patterns)
    
    def _contains_itch_signature(self, payload: str) -> bool:
        """Check for ITCH protocol signatures in payload"""
        if not payload:
            return False
        return len(payload) > 10 and payload.startswith('HEX:')
    
    def _analyze_fix_packet(self, packet_info: Dict[str, Any]) -> Dict[str, Any]:
        payload = packet_info.get('payload_preview', '')
        analysis = {
            'protocol': 'FIX',
            'message_type': None,
            'trading_data': {}
        }
        if not payload:
            return analysis
        try:
            fix_data = self._parse_fix_message(payload)
            analysis['trading_data'] = fix_data
            msg_type = fix_data.get('35')
            analysis['message_type'] = self._get_fix_message_type_name(msg_type)
            self._track_fix_message(packet_info, fix_data)
        except Exception as e:
            self.logger.warning(f"Failed to parse FIX message: {e}")
            analysis['trading_data'] = {'parse_error': str(e)}
        return analysis
    
    def _analyze_itch_packet(self, packet_info: Dict[str, Any]) -> Dict[str, Any]:
        payload = packet_info.get('payload_preview', '')
        analysis = {
            'protocol': 'ITCH',
            'message_type': None,
            'trading_data': {}
        }
        if not payload:
            return analysis
        try:
            itch_data = self._parse_itch_message(payload)
            analysis['trading_data'] = itch_data
            analysis['message_type'] = itch_data.get('message_type', 'Unknown')
            self._track_itch_message(packet_info, itch_data)
        except Exception as e:
            self.logger.warning(f"Failed to parse ITCH message: {e}")
            analysis['trading_data'] = {'parse_error': str(e)}
        return analysis
    
    def _parse_fix_message(self, payload: str) -> Dict[str, str]:
        fix_fields = {}
        if payload.startswith('ASCII:'):
            payload = payload[7:].strip()
        field_separators = ['\x01', '|', '\n']
        for separator in field_separators:
            if separator in payload:
                fields = payload.split(separator)
                break
        else:
            fields = re.findall(r'(\d+=[^|\x01\n]*)', payload)
        for field in fields:
            if '=' in field:
                tag, value = field.split('=', 1)
                fix_fields[tag.strip()] = value.strip()
        return fix_fields
    
    def _parse_itch_message(self, payload: str) -> Dict[str, Any]:
        itch_data = {'message_type': 'Unknown'}
        if payload.startswith('HEX:'):
            hex_data = payload[4:].replace(' ', '')
            try:
                if len(hex_data) >= 2:
                    msg_type_byte = int(hex_data[:2], 16)
                    itch_data['message_type'] = chr(msg_type_byte) if 32 <= msg_type_byte <= 126 else f'0x{msg_type_byte:02X}'
                    itch_data['raw_hex'] = hex_data[:50]  # First 25 bytes
            except ValueError:
                pass
        
        return itch_data
    
    def _get_fix_message_type_name(self, msg_type: str) -> str:
        fix_message_types = {
            'D': 'New Order Single',
            '8': 'Execution Report',
            'G': 'Order Cancel/Replace Request',
            'F': 'Order Cancel Request',
            '9': 'Order Cancel Reject',
            'A': 'Logon',
            '5': 'Logout',
            '0': 'Heartbeat',
            '1': 'Test Request',
            '2': 'Resend Request',
            '4': 'Sequence Reset',
            'j': 'Business Message Reject',
            '3': 'Reject'
        }
        return fix_message_types.get(msg_type, f'Unknown ({msg_type})')
    
    def _track_fix_message(self, packet_info: Dict[str, Any], fix_data: Dict[str, str]):
        msg_type = fix_data.get('35')
        timestamp = packet_info.get('timestamp')
        if msg_type == 'D':
            order_data = {
                'timestamp': timestamp,
                'order_id': fix_data.get('11', 'Unknown'),
                'symbol': fix_data.get('55', 'Unknown'),
                'side': fix_data.get('54', 'Unknown'),
                'quantity': fix_data.get('38', 'Unknown'),
                'price': fix_data.get('44', 'Unknown')
            }
            self.session_data['orders'].append(order_data)
        elif msg_type == '8':
            exec_data = {
                'timestamp': timestamp,
                'order_id': fix_data.get('11', 'Unknown'),
                'exec_type': fix_data.get('150', 'Unknown'),
                'order_status': fix_data.get('39', 'Unknown'),
                'exec_id': fix_data.get('17', 'Unknown')
            }
            self.session_data['executions'].append(exec_data)
            self._calculate_order_latency(exec_data)
        elif msg_type in ['G', 'F']:
            cancel_data = {
                'timestamp': timestamp,
                'order_id': fix_data.get('11', 'Unknown'),
                'orig_order_id': fix_data.get('41', 'Unknown'),
                'type': 'replace' if msg_type == 'G' else 'cancel'
            }
            self.session_data['cancellations'].append(cancel_data)
        elif msg_type == 'j':
            reject_data = {
                'timestamp': timestamp,
                'reason': fix_data.get('380', 'Unknown'),
                'ref_msg_type': fix_data.get('372', 'Unknown'),
                'text': fix_data.get('58', 'Unknown')
            }
            self.session_data['rejections'].append(reject_data)
    
    def _track_itch_message(self, packet_info: Dict[str, Any], itch_data: Dict[str, Any]):
        msg_type = itch_data.get('message_type', 'Unknown')
        timestamp = packet_info.get('timestamp')
        if msg_type in ['A', 'F']:
            self.session_data['orders'].append({
                'timestamp': timestamp,
                'type': 'itch',
                'message_type': msg_type,
                'data': itch_data
            })
    
    def _calculate_order_latency(self, exec_data: Dict[str, Any]):
        order_id = exec_data.get('order_id')
        exec_timestamp = exec_data.get('timestamp')
        if not order_id or not exec_timestamp:
            return
        for order in self.session_data['orders']:
            if order.get('order_id') == order_id:
                order_timestamp = order.get('timestamp')
                if order_timestamp:
                    latency_ms = (exec_timestamp - order_timestamp) * 1000
                    self.session_data['latencies'].append({
                        'order_id': order_id,
                        'latency_ms': latency_ms,
                        'timestamp': exec_timestamp
                    })
                break
    
    def _detect_trading_issues(self, packet_info: Dict[str, Any], analysis: Dict[str, Any]) -> List[str]:
        issues = []
        tcp_flags = packet_info.get('tcp_flags', {})
        if isinstance(tcp_flags, dict):
            if tcp_flags.get('RST'):
                issues.append("TCP connection reset - potential session disruption")
            if tcp_flags.get('FIN'):
                issues.append("Connection termination detected")
        seq_num = packet_info.get('seq_num')
        connection_key = f"{packet_info.get('src_ip')}:{packet_info.get('src_port')}-{packet_info.get('dst_ip')}:{packet_info.get('dst_port')}"
        if seq_num and connection_key:
            if connection_key in self.session_data['sequences']:
                last_seq = self.session_data['sequences'][connection_key]
                if seq_num <= last_seq:
                    issues.append("Possible retransmission or out-of-order packet")
            self.session_data['sequences'][connection_key] = seq_num
        payload_size = packet_info.get('payload_size', 0)
        if payload_size == 0 and analysis.get('protocol') in ['FIX', 'ITCH']:
            issues.append("Empty payload in trading message")
        elif payload_size > 8192:
            issues.append("Unusually large trading message - potential fragmentation")
        if analysis.get('protocol') == 'FIX':
            trading_data = analysis.get('trading_data', {})
            if 'parse_error' in trading_data:
                issues.append("FIX message parsing failed - malformed message")
            msg_type = analysis.get('message_type')
            if 'Reject' in str(msg_type):
                issues.append("Order rejection detected")
        return issues
    
    def get_session_statistics(self) -> Dict[str, Any]:
        stats = {
            'total_orders': len(self.session_data['orders']),
            'total_executions': len(self.session_data['executions']),
            'total_rejections': len(self.session_data['rejections']),
            'total_cancellations': len(self.session_data['cancellations']),
            'latency_stats': self._calculate_latency_statistics(),
            'rejection_analysis': self._analyze_rejections(),
            'connection_health': self._analyze_connection_health()
        }
        return stats
    
    def _calculate_latency_statistics(self) -> Dict[str, Any]:
        latencies = [l['latency_ms'] for l in self.session_data['latencies']]
        if not latencies:
            return {'count': 0, 'message': 'No latency data available'}
        latencies.sort()
        count = len(latencies)
        stats = {
            'count': count,
            'min_ms': min(latencies),
            'max_ms': max(latencies),
            'avg_ms': sum(latencies) / count,
            'median_ms': latencies[count // 2],
            'p95_ms': latencies[int(count * 0.95)] if count > 20 else latencies[-1],
            'p99_ms': latencies[int(count * 0.99)] if count > 100 else latencies[-1],
            'high_latency_count': sum(1 for l in latencies if l > self.latency_threshold)
        }
        return stats
    
    def _analyze_rejections(self) -> Dict[str, Any]:
        rejections = self.session_data['rejections']
        if not rejections:
            return {'count': 0, 'message': 'No rejections detected'}
        rejection_reasons = {}
        for rejection in rejections:
            reason = rejection.get('reason', 'Unknown')
            rejection_reasons[reason] = rejection_reasons.get(reason, 0) + 1
        return {
            'count': len(rejections),
            'reasons': rejection_reasons,
            'rejection_rate': len(rejections) / max(len(self.session_data['orders']), 1) * 100
        }
    
    def _analyze_connection_health(self) -> Dict[str, Any]:
        connections = {}
        return {
            'active_connections': len(connections),
            'connection_resets': 0,
            'timeouts': 0,
            'health_score': 100
        }
    
    def reset_session_data(self):
        self.session_data = {
            'orders': [],
            'executions': [],
            'rejections': [],
            'cancellations': [],
            'latencies': [],
            'sequences': {},
            'connections': {}
        }
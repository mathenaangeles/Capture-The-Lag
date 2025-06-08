import re
import yaml
import logging
from typing import Dict, List, Any

class TradingAnalyzer:
    def __init__(self, config_path: str = "config/config.yaml"):
        try:
            with open(config_path, 'r') as file:
                self.config = yaml.safe_load(file)
        except FileNotFoundError:
            self.config = {
                'analysis': {
                    'trading': {
                        'fix_ports': [8080, 8081, 9881, 9882],
                        'itch_ports': [26400, 26401, 26402],
                        'latency_threshold_ms': 10
                    }
                }
            }
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
            'connections': {},
            'connection_issues': {
                'resets': 0,
                'fins': 0,
                'retransmissions': 0,
                'malformed_packets': 0,
                'timeouts': 0
            }
        }
        self.order_tracker = {}
    
    def is_trading_packet(self, packet_info: Dict[str, Any]) -> bool:
        src_port = packet_info.get('src_port')
        dst_port = packet_info.get('dst_port')
        if src_port in self.fix_ports or dst_port in self.fix_ports:
            return True
        if src_port in self.itch_ports or dst_port in self.itch_ports:
            return True
        payload = packet_info.get('payload', '')
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
        self._track_connection(packet_info)
        if self._is_fix_packet(packet_info):
            analysis.update(self._analyze_fix_packet(packet_info))
        elif self._is_itch_packet(packet_info):
            analysis.update(self._analyze_itch_packet(packet_info))
        analysis['issues'] = self._detect_trading_issues(packet_info, analysis)
        return analysis
    
    def _track_connection(self, packet_info: Dict[str, Any]):
        connection_key = f"{packet_info.get('src_ip')}:{packet_info.get('src_port')}-{packet_info.get('dst_ip')}:{packet_info.get('dst_port')}"
        timestamp = packet_info.get('timestamp', 0)
        
        if connection_key not in self.session_data['connections']:
            self.session_data['connections'][connection_key] = {
                'first_seen': timestamp,
                'last_seen': timestamp,
                'packet_count': 0,
                'bytes_transferred': 0,
                'tcp_flags_seen': set(),
                'active': True
            }
        conn = self.session_data['connections'][connection_key]
        conn['last_seen'] = timestamp
        conn['packet_count'] += 1
        conn['bytes_transferred'] += packet_info.get('payload_size', 0)

        tcp_flags = packet_info.get('tcp_flags', {})
        if isinstance(tcp_flags, dict):
            for flag, is_set in tcp_flags.items():
                if is_set:
                    conn['tcp_flags_seen'].add(flag)
            if tcp_flags.get('FIN') or tcp_flags.get('RST'):
                conn['active'] = False
    
    def _is_fix_packet(self, packet_info: Dict[str, Any]) -> bool:
        src_port = packet_info.get('src_port')
        dst_port = packet_info.get('dst_port')
        payload = packet_info.get('payload', '')
        return (src_port in self.fix_ports or dst_port in self.fix_ports or 
                self._contains_fix_signature(payload))
    
    def _is_itch_packet(self, packet_info: Dict[str, Any]) -> bool:
        src_port = packet_info.get('src_port')
        dst_port = packet_info.get('dst_port')
        payload = packet_info.get('payload', '')
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
        if not payload:
            return False
        return (len(payload) > 10 and 
                (payload.startswith('HEX:') or 
                 any(payload.startswith(c) for c in 'AFDEUCXPQBILNORHSKMWY')))
    
    def _analyze_fix_packet(self, packet_info: Dict[str, Any]) -> Dict[str, Any]:
        payload = packet_info.get('payload', '')
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
            self.session_data['connection_issues']['malformed_packets'] += 1
        return analysis
    
    def _analyze_itch_packet(self, packet_info: Dict[str, Any]) -> Dict[str, Any]:
        payload = packet_info.get('payload', '')
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
            self.session_data['connection_issues']['malformed_packets'] += 1
        return analysis
    
    def _parse_fix_message(self, payload: str) -> Dict[str, str]:
        fix_fields = {}
        if payload.startswith('ASCII:'):
            payload = payload[7:].strip()
        elif payload.startswith('HEX:'):
            try:
                hex_data = payload[4:].replace(' ', '')
                payload = bytes.fromhex(hex_data).decode('ascii', errors='ignore')
            except:
                pass
        field_separators = ['\x01', '|', '\n', ';']
        fields = []
        for separator in field_separators:
            if separator in payload:
                fields = payload.split(separator)
                break
        if not fields:
            fields = re.findall(r'(\d+=[^|\x01\n;]*)', payload)
        for field in fields:
            field = field.strip()
            if '=' in field:
                try:
                    tag, value = field.split('=', 1)
                    fix_fields[tag.strip()] = value.strip()
                except:
                    continue
        return fix_fields
    
    def _parse_itch_message(self, payload: str) -> Dict[str, Any]:
        itch_data = {'message_type': 'Unknown'}
        if payload.startswith('HEX:'):
            hex_data = payload[4:].replace(' ', '')
            try:
                if len(hex_data) >= 2:
                    msg_type_byte = int(hex_data[:2], 16)
                    itch_data['message_type'] = chr(msg_type_byte) if 32 <= msg_type_byte <= 126 else f'0x{msg_type_byte:02X}'
                    itch_data['raw_hex'] = hex_data[:50]
                    if len(hex_data) >= 16:
                        itch_data['stock_locate'] = int(hex_data[2:6], 16) if len(hex_data) >= 6 else 0
                        itch_data['tracking_number'] = int(hex_data[6:10], 16) if len(hex_data) >= 10 else 0
                        itch_data['timestamp'] = int(hex_data[10:22], 16) if len(hex_data) >= 22 else 0
                        msg_type = itch_data['message_type']
                        if msg_type in ['A', 'F'] and len(hex_data) >= 30:
                            itch_data['order_reference'] = int(hex_data[22:34], 16) if len(hex_data) >= 34 else 0
                        elif msg_type in ['E', 'C'] and len(hex_data) >= 26:
                            itch_data['order_reference'] = int(hex_data[22:30], 16) if len(hex_data) >= 30 else 0
                            if len(hex_data) >= 38:
                                itch_data['executed_shares'] = int(hex_data[30:38], 16) if len(hex_data) >= 38 else 0       
            except ValueError as e:
                itch_data['parse_error'] = str(e)
        else:
            if len(payload) > 0:
                itch_data['message_type'] = payload[0]
                itch_data['raw_data'] = payload[:50]
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
        timestamp = packet_info.get('timestamp', 0)
        
        if msg_type == 'D':
            order_id = fix_data.get('11', f'Unknown_{timestamp}')
            order_data = {
                'timestamp': timestamp,
                'order_id': order_id,
                'symbol': fix_data.get('55', 'Unknown'),
                'side': 'Buy' if fix_data.get('54') == '1' else 'Sell' if fix_data.get('54') == '2' else fix_data.get('54', 'Unknown'),
                'quantity': fix_data.get('38', 'Unknown'),
                'price': fix_data.get('44', 'Unknown'),
                'order_type': fix_data.get('40', 'Unknown'),
                'time_in_force': fix_data.get('59', 'Unknown'),
                'connection': f"{packet_info.get('src_ip')}:{packet_info.get('src_port')}",
                'protocol': 'FIX'
            }
            self.session_data['orders'].append(order_data)
            self.order_tracker[order_id] = {
                'timestamp': timestamp,
                'data': order_data
            }
            
        elif msg_type == '8':
            order_id = fix_data.get('11', 'Unknown')
            exec_data = {
                'timestamp': timestamp,
                'order_id': order_id,
                'exec_type': fix_data.get('150', 'Unknown'),
                'order_status': fix_data.get('39', 'Unknown'),
                'exec_id': fix_data.get('17', 'Unknown'),
                'symbol': fix_data.get('55', 'Unknown'),
                'exec_qty': fix_data.get('32', '0'),
                'exec_price': fix_data.get('31', '0'),
                'leaves_qty': fix_data.get('151', '0'),
                'cum_qty': fix_data.get('14', '0'),
                'connection': f"{packet_info.get('src_ip')}:{packet_info.get('src_port')}",
                'protocol': 'FIX'
            }
            self.session_data['executions'].append(exec_data)
            self._calculate_order_latency(exec_data)
            
        elif msg_type in ['G', 'F']:
            cancel_data = {
                'timestamp': timestamp,
                'order_id': fix_data.get('11', 'Unknown'),
                'orig_order_id': fix_data.get('41', 'Unknown'),
                'type': 'replace' if msg_type == 'G' else 'cancel',
                'symbol': fix_data.get('55', 'Unknown'),
                'connection': f"{packet_info.get('src_ip')}:{packet_info.get('src_port')}",
                'protocol': 'FIX'
            }
            self.session_data['cancellations'].append(cancel_data)
            
        elif msg_type == 'j':
            reject_data = {
                'timestamp': timestamp,
                'reason': fix_data.get('380', 'Unknown'),
                'ref_msg_type': fix_data.get('372', 'Unknown'),
                'text': fix_data.get('58', 'Unknown'),
                'ref_seq_num': fix_data.get('45', 'Unknown'),
                'connection': f"{packet_info.get('src_ip')}:{packet_info.get('src_port')}",
                'protocol': 'FIX'
            }
            self.session_data['rejections'].append(reject_data)
    
    def _track_itch_message(self, packet_info: Dict[str, Any], itch_data: Dict[str, Any]):
        msg_type = itch_data.get('message_type', 'Unknown')
        timestamp = packet_info.get('timestamp', 0)
        if msg_type in ['A', 'F']:
            order_ref = itch_data.get('order_reference', f'ITCH_{timestamp}')
            order_data = {
                'timestamp': timestamp,
                'order_id': str(order_ref),
                'type': 'itch',
                'message_type': msg_type,
                'stock_locate': itch_data.get('stock_locate', 0),
                'tracking_number': itch_data.get('tracking_number', 0),
                'order_reference': order_ref,
                'connection': f"{packet_info.get('src_ip')}:{packet_info.get('src_port')}",
                'protocol': 'ITCH'
            }
            self.session_data['orders'].append(order_data)
            self.order_tracker[str(order_ref)] = {
                'timestamp': timestamp,
                'data': order_data
            }
        elif msg_type in ['E', 'C']:
            order_ref = itch_data.get('order_reference', 'Unknown')
            exec_data = {
                'timestamp': timestamp,
                'order_id': str(order_ref),
                'type': 'itch',
                'message_type': msg_type,
                'order_reference': order_ref,
                'executed_shares': itch_data.get('executed_shares', 0),
                'execution_price': itch_data.get('execution_price', 0),
                'connection': f"{packet_info.get('src_ip')}:{packet_info.get('src_port')}",
                'protocol': 'ITCH'
            }
            self.session_data['executions'].append(exec_data)
            self._calculate_order_latency(exec_data)
    
    def _calculate_order_latency(self, exec_data: Dict[str, Any]):
        order_id = exec_data.get('order_id')
        exec_timestamp = exec_data.get('timestamp')
        if not order_id or not exec_timestamp:
            return
        if order_id in self.order_tracker:
            order_info = self.order_tracker[order_id]
            order_timestamp = order_info['timestamp']
            if exec_timestamp > order_timestamp:
                latency_ms = (exec_timestamp - order_timestamp) * 1000
                self.session_data['latencies'].append({
                    'order_id': order_id,
                    'latency_ms': latency_ms,
                    'timestamp': exec_timestamp,
                    'order_timestamp': order_timestamp,
                    'exec_timestamp': exec_timestamp,
                    'protocol': exec_data.get('protocol', 'Unknown')
                })
            return
        for order in self.session_data['orders']:
            if order.get('order_id') == order_id:
                order_timestamp = order.get('timestamp')
                if order_timestamp and exec_timestamp > order_timestamp:
                    latency_ms = (exec_timestamp - order_timestamp) * 1000
                    self.session_data['latencies'].append({
                        'order_id': order_id,
                        'latency_ms': latency_ms,
                        'timestamp': exec_timestamp,
                        'order_timestamp': order_timestamp,
                        'exec_timestamp': exec_timestamp,
                        'protocol': exec_data.get('protocol', 'Unknown')
                    })
                break
    
    def _detect_trading_issues(self, packet_info: Dict[str, Any], analysis: Dict[str, Any]) -> List[str]:
        issues = []
        tcp_flags = packet_info.get('tcp_flags', {})
        if isinstance(tcp_flags, dict):
            if tcp_flags.get('RST'):
                issues.append("TCP connection reset - potential session disruption")
                self.session_data['connection_issues']['resets'] += 1
            if tcp_flags.get('FIN'):
                issues.append("Connection termination detected")
                self.session_data['connection_issues']['fins'] += 1
        seq_num = packet_info.get('seq_num')
        connection_key = f"{packet_info.get('src_ip')}:{packet_info.get('src_port')}-{packet_info.get('dst_ip')}:{packet_info.get('dst_port')}"
        if seq_num and connection_key:
            if connection_key in self.session_data['sequences']:
                last_seq = self.session_data['sequences'][connection_key]
                if seq_num <= last_seq:
                    issues.append("Possible retransmission or out-of-order packet")
                    self.session_data['connection_issues']['retransmissions'] += 1
            self.session_data['sequences'][connection_key] = seq_num
        payload_size = packet_info.get('payload_size', 0)
        if payload_size == 0 and analysis.get('protocol') in ['FIX', 'ITCH']:
            issues.append("Empty payload in trading message")
            self.session_data['connection_issues']['malformed_packets'] += 1
        elif payload_size > 8192:
            issues.append("Unusually large trading message - potential fragmentation")
        if analysis.get('protocol') == 'FIX':
            trading_data = analysis.get('trading_data', {})
            if 'parse_error' in trading_data:
                issues.append("FIX message parsing failed - malformed message")
            msg_type = analysis.get('message_type')
            if 'Reject' in str(msg_type):
                issues.append("Order rejection detected")
        timestamp = packet_info.get('timestamp', 0)
        if hasattr(self, '_last_packet_time'):
            time_gap = timestamp - self._last_packet_time
            if time_gap > 30:
                issues.append("Large time gap detected - possible timeout")
                self.session_data['connection_issues']['timeouts'] += 1
        self._last_packet_time = timestamp
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
        total_orders = len(self.session_data['orders'])
        rejection_rate = len(rejections) / max(total_orders, 1) * 100
        
        return {
            'count': len(rejections),
            'reasons': rejection_reasons,
            'rejection_rate': rejection_rate,
            'most_common_reason': max(rejection_reasons.items(), key=lambda x: x[1])[0] if rejection_reasons else 'None'
        }
    
    def _analyze_connection_health(self) -> Dict[str, Any]:
        issues = self.session_data['connection_issues']
        connections = self.session_data['connections']
        total_packets = sum(conn['packet_count'] for conn in connections.values())
        active_connections = sum(1 for conn in connections.values() if conn['active'])
        if total_packets == 0:
            return {
                'active_connections': 0,
                'connection_resets': 0,
                'timeouts': 0,
                'retransmissions': 0,
                'health_score': 100,
                'message': 'No trading activity to analyze'
            }
        reset_rate = issues['resets'] / total_packets if total_packets > 0 else 0
        retransmission_rate = issues['retransmissions'] / total_packets if total_packets > 0 else 0
        malformed_rate = issues['malformed_packets'] / total_packets if total_packets > 0 else 0
        rejection_rate = len(self.session_data['rejections']) / max(len(self.session_data['orders']), 1)
        latency_stats = self._calculate_latency_statistics()
        high_latency_rate = 0
        if latency_stats.get('count', 0) > 0:
            high_latency_rate = latency_stats.get('high_latency_count', 0) / latency_stats['count']
        health_score = 100.0
        health_score -= min(rejection_rate * 40, 25)          # Max 25 points for rejections
        health_score -= min(high_latency_rate * 30, 20)       # Max 20 points for high latency
        health_score -= min(reset_rate * 1000, 20)            # Max 20 points for resets
        health_score -= min(retransmission_rate * 500, 15)    # Max 15 points for retransmissions
        health_score -= min(malformed_rate * 200, 10)         # Max 10 points for malformed packets
        health_score -= min(issues['timeouts'] * 5, 10)       # Max 10 points for timeouts
        health_score = max(0, min(100, health_score))
        return {
            'active_connections': active_connections,
            'total_connections': len(connections),
            'connection_resets': issues['resets'],
            'timeouts': issues['timeouts'],
            'retransmissions': issues['retransmissions'],
            'malformed_packets': issues['malformed_packets'],
            'rejection_rate': rejection_rate * 100,
            'high_latency_rate': high_latency_rate * 100,
            'reset_rate': reset_rate * 100,
            'retransmission_rate': retransmission_rate * 100,
            'health_score': round(health_score, 1)
        }
    
    def reset_session_data(self):
        self.session_data = {
            'orders': [],
            'executions': [],
            'rejections': [],
            'cancellations': [],
            'latencies': [],
            'sequences': {},
            'connections': {},
            'connection_issues': {
                'resets': 0,
                'fins': 0,
                'retransmissions': 0,
                'malformed_packets': 0,
                'timeouts': 0
            }
        }
        self.order_tracker = {}
        if hasattr(self, '_last_packet_time'):
            delattr(self, '_last_packet_time')

    def debug_session_state(self) -> Dict[str, Any]:
        """Debug method to inspect current session state"""
        return {
            'orders_count': len(self.session_data['orders']),
            'executions_count': len(self.session_data['executions']),
            'latencies_count': len(self.session_data['latencies']),
            'order_tracker_count': len(self.order_tracker),
            'sample_order': self.session_data['orders'][:1] if self.session_data['orders'] else None,
            'sample_execution': self.session_data['executions'][:1] if self.session_data['executions'] else None,
            'sample_latency': self.session_data['latencies'][:1] if self.session_data['latencies'] else None,
        }
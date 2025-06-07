import os
import yaml
import logging
from datetime import datetime
from scapy.packet import Packet
from typing import List, Dict, Any, Generator
from scapy.all import rdpcap, IP, TCP, UDP, Raw

try:
    import pyshark
    PYSHARK_AVAILABLE = True
except ImportError:
    PYSHARK_AVAILABLE = False
    logging.warning("PyShark is not available. Large file processing will be limited.")

class PacketReader:
    def __init__(self, config_path: str = "config/config.yaml"):
        with open(config_path, 'r') as file:
            self.config = yaml.safe_load(file)
        self.logger = logging.getLogger(__name__)
        self.max_packets_small = self.config['analysis']['max_packets_small']
        self.max_payload_display = self.config['analysis']['max_payload_display']
        self.batch_size = self.config['analysis']['batch_size']
    
    def read_pcap_file(self, file_path: str, use_pyshark: bool = False) -> Generator[Dict[str, Any], None, None]:
        if not os.path.exists(file_path):
            raise FileNotFoundError(f"PCAP file not found: {file_path}")
        file_size = os.path.getsize(file_path)
        self.logger.info(f"Reading PCAP file: {file_path} ({file_size} bytes)")
        if use_pyshark and PYSHARK_AVAILABLE:
            yield from self._read_with_pyshark(file_path)
        else:
            yield from self._read_with_scapy(file_path)
    
    def _read_with_scapy(self, file_path: str) -> Generator[Dict[str, Any], None, None]:
        try:
            packets = rdpcap(file_path)
            self.logger.info(f"Loaded {len(packets)} packets with Scapy")
            
            for i, packet in enumerate(packets):
                if i >= self.max_packets_small:
                    self.logger.warning(f"Limiting to {self.max_packets_small} packets for Scapy analysis")
                    break
                
                packet_info = self._extract_scapy_packet_info(packet, i)
                yield packet_info
        except Exception as e:
            self.logger.error(f"Error reading with Scapy: {e}")
            raise
    
    def _read_with_pyshark(self, file_path: str) -> Generator[Dict[str, Any], None, None]:
        if not PYSHARK_AVAILABLE:
            raise ImportError("PyShark is not available.")
        try:
            cap = pyshark.FileCapture(file_path)
            packet_count = 0
            
            for packet in cap:
                packet_info = self._extract_pyshark_packet_info(packet, packet_count)
                yield packet_info
                packet_count += 1
                
                if packet_count % 1000 == 0:
                    self.logger.info(f"Processed {packet_count} packets...")
            
            cap.close()
            self.logger.info(f"Completed processing {packet_count} packets with PyShark")
            
        except Exception as e:
            self.logger.error(f"Error reading with PyShark: {e}")
            raise
    
    def _extract_scapy_packet_info(self, packet: Packet, index: int) -> Dict[str, Any]:
        packet_info = {
            'index': index,
            'timestamp': float(packet.time) if hasattr(packet, 'time') else None,
            'length': len(packet),
            'protocol': self._get_protocol_name(packet),
            'src_ip': None,
            'dst_ip': None,
            'src_port': None,
            'dst_port': None,
            'tcp_flags': None,
            'seq_num': None,
            'ack_num': None,
            'payload_size': 0,
            'payload_preview': None,
            'raw_packet': packet
        }
        if IP in packet:
            packet_info['src_ip'] = packet[IP].src
            packet_info['dst_ip'] = packet[IP].dst
            packet_info['ip_id'] = packet[IP].id
            packet_info['ip_flags'] = packet[IP].flags
            packet_info['ttl'] = packet[IP].ttl
        if TCP in packet:
            packet_info['src_port'] = packet[TCP].sport
            packet_info['dst_port'] = packet[TCP].dport
            packet_info['tcp_flags'] = self._parse_tcp_flags(packet[TCP].flags)
            packet_info['seq_num'] = packet[TCP].seq
            packet_info['ack_num'] = packet[TCP].ack
            packet_info['window_size'] = packet[TCP].window
        if UDP in packet:
            packet_info['src_port'] = packet[UDP].sport
            packet_info['dst_port'] = packet[UDP].dport
        if Raw in packet:
            payload = bytes(packet[Raw])
            packet_info['payload_size'] = len(payload)
            packet_info['payload_preview'] = self._format_payload_preview(payload)
        
        return packet_info
    
    def _extract_pyshark_packet_info(self, packet, index: int) -> Dict[str, Any]:
        packet_info = {
            'index': index,
            'timestamp': float(packet.sniff_timestamp) if hasattr(packet, 'sniff_timestamp') else None,
            'length': int(packet.length),
            'protocol': packet.highest_layer,
            'src_ip': None,
            'dst_ip': None,
            'src_port': None,
            'dst_port': None,
            'tcp_flags': None,
            'seq_num': None,
            'ack_num': None,
            'payload_size': 0,
            'payload_preview': None,
            'raw_packet': packet
        }
        
        if hasattr(packet, 'ip'):
            packet_info['src_ip'] = packet.ip.src
            packet_info['dst_ip'] = packet.ip.dst
            if hasattr(packet.ip, 'id'):
                packet_info['ip_id'] = packet.ip.id
            if hasattr(packet.ip, 'ttl'):
                packet_info['ttl'] = packet.ip.ttl
        
        if hasattr(packet, 'tcp'):
            packet_info['src_port'] = int(packet.tcp.srcport)
            packet_info['dst_port'] = int(packet.tcp.dstport)
            if hasattr(packet.tcp, 'flags'):
                packet_info['tcp_flags'] = packet.tcp.flags
            if hasattr(packet.tcp, 'seq'):
                packet_info['seq_num'] = int(packet.tcp.seq)
            if hasattr(packet.tcp, 'ack'):
                packet_info['ack_num'] = int(packet.tcp.ack)
            if hasattr(packet.tcp, 'window_size_value'):
                packet_info['window_size'] = int(packet.tcp.window_size_value)
        
        if hasattr(packet, 'udp'):
            packet_info['src_port'] = int(packet.udp.srcport)
            packet_info['dst_port'] = int(packet.udp.dstport)
        
        try:
            if hasattr(packet, 'data') and hasattr(packet.data, 'data'):
                payload_hex = packet.data.data.replace(':', '')
                payload = bytes.fromhex(payload_hex)
                packet_info['payload_size'] = len(payload)
                packet_info['payload_preview'] = self._format_payload_preview(payload)
        except:
            pass 
        return packet_info
    
    def _get_protocol_name(self, packet: Packet) -> str:
        """Get protocol name from Scapy packet"""
        if TCP in packet:
            return "TCP"
        elif UDP in packet:
            return "UDP"
        elif IP in packet:
            return "IP"
        else:
            return packet.__class__.__name__
    
    def _parse_tcp_flags(self, flags: int) -> Dict[str, bool]:
        return {
            'FIN': bool(flags & 0x01),
            'SYN': bool(flags & 0x02),
            'RST': bool(flags & 0x04),
            'PSH': bool(flags & 0x08),
            'ACK': bool(flags & 0x10),
            'URG': bool(flags & 0x20),
            'ECE': bool(flags & 0x40),
            'CWR': bool(flags & 0x80)
        }
    
    def _format_payload_preview(self, payload: bytes) -> str:
        if not payload:
            return "No payload"
        preview_payload = payload[:self.max_payload_display]
        try:
            ascii_text = preview_payload.decode('ascii', errors='ignore')
            if ascii_text and ascii_text.isprintable():
                return f"ASCII: {ascii_text[:100]}..."
        except:
            pass
        hex_preview = preview_payload.hex()
        return f"HEX: {hex_preview[:200]}..."
    
    def get_file_statistics(self, file_path: str) -> Dict[str, Any]:
        try:
            file_size = os.path.getsize(file_path)
            if file_size < 50 * 1024 * 1024:
                packets = rdpcap(file_path)
                packet_count = len(packets)
                first_timestamp = float(packets[0].time) if packets else None
                last_timestamp = float(packets[-1].time) if packets else None
            else:
                if PYSHARK_AVAILABLE:
                    cap = pyshark.FileCapture(file_path)
                    packet_count = 0
                    first_timestamp = None
                    last_timestamp = None
                    for packet in cap:
                        packet_count += 1
                        if packet_count == 1:
                            first_timestamp = float(packet.sniff_timestamp)
                        last_timestamp = float(packet.sniff_timestamp)
                        if packet_count >= 10000:
                            packet_count = f"{packet_count}+"
                            break
                    cap.close()
                else:
                    return {"error": "The file too large and PyShark not available."}
            duration = (last_timestamp - first_timestamp) if (first_timestamp and last_timestamp) else 0
            return {
                'file_size': file_size,
                'packet_count': packet_count,
                'duration_seconds': duration,
                'first_timestamp': datetime.fromtimestamp(first_timestamp) if first_timestamp else None,
                'last_timestamp': datetime.fromtimestamp(last_timestamp) if last_timestamp else None,
                'packets_per_second': packet_count / duration if duration > 0 else 0
            }
        except Exception as e:
            self.logger.error(f"Error getting file statistics: {e}")
            return {"error": str(e)}
    
    def find_pcap_files(self, directory: str) -> List[str]:
        pcap_files = []
        supported_extensions = self.config['files']['supported_extensions']
        if not os.path.exists(directory):
            self.logger.warning(f"Directory not found: {directory}")
            return pcap_files
        for root, dirs, files in os.walk(directory):
            for file in files:
                if any(file.lower().endswith(ext) for ext in supported_extensions):
                    pcap_files.append(os.path.join(root, file))
        self.logger.info(f"Found {len(pcap_files)} PCAP files in {directory}...")
        return pcap_files
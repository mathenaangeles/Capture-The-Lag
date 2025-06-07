
import os
import json
import yaml
from datetime import datetime
from tabulate import tabulate
from typing import Dict, List, Any

class ReportGenerator:
    def __init__(self, config_path: str = "config/config.yaml"):
        with open(config_path, 'r') as file:
            self.config = yaml.safe_load(file)
        self.output_format = self.config['report']['output_format']
        self.output_directory = self.config['files']['output_directory']
        self.include_packet_details = self.config['report']['include_packet_details']
        self.max_packets_in_report = self.config['report']['max_packets_in_report']
        os.makedirs(self.output_directory, exist_ok=True)

    def generate_comprehensive_report(self, 
                                    file_path: str,
                                    packet_analyses: List[Dict[str, Any]],
                                    trading_stats: Dict[str, Any],
                                    file_stats: Dict[str, Any]) -> str:
        """Generate comprehensive analysis report"""
        report_data = {
            'metadata': {
                'file_path': file_path,
                'analysis_timestamp': datetime.now().isoformat(),
                'total_packets_analyzed': len(packet_analyses),
                'file_statistics': file_stats
            },
            'executive_summary': self._generate_executive_summary(packet_analyses, trading_stats),
            'trading_analysis': trading_stats,
            'network_analysis': self._generate_network_analysis(packet_analyses),
            'packet_details': packet_analyses[:self.max_packets_in_report] if self.include_packet_details else [],
            'recommendations': self._generate_recommendations(packet_analyses, trading_stats)
        }
        if self.output_format == 'html':
            return self._generate_html_report(report_data)
        elif self.output_format == 'json':
            return self._generate_json_report(report_data)
        else:
            return self._generate_markdown_report(report_data)
    
    def _generate_executive_summary(self, 
                                  packet_analyses: List[Dict[str, Any]], 
                                  trading_stats: Dict[str, Any]) -> Dict[str, Any]:        
        total_packets = len(packet_analyses)
        trading_packets = sum(1 for p in packet_analyses if p.get('trading_analysis', {}).get('is_trading', False))
        total_issues = 0
        critical_issues = 0
        protocols = {}
        for packet in packet_analyses:
            issues = packet.get('llm_analysis', {}).get('issues', [])
            if isinstance(issues, list):
                total_issues += len(issues)
                critical_issues += sum(1 for issue in issues if any(word in str(issue).lower() 
                                     for word in ['reject', 'reset', 'timeout', 'fail']))
            protocol = packet.get('packet_info', {}).get('protocol', 'Unknown')
            protocols[protocol] = protocols.get(protocol, 0) + 1
        return {
            'total_packets': total_packets,
            'trading_packets': trading_packets,
            'trading_percentage': (trading_packets / total_packets * 100) if total_packets > 0 else 0,
            'total_issues': total_issues,
            'critical_issues': critical_issues,
            'protocol_distribution': protocols,
            'health_score': self._calculate_health_score(packet_analyses, trading_stats)
        }
    
    def _calculate_health_score(self, packet_analyses: List[Dict[str, Any]], trading_stats: Dict[str, Any]) -> int:
        score = 100
        total_packets = len(packet_analyses)
        if total_packets > 0:
            issue_count = sum(len(p.get('llm_analysis', {}).get('issues', [])) for p in packet_analyses)
            issue_ratio = issue_count / total_packets
            score -= min(50, issue_ratio * 100)
        latency_stats = trading_stats.get('latency_stats', {})
        if isinstance(latency_stats, dict) and 'avg_ms' in latency_stats:
            avg_latency = latency_stats['avg_ms']
            if avg_latency > 10:
                score -= min(20, (avg_latency - 10) * 2)
        rejection_stats = trading_stats.get('rejection_analysis', {})
        if isinstance(rejection_stats, dict) and 'rejection_rate' in rejection_stats:
            rejection_rate = rejection_stats['rejection_rate']
            if rejection_rate > 1:
                score -= min(20, rejection_rate * 5)
        return max(0, int(score))
    
    def _generate_network_analysis(self, packet_analyses: List[Dict[str, Any]]) -> Dict[str, Any]:
        tcp_analysis = {'total': 0, 'syn': 0, 'fin': 0, 'rst': 0, 'retrans': 0}
        ip_pairs = {}
        port_usage = {}
        payload_sizes = []
        for packet in packet_analyses:
            packet_info = packet.get('packet_info', {})
            if packet_info.get('protocol') == 'TCP':
                tcp_analysis['total'] += 1
                tcp_flags = packet_info.get('tcp_flags', {})
                if isinstance(tcp_flags, dict):
                    if tcp_flags.get('SYN'): tcp_analysis['syn'] += 1
                    if tcp_flags.get('FIN'): tcp_analysis['fin'] += 1
                    if tcp_flags.get('RST'): tcp_analysis['rst'] += 1
            src_ip = packet_info.get('src_ip')
            dst_ip = packet_info.get('dst_ip')
            if src_ip and dst_ip:
                pair = f"{src_ip} -> {dst_ip}"
                ip_pairs[pair] = ip_pairs.get(pair, 0) + 1
            src_port = packet_info.get('src_port')
            dst_port = packet_info.get('dst_port')
            if src_port: port_usage[src_port] = port_usage.get(src_port, 0) + 1
            if dst_port: port_usage[dst_port] = port_usage.get(dst_port, 0) + 1
            payload_size = packet_info.get('payload_size', 0)
            if payload_size > 0:
                payload_sizes.append(payload_size)
        payload_stats = {}
        if payload_sizes:
            payload_sizes.sort()
            payload_stats = {
                'min': min(payload_sizes),
                'max': max(payload_sizes),
                'avg': sum(payload_sizes) / len(payload_sizes),
                'median': payload_sizes[len(payload_sizes) // 2]
            }
        return {
            'tcp_analysis': tcp_analysis,
            'top_ip_pairs': dict(sorted(ip_pairs.items(), key=lambda x: x[1], reverse=True)[:10]),
            'top_ports': dict(sorted(port_usage.items(), key=lambda x: x[1], reverse=True)[:10]),
            'payload_statistics': payload_stats
        }
    
    def _generate_recommendations(self, 
                                packet_analyses: List[Dict[str, Any]], 
                                trading_stats: Dict[str, Any]) -> List[Dict[str, str]]:
        recommendations = []
        issue_counts = {}
        for packet in packet_analyses:
            issues = packet.get('llm_analysis', {}).get('issues', [])
            if isinstance(issues, list):
                for issue in issues:
                    issue_str = str(issue).lower()
                    issue_counts[issue_str] = issue_counts.get(issue_str, 0) + 1
        if any('retransmission' in issue for issue in issue_counts):
            recommendations.append({
                'category': 'Network Performance',
                'priority': 'High',
                'issue': 'TCP retransmissions detected',
                'recommendation': 'Investigate network connectivity and buffer sizes. Consider increasing TCP window size.',
                'action': 'Monitor network latency and packet loss between trading endpoints.'
            })
        if any('reset' in issue for issue in issue_counts):
            recommendations.append({
                'category': 'Connection Stability',
                'priority': 'Critical',
                'issue': 'Connection resets detected',
                'recommendation': 'Review connection handling and implement proper reconnection logic.',
                'action': 'Implement heartbeat mechanisms and connection monitoring.'
            })
        latency_stats = trading_stats.get('latency_stats', {})
        if isinstance(latency_stats, dict) and latency_stats.get('avg_ms', 0) > 5:
            recommendations.append({
                'category': 'Trading Performance',
                'priority': 'Medium',
                'issue': f"Average latency {latency_stats['avg_ms']:.2f}ms exceeds threshold",
                'recommendation': 'Optimize order processing pipeline and reduce network hops.',
                'action': 'Profile application performance and consider co-location services.'
            })
        rejection_stats = trading_stats.get('rejection_analysis', {})
        if isinstance(rejection_stats, dict) and rejection_stats.get('count', 0) > 0:
            recommendations.append({
                'category': 'Trading Quality',
                'priority': 'High',
                'issue': f"{rejection_stats['count']} order rejections detected",
                'recommendation': 'Review order validation logic and risk management rules.',
                'action': 'Analyze rejection reasons and implement pre-trade validation.'
            })
        if not recommendations:
            recommendations.append({
                'category': 'Monitoring',
                'priority': 'Low',
                'issue': 'No critical issues detected',
                'recommendation': 'Continue monitoring for performance degradation.',
                'action': 'Implement continuous monitoring and alerting for trading systems.'
            })
        return recommendations
    
    def _generate_html_report(self, report_data: Dict[str, Any]) -> str:
        filename = self._get_report_filename('html')
        html_content = f"""
            <!DOCTYPE html>
            <html>
            <head>
                <title>PCAP Analysis Report</title>
                <style>
                    body {{ font-family: Arial, sans-serif; margin: 40px; line-height: 1.6; }}
                    .header {{ background-color: #f4f4f4; padding: 20px; border-radius: 5px; margin-bottom: 20px; }}
                    .section {{ margin: 20px 0; }}
                    .metric {{ background-color: #e8f4f8; padding: 10px; margin: 5px 0; border-radius: 3px; }}
                    .critical {{ background-color: #ffebee; color: #c62828; }}
                    .warning {{ background-color: #fff3e0; color: #ef6c00; }}
                    .good {{ background-color: #e8f5e8; color: #2e7d32; }}
                    table {{ border-collapse: collapse; width: 100%; margin: 10px 0; }}
                    th, td {{ border: 1px solid #ddd; padding: 8px; text-align: left; }}
                    th {{ background-color: #f2f2f2; }}
                    .health-score {{ font-size: 2em; font-weight: bold; text-align: center; padding: 20px; border-radius: 10px; }}
                    .protocol-chart {{ display: inline-block; margin: 10px; }}
                    .recommendation {{ border-left: 4px solid #2196F3; padding: 10px; margin: 10px 0; background-color: #f8f9fa; }}
                    .priority-critical {{ border-left-color: #f44336; }}
                    .priority-high {{ border-left-color: #ff9800; }}
                    .priority-medium {{ border-left-color: #ffeb3b; }}
                    .priority-low {{ border-left-color: #4caf50; }}
                </style>
            </head>
            <body>
                <div class="header">
                    <h1>PCAP Analysis Report</h1>
                    <p><strong>File:</strong> {report_data['metadata']['file_path']}</p>
                    <p><strong>Generated:</strong> {report_data['metadata']['analysis_timestamp']}</p>
                    <p><strong>Packets Analyzed:</strong> {report_data['metadata']['total_packets_analyzed']}</p>
                </div>
                
                <div class="section">
                    <h2>Executive Summary</h2>
                    <div class="health-score {'good' if report_data['executive_summary']['health_score'] >= 80 else 'warning' if report_data['executive_summary']['health_score'] >= 60 else 'critical'}">
                        Health Score: {report_data['executive_summary']['health_score']}/100
                    </div>
                    
                    <div class="metric">
                        <strong>Total Packets:</strong> {report_data['executive_summary']['total_packets']}
                    </div>
                    <div class="metric">
                        <strong>Trading Packets:</strong> {report_data['executive_summary']['trading_packets']} ({report_data['executive_summary']['trading_percentage']:.1f}%)
                    </div>
                    <div class="metric">
                        <strong>Issues Detected:</strong> {report_data['executive_summary']['total_issues']} (Critical: {report_data['executive_summary']['critical_issues']})
                    </div>
                    
                    <h3>Protocol Distribution</h3>
                    <table>
                        <tr><th>Protocol</th><th>Count</th><th>Percentage</th></tr>
                        {self._generate_protocol_table(report_data['executive_summary']['protocol_distribution'], report_data['executive_summary']['total_packets'])}
                    </table>
                </div>
                
                <div class="section">
                    <h2>Trading Analysis</h2>
                    {self._generate_trading_analysis_html(report_data['trading_analysis'])}
                </div>
                
                <div class="section">
                    <h2>Network Analysis</h2>
                    {self._generate_network_analysis_html(report_data['network_analysis'])}
                </div>
                
                <div class="section">
                    <h2>Recommendations</h2>
                    {self._generate_recommendations_html(report_data['recommendations'])}
                </div>
                
                {self._generate_packet_details_html(report_data['packet_details']) if report_data['packet_details'] else ''}
                
            </body>
            </html>
            """
        output_path = os.path.join(self.output_directory, filename)
        with open(output_path, 'w') as f:
            f.write(html_content)
        return output_path
    
    def _generate_protocol_table(self, protocol_dist: Dict[str, int], total_packets: int) -> str:
        rows = []
        for protocol, count in sorted(protocol_dist.items(), key=lambda x: x[1], reverse=True):
            percentage = (count / total_packets * 100) if total_packets > 0 else 0
            rows.append(f"<tr><td>{protocol}</td><td>{count}</td><td>{percentage:.1f}%</td></tr>")
        return "\n".join(rows)
    
    def _generate_trading_analysis_html(self, trading_analysis: Dict[str, Any]) -> str:
        html = "<h3>Trading Statistics</h3>"
        order_stats = trading_analysis.get('order_statistics', {})
        if order_stats:
            html += f"""
            <div class="metric">
                <strong>Total Orders:</strong> {order_stats.get('total_orders', 0)}
            </div>
            <div class="metric">
                <strong>Order Types:</strong> {', '.join(f"{k}: {v}" for k, v in order_stats.get('order_types', {}).items())}
            </div>
            """
        latency_stats = trading_analysis.get('latency_stats', {})
        if latency_stats:
            html += f"""
            <h4>Latency Analysis</h4>
            <div class="metric">
                <strong>Average Latency:</strong> {latency_stats.get('avg_ms', 0):.2f}ms
            </div>
            <div class="metric">
                <strong>Max Latency:</strong> {latency_stats.get('max_ms', 0):.2f}ms
            </div>
            <div class="metric">
                <strong>Min Latency:</strong> {latency_stats.get('min_ms', 0):.2f}ms
            </div>
            """
        rejection_stats = trading_analysis.get('rejection_analysis', {})
        if rejection_stats:
            html += f"""
            <h4>Rejection Analysis</h4>
            <div class="metric">
                <strong>Rejections:</strong> {rejection_stats.get('count', 0)}
            </div>
            <div class="metric">
                <strong>Rejection Rate:</strong> {rejection_stats.get('rejection_rate', 0):.2f}%
            </div>
            """
        return html
    
    def _generate_network_analysis_html(self, network_analysis: Dict[str, Any]) -> str:
        html = "<h3>TCP Analysis</h3>"
        tcp_stats = network_analysis.get('tcp_analysis', {})
        if tcp_stats:
            html += f"""
            <div class="metric">
                <strong>Total TCP Packets:</strong> {tcp_stats.get('total', 0)}
            </div>
            <div class="metric">
                <strong>SYN Packets:</strong> {tcp_stats.get('syn', 0)}
            </div>
            <div class="metric">
                <strong>FIN Packets:</strong> {tcp_stats.get('fin', 0)}
            </div>
            <div class="metric">
                <strong>RST Packets:</strong> {tcp_stats.get('rst', 0)}
            </div>
            """
        top_ips = network_analysis.get('top_ip_pairs', {})
        if top_ips:
            html += "<h4>Top IP Pairs</h4><table><tr><th>IP Pair</th><th>Count</th></tr>"
            for pair, count in list(top_ips.items())[:5]:
                html += f"<tr><td>{pair}</td><td>{count}</td></tr>"
            html += "</table>"
        top_ports = network_analysis.get('top_ports', {})
        if top_ports:
            html += "<h4>Top Ports</h4><table><tr><th>Port</th><th>Count</th></tr>"
            for port, count in list(top_ports.items())[:5]:
                html += f"<tr><td>{port}</td><td>{count}</td></tr>"
            html += "</table>"
        payload_stats = network_analysis.get('payload_statistics', {})
        if payload_stats:
            html += f"""
            <h4>Payload Statistics</h4>
            <div class="metric">
                <strong>Average Size:</strong> {payload_stats.get('avg', 0):.1f} bytes
            </div>
            <div class="metric">
                <strong>Max Size:</strong> {payload_stats.get('max', 0)} bytes
            </div>
            <div class="metric">
                <strong>Min Size:</strong> {payload_stats.get('min', 0)} bytes
            </div>
            """
        return html
    
    def _generate_recommendations_html(self, recommendations: List[Dict[str, str]]) -> str:
        html = ""
        for rec in recommendations:
            priority_class = f"priority-{rec.get('priority', 'low').lower()}"
            html += f"""
            <div class="recommendation {priority_class}">
                <h4>{rec.get('category', 'General')} - {rec.get('priority', 'Low')} Priority</h4>
                <p><strong>Issue:</strong> {rec.get('issue', 'N/A')}</p>
                <p><strong>Recommendation:</strong> {rec.get('recommendation', 'N/A')}</p>
                <p><strong>Action:</strong> {rec.get('action', 'N/A')}</p>
            </div>
            """
        return html
    
    def _generate_packet_details_html(self, packet_details: List[Dict[str, Any]]) -> str:
        if not packet_details:
            return ""
        html = """
        <div class="section">
            <h2>Packet Details</h2>
            <table>
                <tr>
                    <th>Timestamp</th>
                    <th>Protocol</th>
                    <th>Source</th>
                    <th>Destination</th>
                    <th>Size</th>
                    <th>Issues</th>
                </tr>
        """
        for packet in packet_details:
            packet_info = packet.get('packet_info', {})
            issues = packet.get('llm_analysis', {}).get('issues', [])
            issue_str = ', '.join(str(issue) for issue in issues) if issues else 'None'
            html += f"""
                <tr>
                    <td>{packet_info.get('timestamp', 'N/A')}</td>
                    <td>{packet_info.get('protocol', 'N/A')}</td>
                    <td>{packet_info.get('src_ip', 'N/A')}:{packet_info.get('src_port', 'N/A')}</td>
                    <td>{packet_info.get('dst_ip', 'N/A')}:{packet_info.get('dst_port', 'N/A')}</td>
                    <td>{packet_info.get('payload_size', 0)} bytes</td>
                    <td>{issue_str}</td>
                </tr>
            """
        html += "</table></div>"
        return html
    
    def _generate_json_report(self, report_data: Dict[str, Any]) -> str:
        filename = self._get_report_filename('json')
        output_path = os.path.join(self.output_directory, filename)
        with open(output_path, 'w') as f:
            json.dump(report_data, f, indent=2, default=str)
        return output_path
    
    def _generate_markdown_report(self, report_data: Dict[str, Any]) -> str:
        filename = self._get_report_filename('md')
        markdown_content = f"""# PCAP Analysis Report
        ## Metadata
        - **File:** {report_data['metadata']['file_path']}
        - **Generated:** {report_data['metadata']['analysis_timestamp']}
        - **Packets Analyzed:** {report_data['metadata']['total_packets_analyzed']}

        ## Executive Summary

        ### Health Score: {report_data['executive_summary']['health_score']}/100

        - **Total Packets:** {report_data['executive_summary']['total_packets']}
        - **Trading Packets:** {report_data['executive_summary']['trading_packets']} ({report_data['executive_summary']['trading_percentage']:.1f}%)
        - **Issues Detected:** {report_data['executive_summary']['total_issues']} (Critical: {report_data['executive_summary']['critical_issues']})

        ### Protocol Distribution
        {self._generate_protocol_markdown_table(report_data['executive_summary']['protocol_distribution'], report_data['executive_summary']['total_packets'])}

        ## Trading Analysis
        {self._generate_trading_analysis_markdown(report_data['trading_analysis'])}

        ## Network Analysis
        {self._generate_network_analysis_markdown(report_data['network_analysis'])}

        ## Recommendations
        {self._generate_recommendations_markdown(report_data['recommendations'])}

        {self._generate_packet_details_markdown(report_data['packet_details']) if report_data['packet_details'] else ''}
        """
        output_path = os.path.join(self.output_directory, filename)
        with open(output_path, 'w') as f:
            f.write(markdown_content)
        return output_path
    
    def _generate_protocol_markdown_table(self, protocol_dist: Dict[str, int], total_packets: int) -> str:
        lines = ["| Protocol | Count | Percentage |", "|----------|-------|------------|"]
        for protocol, count in sorted(protocol_dist.items(), key=lambda x: x[1], reverse=True):
            percentage = (count / total_packets * 100) if total_packets > 0 else 0
            lines.append(f"| {protocol} | {count} | {percentage:.1f}% |")
        return "\n".join(lines)
    
    def _generate_trading_analysis_markdown(self, trading_analysis: Dict[str, Any]) -> str:
        markdown = "### Trading Statistics\n\n"
        order_stats = trading_analysis.get('order_statistics', {})
        if order_stats:
            markdown += f"- **Total Orders:** {order_stats.get('total_orders', 0)}\n"
            if order_stats.get('order_types'):
                markdown += f"- **Order Types:** {', '.join(f'{k}: {v}' for k, v in order_stats['order_types'].items())}\n"
        latency_stats = trading_analysis.get('latency_stats', {})
        if latency_stats:
            markdown += "\n### Latency Analysis\n"
            markdown += f"- **Average Latency:** {latency_stats.get('avg_ms', 0):.2f}ms\n"
            markdown += f"- **Max Latency:** {latency_stats.get('max_ms', 0):.2f}ms\n"
            markdown += f"- **Min Latency:** {latency_stats.get('min_ms', 0):.2f}ms\n"
        rejection_stats = trading_analysis.get('rejection_analysis', {})
        if rejection_stats:
            markdown += "\n### Rejection Analysis\n"
            markdown += f"- **Rejections:** {rejection_stats.get('count', 0)}\n"
            markdown += f"- **Rejection Rate:** {rejection_stats.get('rejection_rate', 0):.2f}%\n"
        return markdown
    
    def _generate_network_analysis_markdown(self, network_analysis: Dict[str, Any]) -> str:
        markdown = "### TCP Analysis\n\n"
        tcp_stats = network_analysis.get('tcp_analysis', {})
        if tcp_stats:
            markdown += f"- **Total TCP Packets:** {tcp_stats.get('total', 0)}\n"
            markdown += f"- **SYN Packets:** {tcp_stats.get('syn', 0)}\n"
            markdown += f"- **FIN Packets:** {tcp_stats.get('fin', 0)}\n"
            markdown += f"- **RST Packets:** {tcp_stats.get('rst', 0)}\n"
        top_ips = network_analysis.get('top_ip_pairs', {})
        if top_ips:
            markdown += "\n### Top IP Pairs\n"
            markdown += "| IP Pair | Count |\n|---------|-------|\n"
            for pair, count in list(top_ips.items())[:5]:
                markdown += f"| {pair} | {count} |\n"
        top_ports = network_analysis.get('top_ports', {})
        if top_ports:
            markdown += "\n### Top Ports\n"
            markdown += "| Port | Count |\n|------|-------|\n"
            for port, count in list(top_ports.items())[:5]:
                markdown += f"| {port} | {count} |\n"
        payload_stats = network_analysis.get('payload_statistics', {})
        if payload_stats:
            markdown += "\n### Payload Statistics\n"
            markdown += f"- **Average Size:** {payload_stats.get('avg', 0):.1f} bytes\n"
            markdown += f"- **Max Size:** {payload_stats.get('max', 0)} bytes\n"
            markdown += f"- **Min Size:** {payload_stats.get('min', 0)} bytes\n"
        return markdown
    
    def _generate_recommendations_markdown(self, recommendations: List[Dict[str, str]]) -> str:
        markdown = ""
        for rec in recommendations:
            markdown += f"### {rec.get('category', 'General')} - {rec.get('priority', 'Low')} Priority\n\n"
            markdown += f"**Issue:** {rec.get('issue', 'N/A')}\n\n"
            markdown += f"**Recommendation:** {rec.get('recommendation', 'N/A')}\n\n"
            markdown += f"**Action:** {rec.get('action', 'N/A')}\n\n"
            markdown += "---\n\n"
        return markdown
    
    def _generate_packet_details_markdown(self, packet_details: List[Dict[str, Any]]) -> str:
        if not packet_details:
            return ""
        markdown = "## Packet Details\n\n"
        markdown += "| Timestamp | Protocol | Source | Destination | Size | Issues |\n"
        markdown += "|-----------|----------|--------|-------------|------|--------|\n"
        for packet in packet_details:
            packet_info = packet.get('packet_info', {})
            issues = packet.get('llm_analysis', {}).get('issues', [])
            issue_str = ', '.join(str(issue) for issue in issues) if issues else 'None'
            timestamp = packet_info.get('timestamp', 'N/A')
            protocol = packet_info.get('protocol', 'N/A')
            source = f"{packet_info.get('src_ip', 'N/A')}:{packet_info.get('src_port', 'N/A')}"
            destination = f"{packet_info.get('dst_ip', 'N/A')}:{packet_info.get('dst_port', 'N/A')}"
            size = f"{packet_info.get('payload_size', 0)} bytes"
            markdown += f"| {timestamp} | {protocol} | {source} | {destination} | {size} | {issue_str} |\n"
        return markdown
    
    def _get_report_filename(self, extension: str) -> str:
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        return f"pcap_analysis_report_{timestamp}.{extension}"
    
    def save_summary_report(self, 
                           file_path: str,
                           packet_analyses: List[Dict[str, Any]],
                           trading_stats: Dict[str, Any]) -> str:        
        summary_data = {
            'metadata': {
                'file_path': file_path,
                'analysis_timestamp': datetime.now().isoformat(),
                'total_packets': len(packet_analyses)
            },
            'summary': self._generate_executive_summary(packet_analyses, trading_stats),
            'key_metrics': self._extract_key_metrics(packet_analyses, trading_stats),
            'top_issues': self._extract_top_issues(packet_analyses)
        }
        filename = self._get_summary_filename()
        output_path = os.path.join(self.output_directory, filename)
        if self.output_format == 'json':
            with open(output_path, 'w') as f:
                json.dump(summary_data, f, indent=2, default=str)
        else:
            markdown_content = self._generate_summary_markdown(summary_data)
            with open(output_path, 'w') as f:
                f.write(markdown_content)
        return output_path
    
    def _extract_key_metrics(self, packet_analyses: List[Dict[str, Any]],  trading_stats: Dict[str, Any]) -> Dict[str, Any]:
        metrics = {}
        protocols = {}
        total_payload = 0
        tcp_issues = 0
        for packet in packet_analyses:
            packet_info = packet.get('packet_info', {})
            protocol = packet_info.get('protocol', 'Unknown')
            protocols[protocol] = protocols.get(protocol, 0) + 1
            payload_size = packet_info.get('payload_size', 0)
            total_payload += payload_size
            issues = packet.get('llm_analysis', {}).get('issues', [])
            if isinstance(issues, list):
                tcp_issues += sum(1 for issue in issues if 'tcp' in str(issue).lower())
        metrics['network'] = {
            'dominant_protocol': max(protocols.items(), key=lambda x: x[1])[0] if protocols else 'Unknown',
            'total_payload_bytes': total_payload,
            'avg_payload_size': total_payload / len(packet_analyses) if packet_analyses else 0,
            'tcp_issues': tcp_issues
        }
        trading_metrics = {}
        if trading_stats:
            latency_stats = trading_stats.get('latency_stats', {})
            if latency_stats:
                trading_metrics['avg_latency_ms'] = latency_stats.get('avg_ms', 0)
                trading_metrics['max_latency_ms'] = latency_stats.get('max_ms', 0)
            order_stats = trading_stats.get('order_statistics', {})
            if order_stats:
                trading_metrics['total_orders'] = order_stats.get('total_orders', 0)
            rejection_stats = trading_stats.get('rejection_analysis', {})
            if rejection_stats:
                trading_metrics['rejection_count'] = rejection_stats.get('count', 0)
                trading_metrics['rejection_rate'] = rejection_stats.get('rejection_rate', 0)
        metrics['trading'] = trading_metrics
        return metrics
    
    def _extract_top_issues(self, packet_analyses: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        issue_counts = {}
        issue_details = {}
        for packet in packet_analyses:
            issues = packet.get('llm_analysis', {}).get('issues', [])
            if isinstance(issues, list):
                for issue in issues:
                    issue_str = str(issue).lower()
                    issue_counts[issue_str] = issue_counts.get(issue_str, 0) + 1
                    if issue_str not in issue_details:
                        issue_details[issue_str] = str(issue)
        top_issues = []
        for issue, count in sorted(issue_counts.items(), key=lambda x: x[1], reverse=True)[:10]:
            top_issues.append({
                'issue': issue_details[issue],
                'count': count,
                'percentage': (count / len(packet_analyses) * 100) if packet_analyses else 0
            })
        return top_issues
    
    def _generate_summary_markdown(self, summary_data: Dict[str, Any]) -> str:
        content = f"""# PCAP Analysis Summary
        ## File Information
        - **File:** {summary_data['metadata']['file_path']}
        - **Analyzed:** {summary_data['metadata']['analysis_timestamp']}
        - **Total Packets:** {summary_data['metadata']['total_packets']}

        ## Health Score: {summary_data['summary']['health_score']}/100

        ## Key Metrics

        ### Network Analysis
        - **Dominant Protocol:** {summary_data['key_metrics']['network']['dominant_protocol']}
        - **Total Payload:** {summary_data['key_metrics']['network']['total_payload_bytes']:,} bytes
        - **Average Payload Size:** {summary_data['key_metrics']['network']['avg_payload_size']:.1f} bytes
        - **TCP Issues:** {summary_data['key_metrics']['network']['tcp_issues']}

        ### Trading Analysis
        """
        trading_metrics = summary_data['key_metrics']['trading']
        if trading_metrics:
            content += f"""- **Average Latency:** {trading_metrics.get('avg_latency_ms', 0):.2f}ms
        - **Max Latency:** {trading_metrics.get('max_latency_ms', 0):.2f}ms
        - **Total Orders:** {trading_metrics.get('total_orders', 0)}
        - **Rejections:** {trading_metrics.get('rejection_count', 0)} ({trading_metrics.get('rejection_rate', 0):.2f}%)
        """
        else:
            content += "- No trading-specific metrics detected\n"
        if summary_data['top_issues']:
            content += "\n## Top Issues\n\n"
            content += "| Issue | Count | Percentage |\n|-------|-------|------------|\n"
            for issue_data in summary_data['top_issues']:
                content += f"| {issue_data['issue']} | {issue_data['count']} | {issue_data['percentage']:.1f}% |\n"
        return content
    
    def _get_summary_filename(self) -> str:
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        extension = 'json' if self.output_format == 'json' else 'md'
        return f"pcap_summary_{timestamp}.{extension}"
    
    def generate_batch_report(self, batch_results: List[Dict[str, Any]]) -> str:
        batch_data = {
            'metadata': {
                'batch_timestamp': datetime.now().isoformat(),
                'total_files': len(batch_results),
                'successful_analyses': sum(1 for r in batch_results if r.get('success', False))
            },
            'file_summaries': [],
            'aggregate_stats': self._calculate_aggregate_stats(batch_results)
        }
        for result in batch_results:
            if result.get('success', False):
                file_summary = {
                    'filename': result.get('filename', 'Unknown'),
                    'packets_analyzed': result.get('total_packets', 0),
                    'health_score': result.get('health_score', 0),
                    'issues_found': result.get('total_issues', 0),
                    'trading_packets': result.get('trading_packets', 0)
                }
                batch_data['file_summaries'].append(file_summary)
        filename = self._get_batch_filename()
        output_path = os.path.join(self.output_directory, filename)
        
        if self.output_format == 'json':
            with open(output_path, 'w') as f:
                json.dump(batch_data, f, indent=2, default=str)
        else:
            markdown_content = self._generate_batch_markdown(batch_data)
            with open(output_path, 'w') as f:
                f.write(markdown_content)
        return output_path
    
    def _calculate_aggregate_stats(self, batch_results: List[Dict[str, Any]]) -> Dict[str, Any]:
        successful_results = [r for r in batch_results if r.get('success', False)]
        if not successful_results:
            return {}
        total_packets = sum(r.get('total_packets', 0) for r in successful_results)
        total_issues = sum(r.get('total_issues', 0) for r in successful_results)
        health_scores = [r.get('health_score', 0) for r in successful_results]
        return {
            'total_packets_analyzed': total_packets,
            'total_issues_found': total_issues,
            'average_health_score': sum(health_scores) / len(health_scores) if health_scores else 0,
            'files_with_issues': sum(1 for r in successful_results if r.get('total_issues', 0) > 0),
            'issue_rate': (total_issues / total_packets * 100) if total_packets > 0 else 0
        }
    
    def _generate_batch_markdown(self, batch_data: Dict[str, Any]) -> str:
        content = f"""# Batch PCAP Analysis Report
        ## Batch Summary
        - **Generated:** {batch_data['metadata']['batch_timestamp']}
        - **Total Files:** {batch_data['metadata']['total_files']}
        - **Successful Analyses:** {batch_data['metadata']['successful_analyses']}

        ## Aggregate Statistics
        - **Total Packets Analyzed:** {batch_data['aggregate_stats'].get('total_packets_analyzed', 0):,}
        - **Total Issues Found:** {batch_data['aggregate_stats'].get('total_issues_found', 0):,}
        - **Average Health Score:** {batch_data['aggregate_stats'].get('average_health_score', 0):.1f}/100
        - **Files with Issues:** {batch_data['aggregate_stats'].get('files_with_issues', 0)}
        - **Overall Issue Rate:** {batch_data['aggregate_stats'].get('issue_rate', 0):.2f}%

        ## File Analysis Results

        | Filename | Packets | Health Score | Issues | Trading Packets |
        |----------|---------|--------------|--------|-----------------|
        """
        for file_summary in batch_data['file_summaries']:
            content += f"| {file_summary['filename']} | {file_summary['packets_analyzed']:,} | {file_summary['health_score']}/100 | {file_summary['issues_found']} | {file_summary['trading_packets']} |\n"
        return content
    
    def _get_batch_filename(self) -> str:
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        extension = 'json' if self.output_format == 'json' else 'md'
        return f"batch_analysis_{timestamp}.{extension}"
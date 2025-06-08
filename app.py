import os
import yaml
import pandas as pd
import streamlit as st
import plotly.express as px
from datetime import datetime
import plotly.graph_objects as go
from typing import Dict, Any, List
from pcap.llm_client import LLMClient
from pcap.packet_reader import PacketReader
from pcap.trading_analyzer import TradingAnalyzer
from pcap.report_generator import ReportGenerator
from pcap.anolmany_detector import MLAnomalyDetector

class StreamlitPCAPAnalyzer:
    def __init__(self, config_path: str = "config/config.yaml"):
        with open(config_path, 'r') as file:
            self.config = yaml.safe_load(file)
        self.packet_reader = PacketReader(config_path)
        self.llm_client = LLMClient(config_path)
        self.trading_analyzer = TradingAnalyzer(config_path)
        self.report_generator = ReportGenerator(config_path)
        self.anomaly_detector = MLAnomalyDetector()
        self.input_dir = self.config['files']['input_directory']
        self.output_dir = self.config['files']['output_directory']
        os.makedirs(self.input_dir, exist_ok=True)
        os.makedirs(self.output_dir, exist_ok=True)
    
    def _process_packet_analysis(self, file_path: str, file_stats: Dict, use_pyshark: bool = False, progress_callback=None) -> Dict[str, Any]:
        try:
            packet_analyses = []
            self.trading_analyzer.reset_session_data()
            packet_count = 0
            total_packets = file_stats.get('packet_count', 0)
            if isinstance(total_packets, str):
                total_packets = int(total_packets.replace('+', ''))
            tcp_streams = {}
            packet_loss_counter = 0
            for packet_info in self.packet_reader.read_pcap_file(file_path, use_pyshark):
                if packet_info.get('protocol') == 'TCP':
                    key = (
                        packet_info.get('src_ip'),
                        packet_info.get('src_port'),
                        packet_info.get('dst_ip'),
                        packet_info.get('dst_port')
                    )
                    current_seq = packet_info.get('seq_num')
                    payload_size = packet_info.get('payload_size', 0)
                    if None not in key and current_seq is not None:
                        expected_seq = tcp_streams.get(key)
                        if expected_seq is not None and current_seq > expected_seq:
                            packet_info['packet_loss_detected'] = True
                            packet_loss_counter += 1
                        tcp_streams[key] = max(current_seq + payload_size, tcp_streams.get(key, 0))
                trading_analysis = self.trading_analyzer.analyze_trading_packet(packet_info)
                packet_analysis = self.llm_client.analyze_packet(packet_info)
                packet_analyses.append({
                    'packet_info': packet_info,
                    'trading_analysis': trading_analysis,
                    'packet_analysis': packet_analysis
                })
                packet_count += 1
                if progress_callback and (packet_count % 50 == 0 or packet_count <= 10):
                    progress_callback(packet_count, total_packets)
            trading_stats = self.trading_analyzer.get_session_statistics()
            executive_summary = self.report_generator._generate_executive_summary(packet_analyses, trading_stats)
            network_analysis = self.report_generator._generate_network_analysis(packet_analyses)
            recommendations = self.report_generator._generate_recommendations(packet_analyses, trading_stats)
            session_data = {
                'total_packets': len(packet_analyses),
                'duration': file_stats.get('duration_seconds', 0),
                'avg_latency': trading_stats.get('latency_stats', {}).get('avg_ms', 0),
                'packet_loss': packet_loss_counter,
                'retransmissions': trading_stats.get('connection_health', {}).get('connection_resets', 0),
                'protocols': executive_summary.get('protocol_distribution', {}),
                'order_messages': trading_stats.get('total_orders', 0),
                'execution_messages': trading_stats.get('total_executions', 0),
                'rejected_orders': trading_stats.get('total_rejections', 0),
                'cancel_messages': trading_stats.get('total_cancellations', 0),
                'fix_messages': sum(1 for analysis in packet_analyses if 'FIX' in str(analysis.get('packet_info', {}).get('payload', ''))),
                'itch_messages': sum(1 for analysis in packet_analyses if 'ITCH' in str(analysis.get('packet_info', {}).get('payload', '')))
            }
            llm_session_analysis = self.llm_client.analyze_trading_session(session_data)   
            anomalies = {}
            try:
                features = self.anomaly_detector.extract_features(packet_analyses, trading_stats)
                self.anomaly_detector.train(features)
                anomalies = self.anomaly_detector.detect_anomalies(features)  
            except Exception as e:
                pass       
            return {
                'file_stats': file_stats,
                'packet_analyses': packet_analyses,
                'trading_stats': trading_stats,
                'executive_summary': executive_summary,
                'network_analysis': network_analysis,
                'recommendations': recommendations,
                'llm_session_analysis': llm_session_analysis,
                'anomalies': anomalies
            }
        except Exception as e:
            return {"error": str(e)}
        
    def analyze_uploaded_file(self, uploaded_file, use_pyshark: bool = False) -> Dict[str, Any]:
        input_path = os.path.join(self.input_dir, f"{uploaded_file.name}_{datetime.now().strftime('%Y%m%d_%H%M%S')}.pcap")
        with open(input_path, "wb") as f:
            f.write(uploaded_file.getvalue())
        try:
            file_stats = self.packet_reader.get_file_statistics(input_path)
            if "error" in file_stats:
                return {"error": file_stats["error"]}
            progress_bar = st.progress(0)
            status_text = st.empty()
            def progress_callback(current, total):
                progress = min(current / max(total, 1), 1.0)
                progress_bar.progress(progress)
                status_text.text(f"Analyzed {current:,}/{total:,} packets...")
            result = self._process_packet_analysis(input_path, file_stats, use_pyshark, progress_callback)
            progress_bar.progress(1.0)
            status_text.text("Analysis Complete")
            if "error" not in result:
                result['file_path'] = input_path
            return result
        finally:
            try:
                progress_bar.empty()
                status_text.empty()
            except:
                pass
    
    def analyze_batch_files(self, uploaded_files: List) -> Dict[str, Any]:
        batch_results = []
        progress_bar = st.progress(0)
        status_text = st.empty()
        for i, uploaded_file in enumerate(uploaded_files):
            status_text.text(f"Processing {uploaded_file.name} ({i+1}/{len(uploaded_files)})")
            try:
                result = self.analyze_uploaded_file(uploaded_file)
                if "error" not in result:
                    batch_results.append({
                        'filename': uploaded_file.name,
                        'success': True,
                        'total_packets': len(result['packet_analyses']),
                        'health_score': result['executive_summary']['health_score'],
                        'total_issues': result['executive_summary']['total_issues'],
                        'trading_packets': result['executive_summary']['trading_packets']
                    })
                else:
                    batch_results.append({
                        'filename': uploaded_file.name,
                        'success': False,
                        'error': result['error']
                    })
            except Exception as e:
                batch_results.append({
                    'filename': uploaded_file.name,
                    'success': False,
                    'error': str(e)
                })
            progress_bar.progress((i + 1) / len(uploaded_files))
        batch_report_path = self.report_generator.generate_batch_report(batch_results)
        return {
            'batch_results': batch_results,
            'batch_report_path': batch_report_path
        }

def render_executive_summary(executive_summary: Dict[str, Any], file_stats: Dict[str, Any],  trading_stats: Dict[str, Any] = None):
    st.header("📊 Executive Summary")
    health_score = executive_summary['health_score']
    fig = go.Figure(go.Indicator(
        mode="gauge+number+delta",
        value=health_score,
        domain={'x': [0, 1], 'y': [0, 1]},
        title={'text': "System Health Score"},
        delta={'reference': 80},
        gauge={
            'axis': {'range': [None, 100]},
            'bar': {'color': "blue"},
            'steps': [
                {'range': [0, 50], 'color': "#ff4444"},
                {'range': [50, 80], 'color': "#ffaa00"},
                {'range': [80, 100], 'color': "#44ff44"}
            ],
            'threshold': {
                'line': {'color': "red", 'width': 4},
                'thickness': 0.75,
                'value': 90
            }
        }
    ))
    st.plotly_chart(fig, use_container_width=True)
    metrics_col1, metrics_col2, metrics_col3 = st.columns(3)
    with metrics_col1:
        st.metric("📦 Total Packets", f"{executive_summary['total_packets']:,}")
        st.metric("⚠️ Total Issues", f"{executive_summary['total_issues']}")
    with metrics_col2:
        st.metric("📈 Trading Packets", f"{executive_summary['trading_percentage']:.1f}%")
        st.metric("🔴 Critical Issues", f"{executive_summary['critical_issues']}")
    with metrics_col3:
        st.metric("📁 File Size", f"{file_stats['file_size'] / (1024*1024):.1f} MB")
        st.metric("⏱️ Duration", f"{file_stats['duration_seconds']:.1f}s")
    if trading_stats and trading_stats.get('total_orders', 0) > 0:
        st.subheader("📈 Trading Performance Summary")
        perf_col1, perf_col2, perf_col3, perf_col4 = st.columns(4)
        orders = trading_stats.get('total_orders', 0)
        executions = trading_stats.get('total_executions', 0)
        fill_rate = (executions / orders * 100) if orders > 0 else 0
        latency_stats = trading_stats.get('latency_stats', {})
        with perf_col1:
            st.metric("🎯 Fill Rate", f"{fill_rate:.1f}%")
        with perf_col2:
            st.metric("⚡️ Average Latency", f"{latency_stats.get('avg_ms', 0):.2f}ms")
        with perf_col3:
            rejection_rate = (trading_stats.get('total_rejections', 0) / orders * 100) if orders > 0 else 0
            st.metric("❌ Rejection Rate", f"{rejection_rate:.1f}%")
        with perf_col4:
            conn_health = trading_stats.get('connection_health', {}).get('health_score', 100)
            st.metric("🔗 Connection Health", f"{conn_health}/100")
    protocol_dist = executive_summary['protocol_distribution']
    if protocol_dist:
        st.subheader("📡 Protocol Distribution")
        fig = px.pie(
            values=list(protocol_dist.values()),
            names=list(protocol_dist.keys()),
            hole=0.4,
            color_discrete_sequence=px.colors.sequential.RdBu
        )
        fig.update_traces(textinfo='percent+label', textfont_size=12)
        st.plotly_chart(fig, use_container_width=True)

def render_trading_analytics(trading_stats: Dict[str, Any]):
    st.header("📈 Trading Analysis")
    if not trading_stats or trading_stats.get('total_orders', 0) == 0:
        st.info("No trading activity detected in this capture")
        return
    st.subheader("🧾 Order Flow Analysis")
    orders = trading_stats.get('total_orders', 0)
    executions = trading_stats.get('total_executions', 0)
    rejections = trading_stats.get('total_rejections', 0)
    cancellations = trading_stats.get('total_cancellations', 0)
    flow_col1, flow_col2 = st.columns(2)
    with flow_col1:
        order_flow_data = {
            'Type': ['Orders', 'Executions', 'Rejections', 'Cancellations'],
            'Count': [orders, executions, rejections, cancellations]
        }
        fig = px.bar(
            x=order_flow_data['Type'],
            y=order_flow_data['Count'],
            title="Order Flow Distribution",
            color=order_flow_data['Count'],
            color_continuous_scale='viridis'
        )
        st.plotly_chart(fig, use_container_width=True)
    with flow_col2:
        if orders > 0:
            fill_rate = (executions / orders) * 100
            rejection_rate = (rejections / orders) * 100
            cancel_rate = (cancellations / orders) * 100
            rates_data = {
                'Metric': ['Fill Rate', 'Rejection Rate', 'Cancellation Rate'],
                'Percentage': [fill_rate, rejection_rate, cancel_rate]
            }
            fig = px.bar(
                x=rates_data['Metric'],
                y=rates_data['Percentage'],
                title="Order Success Rates (%)",
                color=rates_data['Percentage'],
                color_continuous_scale='RdYlGn'
            )
            st.plotly_chart(fig, use_container_width=True)
    latency_stats = trading_stats.get('latency_stats', {})
    if latency_stats and latency_stats.get('count', 0) > 0:
        st.subheader("⚡️ Latency Performance")
        lat_col1, lat_col2 = st.columns(2)
        with lat_col1:
            latency_metrics = st.columns(4)
            with latency_metrics[0]:
                st.metric("Average", f"{latency_stats.get('avg_ms', 0):.2f}ms")
            with latency_metrics[1]:
                st.metric("P95", f"{latency_stats.get('p95_ms', 0):.2f}ms")
            with latency_metrics[2]:
                st.metric("P99", f"{latency_stats.get('p99_ms', 0):.2f}ms")
            with latency_metrics[3]:
                st.metric("Max", f"{latency_stats.get('max_ms', 0):.2f}ms")
        with lat_col2:
            latency_data = {
                'Metric': ['Min', 'Avg', 'P95', 'P99', 'Max'],
                'Latency (ms)': [
                    latency_stats.get('min_ms', 0),
                    latency_stats.get('avg_ms', 0),
                    latency_stats.get('p95_ms', 0),
                    latency_stats.get('p99_ms', 0),
                    latency_stats.get('max_ms', 0)
                ]
            }
            fig = px.bar(
                x=latency_data['Metric'],
                y=latency_data['Latency (ms)'],
                title="Latency Distribution",
                color=latency_data['Latency (ms)'],
                color_continuous_scale='RdYlGn_r'
            )
            st.plotly_chart(fig, use_container_width=True)
        avg_latency = latency_stats.get('avg_ms', 0)
        if avg_latency > 10:
            st.error(f"🚨 High Latency Detected: {avg_latency:.2f}ms (threshold: 10ms)")
        elif avg_latency > 5:
            st.warning(f"⚠️ Elevated Latency: {avg_latency:.2f}ms")
        else:
            st.success(f"✅ Latency Within Acceptable Range: {avg_latency:.2f}ms")
    rejection_analysis = trading_stats.get('rejection_analysis', {})
    if rejection_analysis.get('count', 0) > 0:
        st.subheader("❌ Rejection Analysis")
        rej_col1, rej_col2 = st.columns(2)
        with rej_col1:
            st.metric("Total Rejections", rejection_analysis['count'])
            st.metric("Rejection Rate", f"{rejection_analysis['rejection_rate']:.2f}%")
        with rej_col2:
            reasons = rejection_analysis.get('reasons', {})
            if reasons:
                fig = px.pie(
                    values=list(reasons.values()),
                    names=list(reasons.keys()),
                    title="Rejection Reasons"
                )
                st.plotly_chart(fig, use_container_width=True)

def render_network_analysis(network_analysis: Dict[str, Any], anomalies: Dict[str, Any] = {}, packet_analyses: Dict[str, Any] = {}):
    st.header("🌐 Network Analysis")
    tcp_stats = network_analysis.get('tcp_analysis', {})
    if tcp_stats.get('total', 0) > 0:
        st.subheader("🔗 TCP Connection Analysis")
        tcp_col1, tcp_col2 = st.columns(2)
        with tcp_col1:
            tcp_metrics = {
                'SYN (New)': tcp_stats.get('syn', 0),
                'FIN (Close)': tcp_stats.get('fin', 0),
                'RST (Reset)': tcp_stats.get('rst', 0),
                'Other': tcp_stats.get('total', 0) - tcp_stats.get('syn', 0) - tcp_stats.get('fin', 0) - tcp_stats.get('rst', 0)
            }
            fig = px.pie(
                values=list(tcp_metrics.values()),
                names=list(tcp_metrics.keys()),
                title="TCP Flags Distribution"
            )
            st.plotly_chart(fig, use_container_width=True)
        with tcp_col2:
            total_tcp = tcp_stats.get('total', 1)
            rst_rate = (tcp_stats.get('rst', 0) / total_tcp) * 100
            fin_rate = (tcp_stats.get('fin', 0) / total_tcp) * 100
            
            conn_col1, conn_col2 = st.columns(2)
            with conn_col1:
                st.metric("RST Rate", f"{rst_rate:.1f}%", help="Forced connection closes")
            with conn_col2:
                st.metric("Clean Close Rate", f"{fin_rate:.1f}%", help="Normal connection closes")
    top_ips = network_analysis.get('top_ip_pairs', {})
    top_ports = network_analysis.get('top_ports', {})
    if top_ips or top_ports:
        st.subheader("🚦 Traffic Analysis")
        st.markdown("<br>", unsafe_allow_html=True) 
        traffic_col1, traffic_col2 = st.columns(2)
        with traffic_col1:
            if top_ips:
                st.write("**Top Communication Pairs**")
                ip_data = list(top_ips.items())[:8]
                fig = px.bar(
                    x=[count for _, count in ip_data],
                    y=[pair for pair, _ in ip_data],
                    orientation='h',
                    title="Most Active IP Pairs"
                )
                st.plotly_chart(fig, use_container_width=True)
        with traffic_col2:
            if top_ports:
                st.write("**Port Usage Distribution**")
                port_data = list(top_ports.items())[:8]
                fig = px.bar(
                    x=[port for port, _ in port_data],
                    y=[count for _, count in port_data],
                    title="Most Used Ports"
                )
                st.plotly_chart(fig, use_container_width=True)
    payload_stats = network_analysis.get('payload_statistics', {})
    if payload_stats:
        st.subheader("🗳️ Payload Analysis")
        payload_col1, payload_col2, payload_col3, payload_col4 = st.columns(4)
        payload_col1.metric("Avg Size", f"{payload_stats.get('avg', 0):.1f} bytes")
        payload_col2.metric("Median", f"{payload_stats.get('median', 0)} bytes")
        payload_col3.metric("Min", f"{payload_stats.get('min', 0)} bytes")
        payload_col4.metric("Max", f"{payload_stats.get('max', 0)} bytes")
    if 'anomalies' in anomalies:
        st.subheader("🤖 Anomaly Detection")
        render_ml_anomaly_analysis(anomalies, packet_analyses)

def render_packet_analysis(results: Dict[str, Any]):
    st.header("📦 Packet Analysis")
    filter_col1, filter_col2, filter_col3, filter_col4 = st.columns(4)
    with filter_col1:
        show_trading_only = st.checkbox("Trading Packets Only", key="explorer_trading")
    with filter_col2:
        show_issues_only = st.checkbox("Issues Only", key="explorer_issues")
    with filter_col3:
        protocol_filter = st.selectbox("Protocol", ["All"] + list(set(p['packet_info']['protocol'] for p in results['packet_analyses'])))
    with filter_col4:
        max_packets = st.number_input("Max Display", min_value=10, max_value=1000, value=100, key="explorer_max")
    filtered_packets = []
    for i, analysis in enumerate(results['packet_analyses'][:max_packets]):
        packet_info = analysis['packet_info']
        trading_analysis = analysis.get('trading_analysis', {})
        packet_analysis = analysis.get('packet_analysis', {})
        is_trading = trading_analysis.get('is_trading', False)
        issues_count = len(packet_analysis.get('issues', []))
        if show_trading_only and not is_trading:
            continue
        if show_issues_only and issues_count == 0:
            continue
        if protocol_filter != "All" and packet_info['protocol'] != protocol_filter:
            continue
        filtered_packets.append({
            'Index': i + 1,
            'Time': datetime.fromtimestamp(packet_info['timestamp']) if packet_info['timestamp'] else 'N/A',
            'Protocol': packet_info['protocol'],
            'Source': f"{packet_info['src_ip']}:{packet_info['src_port']}",
            'Destination': f"{packet_info['dst_ip']}:{packet_info['dst_port']}",
            'Length': packet_info['length'],
            'Trading': '✅' if is_trading else '❎',
            'Issues': issues_count,
            'Type': packet_analysis.get('packet_type', 'Unknown'),
            'Impact': packet_analysis.get('performance_impact', 'Low')
        })
    if filtered_packets:
        st.info(f"Showing {len(filtered_packets)} of {len(results['packet_analyses'])} packets")
        df = pd.DataFrame(filtered_packets)
        selected_packet = st.dataframe(
            df,
            column_config={
                "Trading": st.column_config.Column("Trading", width="small"),
                "Issues": st.column_config.NumberColumn("Issues", format="%d ⚠️"),
                "Impact": st.column_config.Column("Impact", width="medium")
            },
            hide_index=True,
            use_container_width=True,
            on_select="rerun",
            selection_mode="single-row"
        )
        if len(selected_packet.selection.rows) > 0:
            selected_idx = selected_packet.selection.rows[0]
            packet_idx = filtered_packets[selected_idx]['Index'] - 1
            st.subheader(f"📋 Packet {packet_idx + 1} Details")
            analysis = results['packet_analyses'][packet_idx]
            packet_info = analysis['packet_info']
            packet_analysis = analysis.get('packet_analysis', {})
            detail_col1, detail_col2 = st.columns(2)
            with detail_col1:
                st.write("**Packet Information**")
                st.json({
                    "Protocol": packet_info['protocol'],
                    "Source": f"{packet_info['src_ip']}:{packet_info['src_port']}",
                    "Destination": f"{packet_info['dst_ip']}:{packet_info['dst_port']}",
                    "Length": packet_info['length'],
                    "Timestamp": datetime.fromtimestamp(packet_info['timestamp']).strftime('%Y-%m-%d %H:%M:%S.%f') if packet_info['timestamp'] else 'N/A'
                })
            with detail_col2:
                if packet_analysis:
                    st.write("**AI Analysis**")
                    st.write(f"**Type:** {packet_analysis.get('packet_type', 'Unknown')}")
                    st.write(f"**Trading Relevance:** {packet_analysis.get('trading_relevance', 'Unknown')}")
                    st.write(f"**Performance Impact:** {packet_analysis.get('performance_impact', 'Unknown')}")
                    issues = packet_analysis.get('issues', [])
                    if issues:
                        st.write("**Issues:**")
                        for issue in issues:
                            st.write(f"• ⚠️ {issue}")
                    recommendations = packet_analysis.get('recommendations', [])
                    if recommendations:
                        st.write("**Recommendations:**")
                        for rec in recommendations:
                            st.write(f"• 💡 {rec}")
    else:
        st.warning("No packets match the current filters.")

def render_recommendations(recommendations: List[Dict[str, str]]):
    st.subheader("🧠 Recommendations")
    priority_groups = {}
    for rec in recommendations:
        priority = rec.get('priority', 'Low')
        if priority not in priority_groups:
            priority_groups[priority] = []
        priority_groups[priority].append(rec)
    priority_order = ['Critical', 'High', 'Medium', 'Low']
    priority_colors = {
        'Critical': '🔴',
        'High': '🟠', 
        'Medium': '🟡',
        'Low': '🟢'
    }
    for priority in priority_order:
        if priority in priority_groups:
            st.write(f"### {priority_colors[priority]} {priority} Priority")
            for rec in priority_groups[priority]:
                with st.expander(f"{rec['category']} - {rec['issue'][:50]}..."):
                    st.write(f"**Issue:** {rec['issue']}")
                    st.write(f"**Recommendation:** {rec['recommendation']}")
                    st.write(f"**Action Required:** {rec['action']}")

def render_llm_packet_analysis(packet_analyses: List[Dict], max_display: int = 50):
    st.subheader("🧠 AI Packet Analysis")
    analyzed_packets = [
        analysis for analysis in packet_analyses 
        if analysis.get('packet_analysis') and analysis['packet_analysis']
    ]
    if not analyzed_packets:
        st.info("No packets were analyzed by AI (only trading-relevant packets are sent to LLM)")
        return
    display_count = min(len(analyzed_packets), max_display)
    if len(analyzed_packets) > max_display:
        st.warning(f"Showing first {max_display} of {len(analyzed_packets)} AI-analyzed packets")
    col1, col2, col3, col4 = st.columns(4)
    total_issues = sum(len(p.get('packet_analysis', {}).get('issues', [])) for p in analyzed_packets)
    high_impact = sum(1 for p in analyzed_packets 
                     if 'high' in p.get('packet_analysis', {}).get('performance_impact', '').lower())
    col1.metric("AI Analyzed Packets", len(analyzed_packets))
    col2.metric("Total Issues Found", total_issues)
    col3.metric("High Impact Packets", high_impact)
    col4.metric("Analysis Coverage", f"{len(analyzed_packets)}/{len(packet_analyses)} packets")
    for i, analysis in enumerate(analyzed_packets[:display_count]):
        packet_info = analysis['packet_info']
        packet_analysis = analysis['packet_analysis']
        with st.expander(f"Packet {i+1}: {packet_info['protocol']} - {packet_info['src_ip']}:{packet_info['src_port']} → {packet_info['dst_ip']}:{packet_info['dst_port']}"):
            col1, col2 = st.columns(2)
            with col1:
                st.write("**Packet Details**")
                st.write(f"• **Type:** {packet_analysis.get('packet_type', 'Unknown')}")
                st.write(f"• **Size:** {packet_info['length']} bytes")
                st.write(f"• **Trading Relevance:** {packet_analysis.get('trading_relevance', 'Unknown')}")
                st.write(f"• **Performance Impact:** {packet_analysis.get('performance_impact', 'Unknown')}")
            with col2:
                issues = packet_analysis.get('issues', [])
                if issues:
                    st.write("**Issues Detected:**")
                    for issue in issues:
                        st.write(f"• ⚠️ {issue}")
                else:
                    st.write("✅ **No issues detected**")
                recommendations = packet_analysis.get('recommendations', [])
                if recommendations:
                    st.write("**Recommendations:**")
                    for rec in recommendations:
                        st.write(f"• 💡 {rec}")

def render_ai_chat_interface(analyzer, results):
    st.header("🤖 AI Assistant")
    if 'chat_history' not in st.session_state:
        st.session_state.chat_history = []
        welcome_msg = f"""
        👋 Hello! I'm your AI Assistant. I've analyzed your PCAP data:
        📊 **Quick Summary:**
        • {results['executive_summary']['total_packets']:,} total packets
        • {results['executive_summary']['trading_packets']} trading packets
        • {results['executive_summary']['health_score']}/100 health score
        • {results['trading_stats'].get('latency_stats', {}).get('avg_ms', 0):.2f}ms average latency
        
        Ask me anything about your network analysis, trading performance, or specific issues!
        """
        st.session_state.chat_history.append({"role": "assistant", "content": welcome_msg})
    chat_container = st.container()
    with chat_container:
        for i, message in enumerate(st.session_state.chat_history):
            if message["role"] == "user":
                with st.chat_message("user"):
                    st.write(message['content'])
            else:
                with st.chat_message("assistant"):
                    st.write(message['content'])
    user_message = st.chat_input("Ask about your network analysis...")
    if user_message:
        st.session_state.chat_history.append({"role": "user", "content": user_message})
        context = f"""
        Analysis Results Summary:
        - Total Packets: {results['executive_summary']['total_packets']}
        - Trading Packets: {results['executive_summary']['trading_packets']}
        - Health Score: {results['executive_summary']['health_score']}/100
        - Issues Found: {results['executive_summary']['total_issues']}
        - Critical Issues: {results['executive_summary']['critical_issues']}
        - Average Latency: {results['trading_stats'].get('latency_stats', {}).get('avg_ms', 0):.2f}ms
        - P99 Latency: {results['trading_stats'].get('latency_stats', {}).get('p99_ms', 0):.2f}ms
        - Fill Rate: {(results['trading_stats'].get('total_executions', 0) / max(results['trading_stats'].get('total_orders', 1), 1) * 100):.1f}%
        - Rejection Rate: {(results['trading_stats'].get('total_rejections', 0) / max(results['trading_stats'].get('total_orders', 1), 1) * 100):.1f}%
        - Connection Health: {results['trading_stats'].get('connection_health', {}).get('health_score', 100)}/100
        """
        try:
            with st.spinner("🤖 Thinking..."):
                ai_response = analyzer.llm_client.chat_query(user_message, context)
                st.session_state.chat_history.append({"role": "assistant", "content": ai_response})
                st.rerun()
        except Exception as e:
            error_msg = f"Sorry, I encountered an error: {str(e)}"
            st.session_state.chat_history.append({"role": "assistant", "content": error_msg})
            st.rerun()
    chat_controls = st.columns([1, 1, 3])
    with chat_controls[0]:
        if st.button("🗑️ Clear Chat"):
            st.session_state.chat_history = []
            st.rerun()
    with chat_controls[1]:
        if st.button("💾 Export Chat"):
            chat_export = "\n".join([
                f"{'User' if msg['role'] == 'user' else 'AI'}: {msg['content']}"
                for msg in st.session_state.chat_history
            ])
            st.download_button(
                "📥 Download",
                chat_export,
                file_name=f"chat_history_{datetime.now().strftime('%Y%m%d_%H%M%S')}.txt",
                mime="text/plain"
            )

def render_ai_session_analysis(llm_session_analysis):
    st.subheader("🧠 AI Session Analysis")
    if not llm_session_analysis:
        st.error(f"An error was encountered while generating the results. Please try again.")
        return
    if isinstance(llm_session_analysis, dict):
        if 'session_health' in llm_session_analysis:
            st.write("**Session Health**")
            st.info(llm_session_analysis.get('session_health', 'No assessment available'))
        if 'trading_performance' in llm_session_analysis:
            st.write("**Trading Performance**")
            st.info(llm_session_analysis.get('trading_performance', 'No analysis available'))
        if 'risk_assessment' in llm_session_analysis:
            st.write("**Risk Assessment**")
            risk = llm_session_analysis.get('risk_assessment', [])
            if isinstance(risk, list) and risk:
                for item in risk:
                    st.markdown(f"- ⚠️ {item}")
            elif isinstance(risk, str):
                st.warning(risk)
            else:
                st.info("No risk assessment available.")
        if 'compliance_notes' in llm_session_analysis:
            st.write("**Compliance Notes**")
            st.info(llm_session_analysis.get('compliance_notes', 'No notes available'))
        if 'recommendations' in llm_session_analysis:
            st.write("**Optimization Recommendations**")
            recs = llm_session_analysis.get('recommendations', [])
            if isinstance(recs, list) and recs:
                for item in recs:
                    st.markdown(f"- ✅ {item}")
            elif isinstance(recs, str):
                st.success(recs)
            else:
                st.info("No recommendations available.")

def render_ml_anomaly_analysis(anomalies, packet_analyses):
    st.subheader("🤖 Machine Learning Anomaly Detection")
    if not anomalies:
        st.info("No anomalies detected or insufficient data for ML analysis")
        return
    total_anomalies = sum(anom.get('anomaly_count', 0) for anom in anomalies.values())
    st.metric("Total Anomalies Detected", total_anomalies)
    col1, col2 = st.columns(2)
    with col1:
        anomaly_types = []
        anomaly_counts = []
        for anom_type, anom_data in anomalies.items():
            anomaly_types.append(anom_type.replace('_features', '').title())
            anomaly_counts.append(anom_data.get('anomaly_count', 0))
        if anomaly_counts:
            fig = px.bar(
                x=anomaly_types,
                y=anomaly_counts,
                title="Anomalies by Type",
                color=anomaly_counts,
                color_continuous_scale='Reds'
            )
            st.plotly_chart(fig, use_container_width=True)
    with col2:
        severity_data = []
        for anom_type, anom_data in anomalies.items():
            scores = anom_data.get('anomaly_scores', [])
            for score in scores:
                severity = 'High' if score < -0.5 else 'Medium' if score < -0.2 else 'Low'
                severity_data.append(severity)
        if severity_data:
            severity_counts = pd.Series(severity_data).value_counts()
            fig = px.pie(
                values=severity_counts.values,
                names=severity_counts.index,
                title="Anomaly Severity Distribution"
            )
            st.plotly_chart(fig, use_container_width=True)

def main():
    st.set_page_config(
        page_title="Capture the Lag",
        page_icon="🚩",
        layout="wide"
    )
    if 'analysis_running' not in st.session_state:
        st.session_state.analysis_running = False
    st.title("🚩 Advanced PCAP Analysis Tool for Exchange Trading")
    st.markdown(":red[Capture The Lag] provides you with a comprehensive network packet analysis with AI-powered insights.")
    st.sidebar.header("⚙️ Configuration")
    analyzer = StreamlitPCAPAnalyzer()
    analysis_mode = st.sidebar.radio(
        "Analysis Mode",
        ["Single File Analysis", "Batch File Analysis"]
    )
    if analysis_mode == "Single File Analysis":
        uploaded_file = st.sidebar.file_uploader(
            "Upload PCAP File", 
            type=['pcap', 'pcapng', 'cap'],
            help="Upload a single PCAP file for detailed analysis"
        )
        use_pyshark = st.sidebar.checkbox("Use PyShark (for large files)", help="Enable for better compatibility with complex PCAP formats")
        if uploaded_file:
            with st.spinner("🔍 Analyzing PCAP file..."):
                results = analyzer.analyze_uploaded_file(uploaded_file, use_pyshark)
                if "error" in results:
                    st.error(f"❌ Analysis failed: {results['error']}")
                else:
                    tabs = st.tabs([
                        "📊 Executive Summary", 
                        "📈 Trading Analysis", 
                        "🌐 Network Analysis", 
                        "📦 Packet Analysis", 
                        "🧠 AI Analysis",
                        "🤖 AI Chat" 
                    ])
                    with tabs[0]:
                        render_executive_summary(results['executive_summary'], results['file_stats'], results['trading_stats'])
                    with tabs[1]:
                        render_trading_analytics(results['trading_stats'])
                    with tabs[2]:
                        render_network_analysis(results['network_analysis'], results['anomalies'], results['packet_analyses'])
                    with tabs[3]:
                        render_packet_analysis(results)
                    with tabs[4]:
                        render_recommendations(results['recommendations'])
                        render_llm_packet_analysis(results['packet_analyses'])
                        st.markdown("---")
                        if 'llm_session_analysis' in results:
                            render_ai_session_analysis(results['llm_session_analysis'])
                        else:
                            st.info("AI session analysis not available for this result set.")
                    with tabs[5]:
                        render_ai_chat_interface(analyzer, results)
    elif analysis_mode == "Batch File Analysis":
        st.subheader("📚 Batch File Analysis")
        uploaded_files = st.file_uploader(
            "Upload Multiple PCAP Files",
            type=['pcap', 'pcapng', 'cap'],
            accept_multiple_files=True,
            help="Upload multiple PCAP files for batch analysis"
        )
        if uploaded_files:
            if st.button("🚀 Start Batch Analysis"):
                with st.spinner("Processing batch analysis..."):
                    batch_results = analyzer.analyze_batch_files(uploaded_files)
                    st.subheader("📊 Batch Analysis Results")
                    successful_analyses = [r for r in batch_results['batch_results'] if r['success']]
                    failed_analyses = [r for r in batch_results['batch_results'] if not r['success']]
                    col1, col2, col3 = st.columns(3)
                    col1.metric("Total Files", len(uploaded_files))
                    col2.metric("Successful", len(successful_analyses))
                    col3.metric("Failed", len(failed_analyses))
                    if successful_analyses:
                        total_packets = sum(r['total_packets'] for r in successful_analyses)
                        avg_health = sum(r['health_score'] for r in successful_analyses) / len(successful_analyses)
                        total_issues = sum(r['total_issues'] for r in successful_analyses)
                        st.write("**Aggregate Statistics**")
                        col1, col2, col3 = st.columns(3)
                        col1.metric("Total Packets", f"{total_packets:,}")
                        col2.metric("Average Health Score", f"{avg_health:.1f}/100")
                        col3.metric("Total Issues", total_issues)
                        results_df = pd.DataFrame([
                            {
                                'Filename': r['filename'],
                                'Packets': r['total_packets'],
                                'Health Score': f"{r['health_score']}/100",
                                'Issues': r['total_issues'],
                                'Trading Packets': r['trading_packets']
                            }
                            for r in successful_analyses
                        ])
                        st.dataframe(results_df, hide_index=True, use_container_width=True)
                    if failed_analyses:
                        st.error("❌ Failed Analyses")
                        for failure in failed_analyses:
                            st.write(f"**{failure['filename']}**: {failure['error']}")
    with st.sidebar:
        if 'results' in locals() and 'error' not in results:
            st.header("📄 Report Generation")
            report_format = st.selectbox(
                "Report Format",
                ["HTML", "Markdown", "JSON"],
                help="Choose the output format for your report"
            )
            report_type = st.selectbox(
                "Report Type",
                ["Comprehensive", "Summary", "Both"]
            )
            if st.button("📝 Generate Report"):
                with st.spinner("Generating reports..."):
                    format_map = {"HTML": "html", "Markdown": "markdown", "JSON": "json"}
                    analyzer.report_generator.output_format = format_map[report_format]
                    if report_type in ["Comprehensive", "Both"]:
                        report_path = analyzer.report_generator.generate_comprehensive_report(
                            uploaded_file.name,
                            results['packet_analyses'],
                            results['trading_stats'],
                            results['file_stats']
                        )
                        with open(report_path, 'r', encoding='utf-8') as f:
                            report_content = f.read()
                        st.download_button(
                            f"📥 Download Comprehensive Report ({report_format})",
                            report_content,
                            file_name=f"comprehensive_report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.{format_map[report_format]}",
                            mime=f"text/{format_map[report_format]}"
                        )
                    if report_type in ["Summary", "Both"]:
                        summary_path = analyzer.report_generator.save_summary_report(
                            uploaded_file.name,
                            results['packet_analyses'],
                            results['trading_stats']
                        )
                        with open(summary_path, 'r', encoding='utf-8') as f:
                            summary_content = f.read()
                        st.download_button(
                            f"📥 Download Summary Report",
                            summary_content,
                            file_name=f"summary_report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.md",
                            mime="text/markdown"
                        )
                    st.success("✅ Reports were generated successfully.")

if __name__ == "__main__":
    main()
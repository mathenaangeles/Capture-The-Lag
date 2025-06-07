import os
import logging
import argparse
from typing import List

from pcap.llm_client import LLMClient
from pcap.packet_reader import PacketReader
from pcap.trading_analyzer import TradingAnalyzer
from pcap.report_generator import ReportGenerator

class PCAPAnalyzer:
    def __init__(self, config_path: str = "config/config.yaml"):
        self.config_path = config_path
        self.logger = self._setup_logging()
        self.packet_reader = PacketReader(config_path)
        self.llm_client = LLMClient(config_path)
        self.trading_analyzer = TradingAnalyzer(config_path)
        self.report_generator = ReportGenerator(config_path)
    
    def _setup_logging(self) -> logging.Logger:
        logger = logging.getLogger('PCAPAnalyzer')
        logger.setLevel(logging.INFO)
        handler = logging.StreamHandler()
        formatter = logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s')
        handler.setFormatter(formatter)
        logger.addHandler(handler)
        return logger

    def analyze_file(self, file_path: str, use_pyshark: bool = False) -> str:
        self.logger.info(f"Starting analysis of {file_path}")
        try:
            file_stats = self.packet_reader.get_file_statistics(file_path)
            if "error" in file_stats:
                self.logger.error(f"Failed to analyze file: {file_stats['error']}")
                return None
            packet_analyses = []
            self.trading_analyzer.reset_session_data()
            for packet_info in self.packet_reader.read_pcap_file(file_path, use_pyshark):
                trading_analysis = self.trading_analyzer.analyze_trading_packet(packet_info)
                llm_analysis = {}
                if trading_analysis['is_trading']:
                    llm_analysis = self.llm_client.analyze_packet(packet_info)
                packet_analyses.append({
                    'packet_info': packet_info,
                    'trading_analysis': trading_analysis,
                    'llm_analysis': llm_analysis
                })
            trading_stats = self.trading_analyzer.get_session_statistics()
            report_path = self.report_generator.generate_comprehensive_report(
                file_path,
                packet_analyses,
                trading_stats,
                file_stats
            )
            self.logger.info(f"Analysis complete. Report generated: {report_path}")
            return report_path
        except Exception as e:
            self.logger.error(f"Error analyzing file {file_path}: {e}")
            raise

    def analyze_directory(self, directory_path: str) -> List[str]:
        self.logger.info(f"Starting batch analysis of directory: {directory_path}")
        pcap_files = self.packet_reader.find_pcap_files(directory_path)
        if not pcap_files:
            self.logger.warning(f"No PCAP files found in {directory_path}")
            return []
        batch_results = []
        report_paths = []
        for file_path in pcap_files:
            try:
                self.logger.info(f"Processing {file_path}")
                report_path = self.analyze_file(file_path)
                if report_path:
                    report_paths.append(report_path)
                    batch_results.append({
                        'filename': os.path.basename(file_path),
                        'success': True,
                        'report_path': report_path
                    })
            except Exception as e:
                self.logger.error(f"Failed to analyze {file_path}: {e}")
                batch_results.append({
                    'filename': os.path.basename(file_path),
                    'success': False,
                    'error': str(e)
                })
        batch_report_path = self.report_generator.generate_batch_report(batch_results)
        report_paths.append(batch_report_path)
        return report_paths

def main():
    parser = argparse.ArgumentParser(description='PCAP Analysis Tool for Exchange Trading Data')
    parser.add_argument('path', help='Path to PCAP file or directory')
    parser.add_argument('--config', default='config/config.yaml', help='Path to configuration file')
    parser.add_argument('--use-pyshark', action='store_true', help='Use PyShark for packet reading')
    parser.add_argument('--output-dir', help='Custom output directory for reports')
    args = parser.parse_args()
    try:
        analyzer = PCAPAnalyzer(args.config)
        if args.output_dir:
            os.makedirs(args.output_dir, exist_ok=True)
            analyzer.report_generator.output_directory = args.output_dir
        if os.path.isfile(args.path):
            report_path = analyzer.analyze_file(args.path, args.use_pyshark)
            if report_path:
                print(f"\nAnalysis complete! Report generated: {report_path}")
        elif os.path.isdir(args.path):
            report_paths = analyzer.analyze_directory(args.path)
            if report_paths:
                print("\nBatch analysis complete! Reports generated:")
                for path in report_paths:
                    print(f"- {path}")
        else:
            print(f"Error: Path not found: {args.path}")
            return 1
        return 0
    except Exception as e:
        print(f"Error: {e}")
        return 1

if __name__ == '__main__':
    exit(main())
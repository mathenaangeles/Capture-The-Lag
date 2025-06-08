import yaml
import logging
import requests
from ollama import chat
from pydantic import BaseModel
from typing import Dict, Any, List
from urllib3.util.retry import Retry
from requests.adapters import HTTPAdapter
from azure.ai.inference import ChatCompletionsClient
from azure.core.credentials import AzureKeyCredential
from azure.ai.inference.models import SystemMessage, UserMessage

class PacketAnalysis(BaseModel):
    packet_type: str
    trading_relevance: str
    issues: List[str]
    performance_impact: str
    recommendations: List[str]

class TradingAnalysis(BaseModel):
    session_health: str
    trading_performance: str
    risk_assessment: List[str]
    recommendations: List[str]
    compliance_notes: str
    
class LLMClient:
    def __init__(self, config_path: str = "config/config.yaml"):
        with open(config_path, 'r') as file:
            self.config = yaml.safe_load(file)
        self.provider = self.config['llm']['provider']
        self.logger = logging.getLogger(__name__)
        if self.provider == "ollama":
            self.base_url = self.config['llm']['ollama']['base_url']
            self.model = self.config['llm']['ollama']['model']
            self.temperature = self.config['llm']['ollama']['temperature']
            self.max_tokens = self.config['llm']['ollama']['max_tokens']
            self.timeout = self.config['llm']['ollama'].get('timeout', 120)
            self.retry_count = self.config['llm']['ollama'].get('retry_count', 3)
            self.session = self._setup_session()
        elif self.provider == "azure":
            self.azure_client = self._init_azure_client()
    
    def _init_azure_client(self):
        azure_config = self.config['llm']['azure']
        return ChatCompletionsClient(
            endpoint=azure_config['endpoint'],
            credential=AzureKeyCredential(azure_config['api_key'])
        )
    
    def _setup_session(self):
        session = requests.Session()
        retry_strategy = Retry(
            total=self.retry_count,
            backoff_factor=1,
            status_forcelist=[429, 500, 502, 503, 504],
        )
        adapter = HTTPAdapter(max_retries=retry_strategy)
        session.mount("http://", adapter)
        session.mount("https://", adapter)
        return session
    
    def analyze_packet(self, packet_info: Dict[str, Any]) -> Dict[str, Any]:
        prompt = self._create_packet_analysis_prompt(packet_info)
        if self.provider == "ollama":
            return self._query_ollama(prompt, model_cls=PacketAnalysis)
        elif self.provider == "azure":
            return self._query_azure(prompt, model_cls=PacketAnalysis)
        else:
            raise ValueError(f"Unsupported LLM Provider: {self.provider}")
    
    def analyze_trading_session(self, session_data: Dict[str, Any]) -> Dict[str, Any]:
        prompt = self._create_trading_analysis_prompt(session_data)
        if self.provider == "ollama":
            return self._query_ollama(prompt, model_cls=TradingAnalysis)
        elif self.provider == "azure":
            return self._query_azure(prompt, model_cls=TradingAnalysis)
        else:
            raise ValueError(f"Unsupported LLM Provider: {self.provider}")
    
    def _create_packet_analysis_prompt(self, packet_info: Dict[str, Any]) -> str:
        return f"""
            You are an expert network and trading systems analyst. Analyze the following packet data and provide insights:
            Packet Information:
            - Source IP: {packet_info.get('src_ip', 'N/A')}
            - Destination IP: {packet_info.get('dst_ip', 'N/A')}
            - Protocol: {packet_info.get('protocol', 'N/A')}
            - Source Port: {packet_info.get('src_port', 'N/A')}
            - Destination Port: {packet_info.get('dst_port', 'N/A')}
            - Payload Size: {packet_info.get('payload_size', 0)} bytes
            - Timestamp: {packet_info.get('timestamp', 'N/A')}
            - TCP Flags: {packet_info.get('tcp_flags', 'N/A')}
            - Sequence Number: {packet_info.get('seq_num', 'N/A')}
            - Acknowledgment Number: {packet_info.get('ack_num', 'N/A')}
            Payload: {packet_info.get('payload', 'No payload')}

            Please analyze this packet and provide:
            1. **Packet Type**: What kind of packet this is (TCP handshake, data transfer, etc.)
            2. **Trading Relevance**: If this appears to be trading-related traffic
            3. **Potential Issues**: Any anomalies, retransmissions, or problems detected
            4. **Performance Impact**: Impact on trading latency or reliability
            5. **Recommended Actions**: Specific troubleshooting steps if issues are found

            Return ONLY valid JSON with these fields: packet_type, trading_relevance, issues, performance_impact, recommendations.
            """

    def _create_trading_analysis_prompt(self, session_data: Dict[str, Any]) -> str:
        return f"""
            You are an expert trading systems analyst. Analyze this trading session data:

            Session Statistics:
            - Total Packets: {session_data.get('total_packets', 0)}
            - Duration: {session_data.get('duration', 'N/A')}
            - Average Latency: {session_data.get('avg_latency', 'N/A')}
            - Packet Loss: {session_data.get('packet_loss', 0)}%
            - Retransmissions: {session_data.get('retransmissions', 0)}
            - Protocol Distribution: {session_data.get('protocols', {})}

            Trading Specific Data:
            - Order Messages: {session_data.get('order_messages', 0)}
            - Execution Messages: {session_data.get('execution_messages', 0)}
            - Rejected Orders: {session_data.get('rejected_orders', 0)}
            - Cancel Messages: {session_data.get('cancel_messages', 0)}
            - FIX Messages: {session_data.get('fix_messages', 0)}
            - ITCH Messages: {session_data.get('itch_messages', 0)}

            Provide comprehensive analysis including:
            1. **Session Health**: Overall assessment of connection quality
            2. **Trading Performance**: Analysis of order execution efficiency
            3. **Risk Assessment**: Potential issues that could impact trading
            4. **Optimization Recommendations**: Specific improvements suggested
            5. **Compliance Notes**: Any regulatory or risk management concerns

            Return ONLY valid JSON with these fields: session_health, trading_performance, risk_assessment, recommendations, compliance_notes.
            """

    def _query_ollama(self, prompt: str,  model_cls: type[BaseModel] = None):
        try:
            kwargs = {
                "messages": [{"role": "user", "content": prompt}],
                "model": self.model,
                "options": {
                    "temperature": self.temperature,
                    "num_predict": self.max_tokens
                }
            }
            if model_cls:
                kwargs["format"] = model_cls.model_json_schema()
            response = chat(**kwargs)
            content = response['message']['content']
            if model_cls:
                try:
                    return model_cls.model_validate_json(content).model_dump()
                except Exception as e:
                    self.logger.error(f"Ollama Validation Error: {str(e)}")
                    return None
            return content
        except Exception as e:
            self.logger.error(f"Ollama Error: {str(e)}")
            return None
    
    def _query_azure(self, prompt: str, model_cls: type[BaseModel] = None):
        try:
            azure_config = self.config['llm']['azure']
            response = self.azure_client.complete(
                messages=[
                    SystemMessage(content="You are an expert network and trading systems analyst."),
                    UserMessage(content=prompt)
                ],
                model=azure_config['model'],
                temperature=azure_config['temperature'],
                max_tokens=azure_config['max_tokens']
            )
            content = response.choices[0].message.content
            if model_cls:
                try:
                    return model_cls.model_validate_json(content).model_dump()
                except Exception as e:
                    self.logger.error(f"Azure Validation Error: {str(e)}")
                    return None
            return content
        except Exception as e:
            self.logger.error(f"Azure Error: {str(e)}")
            return None
    
    def chat_query(self, message: str, context: str = "") -> str:
        prompt = f"""
        Context: {context}

        User Question: {message}
        
        As a network and trading systems expert, provide a helpful and detailed response.
        """
        if self.provider == "ollama":
            result = self._query_ollama(prompt)
        elif self.provider == "azure":
            result = self._query_azure(prompt)
        return str(result) if result else "The LLM is currently unavailable. Please try again."

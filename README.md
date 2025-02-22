# 🛡️ Network Security AI Agent

An autonomous SOC analyst that continuously monitors network traffic, detects attacks in real-time using lightweight ML + LLM reasoning, and automatically responds by blocking malicious IPs.

![License](https://img.shields.io/badge/license-MIT-blue?style=flat-square)
![Python](https://img.shields.io/badge/python-3.11+-green?style=flat-square)

## 🎯 Features

- **🤖 Autonomous Detection**: Isolation Forest + MITRE ATT&CK RAG
- **⚡ Real-Time Analysis**: Live network interface capture or batch pcap processing
- **🎯 Intelligent Response**: Auto-block IPs, send alerts to Slack/webhooks, log incidents
- **📊 Interactive Dashboard**: Streamlit UI with threat visualization and AI reasoning
- **🔗 MITRE ATT&CK Mapping**: Correlates detections to real attack techniques
- **📦 Production Ready**: Docker containerized, fully tested, MIT licensed
- **⚙️ Zero-Config Start**: Works out-of-the-box with CIC-IDS2017 pcaps

## 📋 Quick Start

### Prerequisites

- Python 3.11+
- Linux/macOS (iptables support)
- Docker (optional)

### Installation

```bash
# Clone repository
git clone https://github.com/MuthoniGathiithi/Network-Security-AI-agent.git
cd Network-Security-AI-agent

# Install dependencies
pip install -r requirements.txt

# Run demo
bash scripts/demo.sh
```

### Run Dashboard

```bash
streamlit run dashboards/app.py
```

Visit `http://localhost:8501` in your browser.

### Analyze PCAP File

```bash
python3 << 'EOF'
from src.orchestrator import SOCAgent

# Initialize agent
soc = SOCAgent(dry_run=True)

# Train on benign traffic (optional)
soc.train_on_benign_traffic("path/to/benign.pcap")

# Analyze attack traffic
results = soc.analyze_pcap("path/to/attack.pcap", auto_block_critical=False)

print(f"Flows analyzed: {results['flows_analyzed']}")
print(f"Threats detected: {results['threats_detected']}")

# Export results
soc.export_results("results.json")
EOF
```

## 🏗️ Architecture

```
Packet Capture Layer (Scapy live capture or PCAP reading)
              ↓
Flow Aggregation Engine (NetFlow-style feature extraction)
              ↓
    ┌─────────┴─────────┐
    ↓                   ↓
Detection Agent      Response Agent
(ML + MITRE RAG)     (Playbooks)
    ↓                   ↓
    └─────────┬─────────┘
              ↓
  ┌───────────┼───────────┐
  ↓           ↓           ↓
iptables  Slack/Webhook  Logging
```

## 🔧 Core Components

### Detection Agent (`src/detection_agent.py`)

Analyzes network flows using:

- **ML Models**: Isolation Forest for unsupervised anomaly detection
- **Feature Extraction**: 60+ NetFlow metrics
- **MITRE ATT&CK Mapping**: Maps behaviors to real attack techniques

**Threat Classification**:
- Port Scan (T1046)
- DDoS (T1498, T1499)
- Data Exfiltration (T1041)
- Reverse Shell (T1571, T1090)
- Brute Force (T1110)

### Response Agent (`src/response_agent.py`)

Executes automated playbooks:

- **IP Blocking**: Uses iptables to block malicious IPs
- **Alerts**: Sends to Slack, webhooks, or custom endpoints
- **Logging**: Records all incidents for audit trail
- **Dry-run Mode**: Test without executing actual blocks

### Packet Capture (`src/packet_capture.py`)

Flexible input handling:

- **Live Capture**: Monitor real network interfaces
- **PCAP Files**: Process recorded traffic
- **Flow Aggregation**: Bidirectional flow reconstruction
- **Feature Extraction**: Converts packets to ML-ready features

### Orchestrator (`src/orchestrator.py`)

Coordinates all components with unified analysis pipeline.

## 📊 Dashboard Features

### Real-Time Monitoring
- Threat timeline and statistics
- Live detection feed with severity indicators
- Automated response tracking

### AI Reasoning Explanations
- View detailed reasoning for each detection
- MITRE ATT&CK technique mapping
- Confidence scores and ML metrics

### Security Operations
- Current blocklist management
- Alert configuration
- Detection threshold tuning

## 💾 Sample Datasets

### CIC-IDS2017
Download: https://www.unb.ca/cic/datasets/ids-2017.html

### Malware-Traffic-Classification
Download: https://www.malware-traffic-analysis.net/

## 🚀 Deployment

### Docker

```bash
# Build image
docker build -f docker/Dockerfile -t network-security-ai-agent .

# Run dashboard
docker run -p 8501:8501 network-security-ai-agent

# With docker-compose
docker-compose -f docker/docker-compose.yml up
```

### Configuration

Set environment variables:

```bash
export DRY_RUN=false
export AUTO_BLOCK_CRITICAL=true
export SLACK_WEBHOOK_URL="https://hooks.slack.com/..."
export LOG_LEVEL=INFO
```

## 🧠 ML Model Details

### Isolation Forest
- **Input**: 60 NetFlow features
- **Algorithm**: Unsupervised anomaly detection
- **Contamination**: 10% expected anomalies

### Feature Engineering
- Packet count statistics (forward/backward)
- Packet length metrics (min/max/mean/std)
- Inter-arrival times and flow duration
- TCP/UDP flags aggregation

## 🎯 MITRE ATT&CK Framework Integration

| Detection | MITRE Technique | Tactic |
|-----------|-----------------|--------|
| Port Scan | T1046 | Discovery |
| DDoS | T1498, T1499 | Impact |
| Data Exfil | T1041, T1020 | Exfiltration |
| Reverse Shell | T1571, T1090 | C2 |
| Brute Force | T1110, T1021 | Credential Access |

## 📝 API Reference

### SOCAgent

```python
from src.orchestrator import SOCAgent

soc = SOCAgent(dry_run=False, slack_webhook="...")
soc.train_on_benign_traffic("benign.pcap")
results = soc.analyze_pcap("attack.pcap", auto_block_critical=True)
data = soc.get_dashboard_data()
soc.export_results("results.json")
```

### DetectionAgent

```python
from src.detection_agent import DetectionAgent, FlowFeatures

agent = DetectionAgent()
agent.train(training_data)
detection = agent.detect(flow_features, src_ip, dst_ip)
```

### ResponseAgent

```python
from src.response_agent import ResponseAgent

agent = ResponseAgent(dry_run=False, slack_webhook="...")
actions = agent.respond_to_detection(detection_result)
blocklist = agent.get_blocklist()
```

## ✅ Testing

```bash
# Run all tests
pytest tests/ -v

# With coverage
pytest tests/ --cov=src --cov-report=html
```

## 🎬 Demo

```bash
bash scripts/demo.sh
```

Demonstrates:
1. Model initialization and training
2. Detection of simulated reverse shell
3. AI reasoning generation
4. MITRE ATT&CK mapping
5. Automated response execution

## 🔐 Security Notes

- Run with `dry_run=True` to test without blocking
- Requires root for iptables blocking
- IPs tracked in `/tmp/threat_intelligence_blocklist.txt`
- All actions logged for audit trail

## 📄 License

MIT License - See LICENSE file for details

## 👨‍💻 Author

Created by [Muthoni Gathiithi](https://github.com/MuthoniGathiithi)

## ⭐ Support

If this project helps you, please consider starring this repository!

---

**Built with ❤️ for the cybersecurity community**

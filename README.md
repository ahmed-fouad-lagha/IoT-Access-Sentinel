# IoT-Access-Sentinel

**Autonomous Context-Aware Access Control for IoT via Multi-Agent Generative AI**

[![License](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)
[![Python](https://img.shields.io/badge/python-3.9+-blue.svg)](https://www.python.org/downloads/)

---

## 🎯 Overview

**IoT-Access-Sentinel** is a novel cybersecurity framework that addresses the **Access Management (M0801)** research gap by using **Large Language Models (LLMs)** to actively enforce IoT authorization policies based on dynamic context, rather than static firewall rules.

### The Research Gap

> **Current State**: Generative AI applications in IoT security focus on *passive* detection (IDS) or vulnerability scanning.
>
> **Our Innovation**: Active authorization enforcement using multi-agent LLMs that analyze behavioral context (time, device type, connection frequency) to make ALLOW/DENY decisions in real-time.

### Architecture

```
┌─────────────────┐       ┌──────────────────┐       ┌─────────────────┐
│    Observer     │──────▶│ Decision Engine  │──────▶│    Enforcer     │
│ (Wazuh Client)  │       │  (Multi-Agent    │       │ (Active         │
│                 │       │   LLM Pipeline)  │       │  Response)      │
└─────────────────┘       └──────────────────┘       └─────────────────┘
      ▲                           │                           │
      │                           │                           ▼
 IoT Access                 ┌─────┴─────┐              Firewall Rules
   Alerts                   │  Policy   │              Device Isolation
                            │   Agent   │              Rate Limiting
                            ├───────────┤
                            │  Context  │
                            │   Agent   │
                            └───────────┘
```

**Workflow:**

1. **Observer**: Monitors IoT access events via Wazuh SIEM integration
2. **Decision Engine**: Analyzes context using Policy Agent (rule interpretation) + Context Agent (behavioral analysis)
3. **Enforcer**: Executes active responses (block IP, isolate device, rate limit)

---

## 🧬 External Repository Integration

This project leverages patterns from 5 open-source cybersecurity projects (located in `external_repos/`):

| Repository | Role | What We Borrowed |
|------------|------|------------------|
| **AI_SOC** | Infrastructure | Wazuh integration (`wazuh_client.py`), FastAPI webhook pattern, structured logging |
| **cyber-security-llm-agents (NVISO)** | Logic | AutoGen multi-agent framework (`ConversableAgent`), coordinator+specialist pattern |
| **attackgen** | Training (*future*) | Synthetic log generation for model fine-tuning |
| **PentestGPT** | Red Team (*future*) | Attack patterns to validate enforcement |
| **ChatAFL** | Red Team (*future*) | Fuzzing techniques for testing |

📖 See [`implementation_plan.md`](/.gemini/antigravity/brain/396caa09-0cf4-4e2f-8672-eb2003e7f38f/implementation_plan.md) for detailed pattern analysis.

---

## 📁 Project Structure

```
IoT-Access-Sentinel/
├── config/
│   ├── settings.py              # Pydantic settings (Wazuh, LLM, enforcement)
│   └── access_policies.yaml     # IoT access policy definitions
│
├── observer/                     # Wazuh Integration (from AI_SOC)
│   ├── wazuh_connector.py       # JWT auth + alert polling
│   └── models.py                # IoT access alert models
│
├── decision_engine/              # LLM Multi-Agent Logic (from NVISO)
│   ├── agents/
│   │   ├── policy_agent.py      # Interprets access policies
│   │   └── context_agent.py     # Analyzes device behavior
│   ├── decision_pipeline.py     # Orchestrates agents
│   └── llm_client.py            # LLM API wrapper
│
├── enforcer/                     # Active Response (Novel)
│   └── actions.py               # Block IP, isolate device, rate limit
│
├── common/
│   ├── schemas.py               # Shared data models
│   └── logging_config.py        # Structured logging (structlog)
│
├── main.py                       # FastAPI entry point
├── requirements.txt
├── .env.example
└── README.md
```

---

## 🚀 Quick Start

### Prerequisites

- Python 3.9+
- Wazuh Manager (running instance or Docker)
- LLM API Key (OpenAI/Gemini/Ollama)

### Installation

1. **Clone the repository:**
   ```bash
   cd /home/lagha/repo/IoT-Access-Sentinel
   ```

2. **Create virtual environment:**
   ```bash
   python3 -m venv venv
   source venv/bin/activate  # On Windows: venv\Scripts\activate
   ```

3. **Install dependencies:**
   ```bash
   pip install -r requirements.txt
   ```

4. **Configure environment:**
   ```bash
   cp .env.example .env
   nano .env  # Edit with your credentials
   ```

   **Required settings:**
   ```env
   WAZUH_MANAGER_URL=https://your-wazuh-manager:55000
   WAZUH_USERNAME=wazuh-wui
   WAZUH_PASSWORD=your-password
   
   LLM_PROVIDER=openai
   OPENAI_API_KEY=sk-your-key-here
   ```

5. **Review access policies:**
   ```bash
   nano config/access_policies.yaml
   ```

### Running the Service

**Development mode (with hot reload):**
```bash
python main.py
```

**Production mode (with Uvicorn):**
```bash
uvicorn main:app --host 0.0.0.0 --port 8000
```

**Access the API:**
- **Interactive Docs**: http://localhost:8000/docs
- **Health Check**: http://localhost:8000/health
- **Service Info**: http://localhost:8000/

---

## 🧪 Usage Examples

### 1. Process an IoT Access Alert (Webhook)

**Endpoint:** `POST /access-control`

```bash
curl -X POST "http://localhost:8000/access-control" \
  -H "Content-Type: application/json" \
  -d '{
    "id": "alert-12345",
    "timestamp": "2025-12-23T12:00:00Z",
    "rule": {
      "level": 8,
      "description": "IoT device connection attempt"
    },
    "device_type": "camera",
    "source_ip": "192.168.1.100",
    "destination_ip": "10.0.0.1",
    "destination_port": 443
  }'
```

**Response:**
```json
{
  "id": "alert-12345",
  "decision_action": "DENY",
  "decision_confidence": 0.95,
  "decision_reason": "Connection attempt outside allowed hours (09:00-17:00)",
  "enforcement_action": "BLOCK_IP",
  "enforcement_executed": true,
  "processing_timestamp": "2025-12-23T12:00:05Z"
}
```

### 2. Fetch and Analyze Recent Alerts

**Endpoint:** `GET /alerts`

```bash
curl "http://localhost:8000/alerts?limit=5&time_range=1h"
```

---

## ⚙️ Configuration

### Access Policies (`config/access_policies.yaml`)

Define time-based, network-based, and behavioral rules:

```yaml
policies:
  - device_type: camera
    description: "Security cameras - business hours only"
    allowed_hours: "09:00-17:00"
    allowed_days: ["Monday", "Tuesday", "Wednesday", "Thursday", "Friday"]
    max_connections_per_hour: 10
    allowed_source_networks:
      - "192.168.1.0/24"
```

### Environment Variables (`.env`)

| Variable | Description | Example |
|----------|-------------|---------|
| `WAZUH_MANAGER_URL` | Wazuh Manager API endpoint | `https://wazuh:55000` |
| `WAZUH_USERNAME` | Wazuh API username | `wazuh-wui` |
| `WAZUH_PASSWORD` | Wazuh API password | `your-password` |
| `LLM_PROVIDER` | LLM provider (`openai`/`gemini`/`ollama`) | `openai` |
| `OPENAI_API_KEY` | OpenAI API key (if using OpenAI) | `sk-...` |
| `ENFORCEMENT_ENABLED` | Enable/disable enforcement (dry-run mode) | `true` |
| `MIN_DECISION_CONFIDENCE` | Minimum confidence to enforce DENY | `0.75` |

---

## 🔬 Research Context

### The "Why" - Verified Research Gap

**MITRE ATT&CK Framework Gap Analysis** (M0801 - Access Management):
- Existing GenAI solutions: Passive detection only (IDS, vulnerability scanning)
- **Our contribution**: Active, context-aware authorization enforcement

### Key Differentiators

1. **Dynamic Context Analysis**:
   - Temporal (time of day, day of week)
   - Behavioral (connection frequency, protocol anomalies)
   - Device-specific (camera vs. sensor rules)

2. **Multi-Agent Decision Making**:
   - **Policy Agent**: Interprets human-readable policies
   - **Context Agent**: Detects behavioral anomalies
   - **Coordinator**: Combines outputs for final decision

3. **Active Enforcement**:
   - Real-time firewall rule updates
   - Device isolation (VLAN assignment)
   - Rate limiting

### Future Work

- [ ] **Synthetic Data Generation** (using `attackgen` patterns)
- [ ] **Red Team Evaluation** (using `PentestGPT` + `ChatAFL`)
- [ ] **Model Fine-Tuning** on IoT-specific access logs
- [ ] **Federated Learning** for distributed edge deployments

---

## 🛡️ Security Considerations

### Dry-Run Mode

By default, enforcement actions are **logged but not executed**. To enable enforcement:

```env
ENFORCEMENT_ENABLED=true
```

### Production Deployment

1. **SSL/TLS**: Set `WAZUH_VERIFY_SSL=true` with valid certificates
2. **API Authentication**: Add FastAPI authentication middleware
3. **Rate Limiting**: Configure request rate limits
4. **Audit Logging**: All decisions are logged via `structlog` (JSON format)

---

## 📊 Testing

### Run Unit Tests

```bash
pytest tests/ -v
```

### Test LLM Connectivity

```bash
python -c "from decision_engine.llm_client import test_llm_connection; from config.settings import get_settings; import asyncio; asyncio.run(test_llm_connection(get_settings()))"
```

### Test Wazuh Connection

```bash
curl http://localhost:8000/health
```

---

## 🤝 Contributing

This is a research prototype. Contributions are welcome:

1. Fork the repository
2. Create a feature branch
3. Submit a pull request

---

## 📜 License

This project is licensed under the MIT License. See `LICENSE` for details.

---

## 🙏 Acknowledgements

This research leverages the following open-source projects:

- **AI_SOC** - Wazuh-AI integration patterns
- **cyber-security-llm-agents (NVISO)** - AutoGen multi-agent framework
- **Wazuh** - Open-source SIEM platform
- **Microsoft AutoGen** - Multi-agent orchestration
- **FastAPI** - Modern Python web framework

---

## 📚 References

### External Repositories (in `external_repos/`)

1. [AI_SOC](https://github.com/socfortress/AI-SOC) - Wazuh integration patterns
2. [cyber-security-llm-agents](https://github.com/NVISOsecurity/cyber-security-llm-agents) - NVISO AutoGen framework
3. [attackgen](https://github.com/mrwadams/attackgen) - Synthetic incident generation
4. [PentestGPT](https://github.com/GreyDGL/PentestGPT) - LLM-powered penetration testing
5. [ChatAFL](https://github.com/ChatAFL/ChatAFL) - LLM-guided fuzzing

### Research Papers

*(To be added as research progresses)*

---

## 📧 Contact

For research inquiries or collaboration:

- **Researcher**: Ahmed Fouad Lagha
- **Institution**: Eötvös Loránd University
- **Email**: ahmed.lagha@inf.elte.hu

---

**Status**: 🚧 **Research Prototype** - Not yet production-ready. Active development in progress.

**Version**: 0.1.0 (Initial Scaffold)

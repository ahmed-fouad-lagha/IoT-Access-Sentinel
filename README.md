# IoT-Access-Sentinel

<div align="center">
  <img src="assets/sentinel_architecture.png" alt="Sentinel Architecture" width="600"/>

  **Autonomous Context-Aware Access Control for IoT via Multi-Agent Generative AI**

</div>

[![License](https://img.shields.io/badge/license-Apache%202.0-blue.svg)](LICENSE)
[![Python](https://img.shields.io/badge/python-3.9+-blue.svg)](https://www.python.org/downloads/)
[![Docker](https://img.shields.io/badge/docker-ready-blue.svg)](#-one-command-deployment)

---

## Overview

**IoT-Access-Sentinel** is a novel cybersecurity framework that addresses the **Access Management (M0801)** research gap by using a **Hybrid Architecture** (Deterministic Validation + LLM Reasoning) to actively enforce IoT authorization policies based on dynamic context.

### Key Achievement
In a comprehensive evaluation across **103 test scenarios** against a fair RBAC baseline with proper authentication, the Hybrid LLM system achieved **94.2% accuracy** (97/103 correct), representing a **+16.5% improvement** over the RBAC baseline's 77.7% (80/103), with high statistical significance (McNemar's **χ² = 9.0, p < 0.01**).

### Hybrid Architecture (M0801)

Sentinel specifically addresses the MITRE M0801 gap (User Identification & Verification) by bridging the semantic gap between high-level policies and low-level logs.

```mermaid
graph TD
    A[Wazuh Alert] --> B{Step 0: User Auth}
    B -- Unauthorized --> C[DENY - Fast Path]
    B -- Authorized --> D[Step 1: LLM Context Analysis]
    D --> E[Step 2: LLM Policy Decision]
    E --> F{Decision}
    F -- DENY --> G[Wazuh Active Response]
    F -- ALLOW --> H[Permit Access]
    G --> I[Remote IP Block]
```

1.  **Deterministic Layer**: Sub-millisecond Python validation for security-critical checks (tokens, user->device IDs).
2.  **Generative Layer**: Multi-agent LLM reasoning (Llama 3.3 70B via Groq) for complex behavioral analysis.
3.  **Enforcement Layer**: Real-time remote enforcement via Wazuh Active Response API.


### Hybrid Multi-Agent Access Control Pipeline

```mermaid
graph TD
    subgraph "External IoT Environment"
        IoT_Device[IoT Device]
        Hacker[Attacker]
    end

    subgraph "Wazuh Security Platform"
        Wazuh_Agent[Wazuh Agent]
        Wazuh_Manager[Wazuh Manager]
        Wazuh_DB[(Alert DB)]
        AR_Module[Active Response]
    end

    subgraph "IoT-Access-Sentinel"
        Observer[Observer Module]
        
        subgraph "Decision Engine (Hybrid)"
            Validator{Deterministic\nValidator}
            
            subgraph "LLM Layer"
                Policy_Ag[Policy Agent]
                Context_Ag[Context Agent]
                LLM_API[LLM Inference API]
            end
        end
        
        Enforcer[Enforcer Module]
        Metrics[Prometheus Metrics]
    end

    %% Data Flow
    IoT_Device -->|Network Traffic| Wazuh_Agent
    Hacker -->|Malicious Traffic| Wazuh_Agent
    
    Wazuh_Agent -->|Log Events| Wazuh_Manager
    Wazuh_Manager -->|Alert JSON| Observer
    
    Observer -->|Raw Alert| Validator
    
    %% Decision Logic
    Validator -->|Pass Low Risk| Enforcer
    Validator -->|"Deny (Fail-Secure)"| Enforcer
    Validator -->|Ambiguous| Context_Ag
    
    Context_Ag -->|Context Data| Policy_Ag
    Policy_Ag <-->|"Prompt/Completion"| LLM_API
    Policy_Ag -->|Final Decision| Enforcer
    
    %% Enforcement
    Enforcer -->|Action JSON| AR_Module
    AR_Module -->|Block IP| Wazuh_Agent
    
    %% Monitoring
    Observer -.-> Metrics
    Enforcer -.-> Metrics
    
    classDef secure fill:#e1f5fe,stroke:#01579b,stroke-width:2px;
    classDef attack fill:#ffebee,stroke:#b71c1c,stroke-width:2px;
    classDef ai fill:#f3e5f5,stroke:#4a148c,stroke-width:2px;
    
    class Validator,Enforcer secure;
    class Hacker attack;
    class Policy_Ag,Context_Ag,LLM_API ai;
```

### Detailed Decision Flow

```mermaid
sequenceDiagram
    participant W as Wazuh Manager
    participant V as Deterministic Validator
    participant C as Context Agent
    participant P as Policy Agent
    participant E as Enforcer
    
    W->>V: POST /access-control (Alert JSON)
    
    Note over V: Fast Path (~1ms)
    alt Invalid User Token
        V->>E: Deny (Invalid Auth)
    else Recognized Attack Pattern
        V->>E: Deny (Injection)
    else Ambiguous Context
        V->>C: Request Analysis
        
        Note over C,P: Slow Path (~150ms)
        C->>C: Retrieve Device History
        C->>P: Context+Policy Prompt
        P->>P: Zero-Trust Evaluation
        P->>E: Allow/Deny Decision
    end
    
    E->>W: Enriched Alert + Action
    
    opt If Action = BLOCK
        E->>W: PUT /active-response
    end
```

## One-Command Deployment

The entire stack (Wazuh Manager + Sentinel AI Engine) can be started with a single command:

```bash
docker-compose up -d
```

| Service | Port | Description |
|---------|------|-------------|
| **Sentinel API** | `8000` | AI Decision Engine Webhook |
| **Wazuh Dashboard** | `443` | Security Management UI |
| **Wazuh Manager** | `55000` | Rest API for Active Response |

## Monitoring & Observability

### Prometheus Metrics
The system exposes standard Prometheus metrics at `/metrics`. Key metrics include:
- `sentinel_decisions_total`: Counter for ALLOW/DENY decisions (labeled by category/path).
- `sentinel_llm_cost_dollars`: Estimated LLM inference cost.
- `sentinel_latency_seconds`: End-to-end request latency distribution.
- `sentinel_active_requests`: Real-time concurrent request gauge.

### API Documentation
Interactive API documentation (Swagger UI) is available at:
- **Swagger UI**: `http://localhost:8000/docs`
- **ReDoc**: `http://localhost:8000/redoc`

### Rate Limiting
Built-in sliding window rate limiter protects against DoS and abuse:
- **Default policy**: 100 req/min/IP
- **LLM Endpoints**: Stricter limits (e.g., 20/min) for expensive inference calls.
- **Headers**: Responses include `X-RateLimit-Limit` and `X-RateLimit-Remaining`.

## Testing & Validation

Detailed performance metrics from Phase 4 Evaluation:

| Metric | Result |
|--------|--------|
| **Accuracy (Hybrid LLM)** | **82.1%** |
| **Accuracy (Static Baseline)** | 64.2% |
| **Improvement** | **+17.9% (p < 0.01)** |
| **Latency (Avg)** | **97ms** |
| **Throughput** | **31.5 RPS** |
| **Resource Usage** | **94 MB Memory** |

### Category Breakdown
*   **User Authorization**: +43.5% improvement over baseline.
*   **Attack Scenarios**: +83.3% improvement (100% detection of injection/evasion/confusion).
*   **Time/Network Logic**: Tied at 87.5%.

---

## Project Structure

```
IoT-Access-Sentinel/
├── docker-compose.yml           # Master Stack Orchestration
├── Dockerfile                   # Sentinel App Containerization
├── config/
│   ├── settings.py              # Pydantic Configuration
│   └── access_policies.yaml     # Human-Readable IoT Policies
├── decision_engine/             # Hybrid Decision Intelligence
│   ├── validators/              # Deterministic Path (M0801)
│   ├── agents/                  # LLM Specialists (Policy + Context)
│   └── decision_pipeline.py     # Pipeline Orchestrator
├── enforcer/                    # Active Response Integration
│   └── actions.py               # Remote IP blocking via Wazuh API
├── main.py                      # FastAPI Webhook Endpoint
└── tests/                       # 103 benchmark scenarios
```

## Configuration

### 1. Environment (`.env`)
```bash
ENFORCEMENT_ENABLED=true      # Enable real remote blocking
LLM_MODEL=llama-3.3-70b-versatile
OPENAI_BASE_URL=https://api.groq.com/openai/v1
```

### 2. Access Policies (`access_policies.yaml`)
Define your IoT landscape in natural language style:
```yaml
policies:
  - device_type: camera
    require_authentication: true
    allowed_users:
      - user_id: "alice@company.com"
        allowed_devices: ["camera-office-01"]
    allowed_hours: "09:00-17:00"
```

## Research Significance

This project provides the first quantitative evidence that **Hybrid LLM Architectures** solve the M0801 gap more effectively than rule-based systems. It demonstrates that combining **deterministic security** with **generative reasoning** achieves both trustworthiness and flexibility.

## Future Work

### Domain-Specific LLM Fine-Tuning
While the current system leverages **zero-shot general-purpose LLMs** (demonstrating broad generalizability), fine-tuning domain-specific models could yield several benefits:

**Potential Improvements:**
- **Reduced Latency**: Smaller fine-tuned models (e.g., Llama 3 8B) could achieve sub-50ms inference times vs current ~150ms
- **Lower Operational Costs**: On-premise deployment eliminates API costs (~$0.01/request → $0.00)
- **Enhanced Privacy**: Eliminates external API dependencies for sensitive IoT environments
- **Improved Accuracy**: Specialized training on IoT-specific threat patterns (prompt injection, device impersonation, policy evasion)

**Dataset Requirements:**
- 10,000+ labeled IoT access scenarios
- Representative attack vectors (semantic injection, time-based bypasses)
- Diverse policy violation examples
- Real-world edge cases from production deployments

**Research Questions:**
1. Can a 7B parameter fine-tuned model match GPT-4's 82.1% accuracy?
2. What is the optimal training data composition for IoT threat detection?
3. How does model size affect the accuracy-latency tradeoff in real-time access control?

## License

Apache License. see [LICENSE](./LICENSE).
---
title: IoT Access Sentinel
emoji: 🛡️
colorFrom: blue
colorTo: indigo
sdk: gradio
sdk_version: 6.29.1
app_file: app.py
pinned: false
---

# IoT-Access-Sentinel

<div align="center">

**Autonomous Context-Aware Access Control for IoT via Multi-Agent Generative AI**

[![ITAT 2026](https://img.shields.io/badge/ITAT%202026-Accepted-brightgreen.svg)](https://itat.ics.upjs.sk)
[![Hugging Face Spaces](https://img.shields.io/badge/%F0%9F%A4%97%20Hugging%20Face-Live%20Demo-blue.svg)](https://huggingface.co/spaces/ahmed-fouad-lagha/IoT-Access-Sentinel)
[![CI Tests](https://github.com/ahmed-fouad-lagha/IoT-Access-Sentinel/actions/workflows/ci.yml/badge.svg)](https://github.com/ahmed-fouad-lagha/IoT-Access-Sentinel/actions/workflows/ci.yml)
[![Python](https://img.shields.io/badge/python-3.10%2B-blue.svg)](https://www.python.org/downloads/)
[![License](https://img.shields.io/badge/license-Apache%202.0-blue.svg)](LICENSE)
[![Docker](https://img.shields.io/badge/docker-ready-blue.svg)](#-docker-deployment)

<p align="center">
  <a href="https://huggingface.co/spaces/ahmed-fouad-lagha/IoT-Access-Sentinel"><strong>🚀 Try the Live Interactive Demo »</strong></a>
  •
  <a href="#-key-results--benchmarks"><strong>View Benchmarks »</strong></a>
  •
  <a href="#-quick-start"><strong>Quick Start »</strong></a>
  •
  <a href="#-api-documentation"><strong>API Docs »</strong></a>
</p>

</div>

---

### 🌟 Live Interactive Demo

Experience **IoT-Access-Sentinel** in real time on **Hugging Face Spaces**:
👉 **[huggingface.co/spaces/ahmed-fouad-lagha/IoT-Access-Sentinel](https://huggingface.co/spaces/ahmed-fouad-lagha/IoT-Access-Sentinel)**

Test legitimate access requests, detect adversarial attacks (Unicode RTLO evasion, metadata smuggling, prompt injections), and inspect real-time Layer 0 and Layer 1 decision breakdowns without installing any local dependencies.

---

## 📌 Overview

**IoT-Access-Sentinel** is an autonomous, hybrid zero-trust access control framework tailored for Edge IoT networks. It bridges the semantic gap between low-level telemetry logs and high-level organizational security policies, specifically addressing the **MITRE ATT&CK Access Management (M0801)** gap (*User Identification & Verification*).

Sentinel integrates a deterministic micro-firewall validation pre-filter (**Layer 0**) with multi-agent Large Language Model reasoning (**Layer 1**) into a unified runtime authorization pipeline.

![Hybrid Architecture](https://raw.githubusercontent.com/ahmed-fouad-lagha/IoT-Access-Sentinel/master/assets/hybrid-architecture.png)

<div align="center">
  <sub>Figure 1: High-level architectural pipeline of the IoT-Access-Sentinel framework.</sub>
</div>

---

## ⚙️ Architecture & Decision Pipeline

Sentinel enforces zero-trust authorization policies using a hybrid **Observe → Decide → Act** pipeline:

```mermaid
graph TD
    subgraph Observe [1. Observe]
        Wazuh[Wazuh Agent/SIEM Manager] -->|Access Log Alert| API[FastAPI Webhook: /access-control]
    end

    subgraph Decide [2. Decide: Hybrid Decision Engine]
        API --> L0[Layer 0: Deterministic Validator]
        
        %% Layer 0
        L0 -->|Input Normalization| Sanitizer[NFKC Normalizer & RTLO Stripper]
        L0 -->|Auth Token Verification| JWT[Cryptographic JWT Validator]
        L0 -->|Static Rules| Rules[CIDR Subnet & Time Boundary Checks]
        
        Sanitizer --> L0_Check{Authorization Valid?}
        JWT --> L0_Check
        Rules --> L0_Check
        
        L0_Check -->|No: Fast Path DENY <1ms| Enforcer[Enforcer Actions]
        L0_Check -->|Yes: Proceed to Cache| CacheLookup{Semantic Cache Hit?}
        
        %% Cache
        CacheLookup -->|Hit: Sub-millisecond <1ms| Enforcer
        CacheLookup -->|Miss| L1[Layer 1: Multi-Agent LLM Reasoning]
        
        %% Layer 1
        L1 -->|Device Context Retrieval| CA[Context Agent]
        CA -->|Structured Summary + Risk Score| PA[Policy Agent]
        PA -->|Zero-Trust Policy Reasoning| PA_Dec{Decision: ALLOW/DENY}
        
        PA_Dec -->|Write to Cache & Return| Enforcer
        
        %% Failures
        L1 -.->|Timeout / Inference Error| FailSecure[Fail-Secure Fallback: DENY]
        FailSecure --> Enforcer
    end

    subgraph Act [3. Act: Real-time Enforcement]
        Enforcer -->|ALLOW| AllowAccess[Permit IoT Connection]
        Enforcer -->|DENY| WazuhAR[Wazuh Active Response API]
        WazuhAR -->|Block Command| IPBlock[Host Firewall Rule Drop 3600s]
    end
```

### 1. Layer 0: Deterministic Validation (Fast Path — `< 1 ms`)
* **Input Sanitization & Normalization**: Uses `unicodedata.normalize('NFKC')` and strips directional overrides (`\u202A`–`\u202E`), Bidi isolates (`\u2066`–`\u2069`), and zero-width characters to stop homoglyph and right-to-left override evasion attacks dead in their tracks ([validation.py](common/validation.py)).
* **Cryptographic Token Verification**: Verifies JWT signatures, validates expirations, and enforces that the subject identity matches the requesting entity ([user_auth_validator.py](decision_engine/validators/user_auth_validator.py)).
* **Static Access Rule Pre-filtering**: Enforces network CIDR allowlists and scheduled operating hours. Invalid requests are rejected in **~1ms** without consuming LLM inference tokens.

### 2. Layer 1: Multi-Agent Generative Reasoning (Slow Path — `~97 ms`)
When deterministic checks pass but contextual ambiguity exists:
* **Context Agent**: Aggregates environmental telemetry, historical risk patterns, and device metadata into a concise context report ([context_agent.py](decision_engine/agents/context_agent.py)).
* **Policy Agent**: Compares context against high-level natural language access policies with zero-trust reasoning and generates an explainable decision with a calibrated semantic confidence score ([policy_agent.py](decision_engine/agents/policy_agent.py)).
* **Semantic Caching**: SHA-256 context hashing caches decisions (TTL: 1 hour) so repeated identical queries resolve in sub-millisecond times ([decision_pipeline.py](decision_engine/decision_pipeline.py)).
* **Fail-Secure Architecture**: If the LLM experiences latency spikes, API timeouts, or rate limits, Sentinel immediately defaults to **DENY** (0% False Permit Rate).

### 3. Real-Time Enforcement Layer
Denied access triggers the active enforcer ([actions.py](enforcer/actions.py)), which communicates with the Wazuh REST API to trigger a dynamic firewall drop (`firewall-drop`) on the endpoint for 3600 seconds.

---

## 📊 Key Results & Benchmarks

Sentinel was evaluated against a rigorous benchmark comprising **102 unique scenarios** (evaluated across 204 runs to verify cache reproducibility) and **105 adversarial red-team attacks**:

| Metric | RBAC + Rules Baseline | IoT-Access-Sentinel (Hybrid) | Improvement |
| :--- | :---: | :---: | :---: |
| **Overall Accuracy** | 82.4% (168/204) | **94.1% (192/204)** | **+11.7%** ($p < 0.01$) |
| **Complex Context Scenarios** | 50.0% | **100.0%** | **+50.0%** |
| **Red Team Attack Defense** | 71.4% | **100.0% (105/105)** | **+28.6%** |
| **Layer 0 Deterministic Intercept** | N/A | **66.7% (70/105)** | Zero LLM Cost |
| **Layer 1 Semantic Intercept** | N/A | **33.3% (35/105)** | Zero Evasion |
| **Deterministic Fast-Path Latency** | — | **< 1 ms** | Handles 42.2% traffic |
| **Average End-to-End Latency** | — | **97 ms** | Real-time capable |
| **Fail-Secure Safety Under Stress** | Baseline Fails Open | **0% False Permits** | 100% Fail-Secure |

> **Statistical Significance**: McNemar's test on the 102 independent scenarios yielded $\chi^2 = 7.56$ ($p < 0.01$), confirming a statistically significant improvement over traditional rule-based and RBAC systems.

---

## 📁 Repository Structure

```text
IoT-Access-Sentinel/
├── app.py                      # Interactive Gradio Web Demo (Hugging Face Spaces ready)
├── main.py                     # Production FastAPI server & REST API
├── requirements.txt            # Python dependencies
├── Dockerfile                  # Lightweight single-stage Python 3.11 container
├── docker-compose.yml          # Full SIEM stack (Wazuh Manager, Indexer, Sentinel)
├── common/                     # Cross-cutting utilities (validation, metrics, rate limits)
├── config/                     # Configuration schemas and access_policies.yaml
├── decision_engine/            # Hybrid decision engine (Pipeline, Agents, Prompt Guard)
│   ├── agents/                 # Context Agent & Policy Agent implementations
│   ├── validators/             # Deterministic JWT & User-Auth validators
│   └── prompt_guard.py         # Two-layer adversarial prompt injection guard
├── enforcer/                   # Active response and firewall blocking actions
├── observer/                   # Wazuh SIEM connector and alert ingestion models
├── evaluation/                 # 204 benchmark test scenarios and red-team manifests
├── results/                    # Experimental evaluation results, tables & statistics
└── tests/                      # Automated unit, security, and fail-secure test suite
```

---

## 🚀 Quick Start

### Option 1: Live Web Demo (Zero Installation)
Visit the live demo on Hugging Face Spaces:  
👉 **[https://huggingface.co/spaces/ahmed-fouad-lagha/IoT-Access-Sentinel](https://huggingface.co/spaces/ahmed-fouad-lagha/IoT-Access-Sentinel)**

### Option 2: Local Setup

1. **Clone the repository**:
   ```bash
   git clone https://github.com/ahmed-fouad-lagha/IoT-Access-Sentinel.git
   cd IoT-Access-Sentinel
   ```

2. **Create a virtual environment and install dependencies**:
   ```bash
   python3 -m venv .venv
   source .venv/bin/activate
   pip install -r requirements.txt
   ```

3. **Launch either the API Server or the Interactive Demo**:
   * **To run the Interactive Gradio Demo**:
     ```bash
     python app.py
     ```
     Open `http://localhost:7860` in your browser.

   * **To run the FastAPI Access Control Server**:
     ```bash
     python main.py
     ```
     Access interactive OpenAPI docs at `http://localhost:8000/docs`.

---

## 🐳 Docker Deployment

Run the complete standalone Sentinel container:

```bash
# Build the container
docker build -t iot-access-sentinel .

# Run the container
docker run -d -p 8000:8000 --name sentinel iot-access-sentinel
```

Or launch the entire SIEM integration (Wazuh Manager, Indexer, Dashboard & Sentinel) via Docker Compose:

```bash
docker-compose up -d --build
```

---

## 🧪 Testing & Verification

Run the comprehensive pytest suite verifying deterministic pre-checks, cryptographic token validations, prompt injection defenses, and fail-secure mechanisms:

```bash
pytest tests/ -v
```

To run the reproducibility evaluation benchmark:
```bash
# Quick functional check (8 scenarios)
bash evaluation/run_tests.sh

# Full benchmark (204 evaluation runs)
bash evaluation/run_tests.sh --full
```

---

## 📖 API Documentation

The FastAPI backend automatically serves interactive Swagger documentation:

* **Swagger UI**: `http://localhost:8000/docs`
* **ReDoc**: `http://localhost:8000/redoc`
* **Prometheus Metrics**: `http://localhost:8000/metrics`

### Process Access Alert (`POST /access-control`)

```bash
curl -X POST http://localhost:8000/access-control \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer your-webhook-api-key" \
  -d '{
    "id": "alert-101",
    "timestamp": "2026-05-26T10:30:00Z",
    "device_id": "camera-office-01",
    "device_type": "camera",
    "source_ip": "192.168.1.50",
    "user_id": "alice@company.com",
    "auth_token": "eyJhbGciOiJIUzI1Ni..."
  }'
```

---

## 📜 Citation

If you find **IoT-Access-Sentinel** helpful in your research or applications, please cite our paper:

```bibtex
@inproceedings{lagha2026sentinel,
  title={IoT-Access-Sentinel: Hybrid Zero-Trust Access Control Framework for Edge IoT Networks},
  author={Lagha, Ahmed Fouad and collaborators},
  booktitle={Proceedings of the Information Technologies -- Applications and Theory (ITAT 2026)},
  year={2026}
}
```

---

## 📄 License

This project is licensed under the **Apache License 2.0** — see the [LICENSE](LICENSE) file for details.
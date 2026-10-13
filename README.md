# 🛡️ Sentinel-MAS

**Self-Defending Security Framework for Multi-Agent AI Systems**

Sentinel-MAS is a research framework that demonstrates real-time threat detection, quarantine, and defense mechanisms within a multi-agent system (MAS). It simulates adversarial attacks—such as prompt injections, malicious tool outputs, and abnormal agent behavior—and evaluates how an autonomous defender agent can detect, verify, and contain these threats.

---

## 📋 Table of Contents

- [Features](#-features)
- [Architecture](#-architecture)
- [Project Structure](#-project-structure)
- [Setup & Installation](#-setup--installation)
- [Usage](#-usage)
- [Attack Scenarios](#-attack-scenarios)
- [Security Metrics](#-security-metrics)
- [Dashboard](#-dashboard)
- [Configuration](#-configuration)
- [Tech Stack](#-tech-stack)

---

## ✨ Features

- **Multi-Agent Architecture** — Research, Analyst, Manager, Attacker, and Defender agents collaborating and competing in real time
- **Real-Time Threat Detection** — Rule-based detection engine identifies prompt injections, malicious payloads, and behavioral anomalies
- **LLM-Powered Verification** — Threats flagged by rules are verified using LLM reasoning (supports OpenAI, Groq, or a mock provider)
- **Automatic Quarantine** — Compromised agents are isolated to prevent attack propagation across the system
- **Attack Propagation Analysis** — Graph-based tracking of how attacks spread between agents via Neo4j
- **Comprehensive Metrics** — Detection rate, false positive rate, containment time, propagation accuracy, and service continuity
- **Interactive CLI** — Rich terminal interface for running simulations and viewing results
- **Streamlit Dashboard** — Web-based visualization with real-time agent status, communication logs, and security analytics

---

## 🏗️ Architecture

```
┌─────────────────────────────────────────────────────┐
│                   SENTINEL-MAS                       │
│                                                      │
│  ┌──────────┐  ┌──────────┐  ┌──────────┐           │
│  │ Research  │  │ Analyst  │  │ Manager  │  Task     │
│  │  Agent    │  │  Agent   │  │  Agent   │  Agents   │
│  └────┬─────┘  └────┬─────┘  └────┬─────┘           │
│       │              │             │                  │
│       └──────────────┼─────────────┘                  │
│                      │                                │
│              ┌───────▼───────┐                        │
│              │  Message Bus  │  (Central Comm Hub)    │
│              └───────┬───────┘                        │
│                      │                                │
│       ┌──────────────┼──────────────┐                 │
│       │              │              │                  │
│  ┌────▼─────┐  ┌─────▼────┐  ┌─────▼──────┐          │
│  │ Attacker │  │ Defender │  │ Quarantine │          │
│  │  Agent   │  │  Agent   │  │  Manager   │          │
│  └──────────┘  └──────────┘  └────────────┘          │
│                      │                                │
│              ┌───────▼───────┐                        │
│              │  Neo4j Graph  │  (Attack Tracking)    │
│              └───────────────┘                        │
└─────────────────────────────────────────────────────┘
```

---

## 📁 Project Structure

```
SentinalMAS/
├── agents/                  # Agent implementations
│   ├── base_agent.py        # Base class for all agents
│   ├── research_agent.py    # Research task agent
│   ├── analyst_agent.py     # Analysis task agent
│   ├── manager_agent.py     # Management/coordination agent
│   ├── attacker_agent.py    # Adversarial attack agent
│   └── defender_agent.py    # Security defender agent
├── communication/           # Inter-agent messaging
│   ├── message_bus.py       # Central message routing
│   └── message_models.py    # Message data models
├── config/                  # Configuration
│   └── settings.py          # Centralized settings (from .env)
├── dashboard/               # Web dashboard
│   └── app.py               # Streamlit application
├── data/logs/               # Log output directory
├── detection/               # Threat detection engine
│   ├── rule_detector.py     # Rule-based threat detection
│   ├── threat_models.py     # Threat type definitions
│   └── threat_verifier.py   # LLM-powered threat verification
├── evaluation/              # Security evaluation
│   └── metrics.py           # Security metric calculations
├── graph/                   # Graph database integration
│   └── neo4j_manager.py     # Neo4j operations
├── llm/                     # LLM provider abstraction
│   ├── llm_provider.py      # Provider factory
│   ├── openai_provider.py   # OpenAI integration
│   ├── groq_provider.py     # Groq integration
│   └── mock_provider.py     # Mock provider (no API needed)
├── quarantine/              # Agent quarantine system
│   └── quarantine_manager.py
├── simulation/              # Attack simulation scenarios
│   └── scenarios.py         # Pre-built attack scenarios
├── tests/                   # Test suite
├── main.py                  # Entry point & CLI
├── requirements.txt         # Python dependencies
├── .env.example             # Environment variable template
└── .gitignore
```

---

## 🚀 Setup & Installation

### Prerequisites

- **Python 3.10+**
- **Neo4j** (optional — for graph-based attack tracking)

### 1. Clone the Repository

```bash
git clone https://github.com/NoyalMJ22/SentinalMAS.git
cd SentinalMAS
```

### 2. Create Virtual Environment

```bash
python -m venv venv

# Windows
venv\Scripts\activate

# macOS / Linux
source venv/bin/activate
```

### 3. Install Dependencies

```bash
pip install -r requirements.txt
```

### 4. Configure Environment

```bash
copy .env.example .env    # Windows
# cp .env.example .env    # macOS / Linux
```

Edit `.env` with your settings:

```env
# Use "mock" for no API key needed (default)
LLM_PROVIDER=mock

# Or use a real LLM:
# LLM_PROVIDER=groq
# GROQ_API_KEY=your_key_here

# Neo4j (optional)
NEO4J_URI=bolt://localhost:7687
NEO4J_USER=neo4j
NEO4J_PASSWORD=your_password
```

---

## 💻 Usage

### Interactive CLI

```bash
python main.py
```

This launches the control panel with options to:
1. Run normal agent workflows
2. Simulate various attack types
3. View agent status, communication logs, and security metrics
4. Launch the web dashboard

### Run a Specific Scenario

```bash
python main.py --scenario normal
python main.py --scenario prompt_injection
python main.py --scenario attack_propagation
```

### Launch Dashboard

```bash
python main.py --dashboard
# or directly:
streamlit run dashboard/app.py
```

---

## ⚔️ Attack Scenarios

| Scenario | Description |
|---|---|
| **Normal Workflow** | Legitimate agent collaboration — research → analysis → management |
| **Prompt Injection** | Attacker injects malicious instructions into agent messages |
| **Malicious Tool Output** | Attacker poisons tool outputs consumed by task agents |
| **Abnormal Behavior** | Agent exhibits anomalous patterns (e.g., unauthorized data access) |
| **Attack Propagation** | Multi-stage attack spreading across the agent network |

---

## 📊 Security Metrics

Sentinel-MAS evaluates its defense capabilities using:

| Metric | Description |
|---|---|
| **Detection Rate** | Percentage of actual threats correctly identified |
| **False Positive Rate** | Percentage of benign messages incorrectly flagged |
| **Containment Time** | Average time to quarantine a compromised agent |
| **Propagation Accuracy** | Accuracy of attack path tracking in the graph |
| **Service Continuity** | Percentage of non-compromised agents remaining operational |

---

## 📈 Dashboard

The Streamlit dashboard provides:

- **Agent Status** — Real-time view of all agent states (active, quarantined, monitoring)
- **Communication Log** — Visual timeline of inter-agent messages
- **Security Metrics** — Interactive charts and metric cards
- **Attack Graph** — Visual representation of attack propagation paths

---

## ⚙️ Configuration

All configuration is managed through environment variables (`.env` file):

| Variable | Default | Description |
|---|---|---|
| `LLM_PROVIDER` | `mock` | LLM backend: `mock`, `openai`, or `groq` |
| `OPENAI_API_KEY` | — | OpenAI API key (if using OpenAI) |
| `GROQ_API_KEY` | — | Groq API key (if using Groq) |
| `LLM_MODEL` | auto | Model name (auto-selected per provider) |
| `NEO4J_URI` | `bolt://localhost:7687` | Neo4j connection URI |
| `NEO4J_USER` | `neo4j` | Neo4j username |
| `NEO4J_PASSWORD` | — | Neo4j password |
| `DEBUG` | `false` | Enable debug logging |

---

## 🛠️ Tech Stack

- **Python 3.10+** — Core language
- **LangChain / LangGraph** — Multi-agent orchestration
- **Neo4j** — Graph database for attack propagation tracking
- **Streamlit** — Interactive web dashboard
- **Plotly** — Data visualization
- **Rich** — Terminal UI rendering
- **Pydantic** — Configuration & data validation

---

## 📄 License

This project is for educational and research purposes.

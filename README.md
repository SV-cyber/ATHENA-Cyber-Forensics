# ATHENA: AI-Driven Threat Hunting & Adversary Emulation Platform

**MSc Cyber Forensics Dissertation Project**
**Author:** SV-cyber (Sundaram Vishal)
**Timeline:** March 11 – April 15, 2026
**Status:** 🟢 Functional System (Integrated Pipeline Complete)

---

## 🚀 Overview

ATHENA is a **full-stack cyber threat analysis platform** that simulates adversary behavior, detects anomalies using machine learning, and reconstructs attack chains using correlation logic.

It evolved from a **file-based prototype** into a **database-driven, event-oriented system** capable of end-to-end threat analysis.

---

## 🧠 Core Architecture

```
Simulation → Event Normalization → Event Bus → ML Detection → Correlation Engine → PostgreSQL → FastAPI → Dashboard
```

---

## 🔥 Key Features

### ⚔️ Adversary Emulation

* Simulates real-world attacks based on MITRE ATT&CK techniques
* Multi-stage attack chain generation (APT28-style campaigns)

### 🧪 Event Processing

* Normalizes raw mission logs into structured security events
* Feature engineering (tactics, severity, encoded signals)

### 🤖 Machine Learning Detection

* Isolation Forest for anomaly detection
* LSTM-ready architecture (optional TensorFlow integration)
* Detects suspicious behavioral patterns

### 🔗 Correlation Engine

* Builds graph-based attack relationships
* Reconstructs complete attack chains
* Identifies lateral movement & multi-stage attacks

### ⚡ Event-Driven Pipeline

* Internal event bus for modular processing
* Decoupled architecture between stages

### 🗄️ Database Integration

* PostgreSQL-backed persistence
* Stores events, detections, and correlations
* Eliminates CSV/JSON dependency

### 🌐 API Layer (FastAPI)

* `/run-pipeline` → execute full simulation
* `/events` → fetch normalized events
* `/detections` → anomaly results
* `/attack-chains` → reconstructed attack paths
* `/health` → system status

### 📊 Visualization Dashboard

* Streamlit-based SOC-style dashboard
* Timeline, attack chains, MITRE mapping, logs view

---

## ⚙️ Quick Start (Windows 11)

### Prerequisites

* Python 3.9+
* Docker Desktop
* Git

---

### 🔧 Setup

```powershell
git clone https://github.com/SV-cyber/ATHENA-Cyber-Forensics.git
cd ATHENA-Cyber-Forensics

python -m venv venv
.\venv\Scripts\activate

pip install -r requirements.txt
```

---

### 🐳 Start Services

```powershell
docker compose up -d
```

---

### ▶️ Run Pipeline

```powershell
python src/main_pipeline.py
```

---

### 🌐 Start Backend API

```powershell
uvicorn src.visualization.backend.app:app --reload --port 8001
```

Open:
👉 http://localhost:8001/docs

---

### 📊 Run Dashboard

```powershell
streamlit run src/visualization/frontend/app.py
```

---

## 📁 Project Structure

```
src/
├── caldera-simulator/      # Adversary emulation
├── data_collection/        # Event normalization & ingestion
├── ml-models/              # ML training & detection
├── correlation-engine/     # Attack chain reconstruction
├── visualization/          # FastAPI + Streamlit dashboard
├── utils/                  # Config, DB, event bus
├── main_pipeline.py        # Orchestrates full system
```

---

## 📊 System Output Example

* Total Events: 13
* Anomalies Detected: 2
* Attack Chains: 1

---

## 🧠 Key Innovation

> ATHENA transitions from a static analysis pipeline to a **dynamic, event-driven cyber threat intelligence system** with real-time processing capability.

---

## 🛠️ Technologies Used

* Python, FastAPI
* PostgreSQL, SQLAlchemy
* Scikit-learn (Isolation Forest)
* Streamlit
* Docker
* MITRE ATT&CK framework

---

## 📚 Documentation

* `ARCHITECTURE.md` – System design
* `SETUP_GUIDE.md` – Detailed setup instructions
* `DISSERTATION.md` – Academic research paper

---

## 📜 License

MIT License

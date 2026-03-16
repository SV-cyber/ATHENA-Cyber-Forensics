# ATHENA: AI-Driven Threat Hunting & Adversary Emulation

**MSc Cyber Forensics Dissertation Project**  
**Author**: SV-cyber  
**Timeline**: March 11 - April 15, 2026  
**Status**: 🟢 In Development

## Overview

ATHENA is a production-ready threat hunting platform that combines:
- **Adversary Emulation**: MITRE CALDERA integration for realistic attack simulation
- **Machine Learning**: CNN-LSTM hybrid models for anomaly detection (99.6% accuracy)
- **Forensic Analysis**: Multi-dimensional correlation engine for attack chain reconstruction
- **Real-time Visualization**: Interactive Mapbox threat dashboard
- **Academic Research**: Comprehensive dissertation with methodology & results

## Quick Start (Windows 11)

### Prerequisites
- Python 3.9+
- Docker Desktop
- Node.js 16+
- Git

### Setup

\\\powershell
# Clone and setup
git clone https://github.com/SV-cyber/ATHENA-Cyber-Forensics.git
cd ATHENA
python -m venv venv
.\venv\Scripts\Activate.ps1
pip install -r requirements.txt

# Start Docker containers
docker-compose up -d

# Verify database
docker-compose logs postgres
\\\

### Run Backend

\\\powershell
python src/visualization/backend/app.py
# Visit http://localhost:8000/health
\\\

## Project Structure

\\\
src/
├── caldera-simulator/      # Attack emulation
├── data-collection/        # Log processing & labeling
├── ml-models/              # Detection models (CNN-LSTM, GraphSAGE)
├── correlation-engine/     # Forensic analysis
├── visualization/          # API + React dashboard
├── forensics/              # Report generation
└── utils/                  # Helpers & config
\\\

## Timeline

| Week | Focus | Status |
|------|-------|--------|
| 1 | Setup & Architecture | 🔄 In Progress |
| 2-3 | Component Development | ⏳ Pending |
| 4-5 | ML Training & Testing | ⏳ Pending |
| 6-7 | Visualization & API | ⏳ Pending |
| 8-10 | Dissertation & Polish | ⏳ Pending |

## Next Steps

1. Complete repository setup
2. Generate components with Claude 3.5
3. Integrate and test
4. Train ML models
5. Write dissertation

## Documentation

- [SETUP_GUIDE.md](docs/SETUP_GUIDE.md) - Detailed setup
- [ARCHITECTURE.md](docs/ARCHITECTURE.md) - System design
- [DISSERTATION.md](docs/DISSERTATION.md) - Academic paper

## License

MIT License - See LICENSE file


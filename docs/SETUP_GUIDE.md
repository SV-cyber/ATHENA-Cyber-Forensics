\# ATHENA Setup Guide



\## Requirements



\- Python 3.9+

\- Docker Desktop

\- Git

\- Windows 11 / Linux / macOS



\## Installation



Clone repository:



git clone https://github.com/SV-cyber/ATHENA-Cyber-Forensics.git



Create virtual environment:



python -m venv venv

.\\venv\\Scripts\\Activate.ps1



Install dependencies:



pip install -r requirements.txt



Start Docker services:



docker-compose up -d



Run backend:



uvicorn src.visualization.backend.app:app --host 0.0.0.0 --port 8001



Verify:



http://localhost:8001/health


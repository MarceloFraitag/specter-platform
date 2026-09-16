# Specter SIEM & Governance Platform

Plataforma de cibersegurança para gerenciamento de incidentes (SIEM/SOAR), com arquitetura poliglota: backend em Python, agente coletor em Go e painel em React.

**Demo:** [specter-platform-seven.vercel.app](https://specter-platform-seven.vercel.app)

## Stack

- **Backend:** Python, FastAPI, SQLAlchemy, JWT, bcrypt
- **Frontend:** React, TypeScript, Vite
- **Agente coletor:** Go (concorrência com goroutines e tickers)
- **Banco de dados:** PostgreSQL (Neon)

## O que faz

- Autenticação com JWT e senhas em hash (bcrypt)
- Simulação de ataques (Impossible Travel, Brute Force, Nmap Scan, Bypass MFA)
- Ingestão em massa de telemetria via endpoint dedicado (bulk insert)
- Gestão de incidentes: abertura, triagem e mitigação de tickets
- Auditoria de contas inativas no Active Directory / Entra ID
- Agente em Go enviando telemetria simulada para a API a cada 4 segundos
- Dashboard com atualização em tempo real (polling a cada 3 segundos)

## Como rodar

### Backend
```bash
cd specter-backend
pip install -r requirements.txt
uvicorn main:app --reload
```

### Frontend
```bash
cd specter-frontend
npm install
npm run dev
```

### Agente (Go)
```bash
cd specter-agent-go
go run main.go
```

Configure as variáveis de ambiente (conexão com o banco e segredo do JWT) antes de rodar o backend.

## Estrutura

```
specter-platform/
├── specter-backend/     # API FastAPI
├── specter-frontend/    # Painel React + TypeScript
└── specter-agent-go/    # Agente coletor de telemetria
```

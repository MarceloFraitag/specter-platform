# Specter SIEM & Governance Platform

Plataforma corporativa de cibersegurança e gerenciamento de incidentes (SIEM/SOAR), desenvolvida com uma arquitetura poliglota para garantir alta performance de ingestão, segurança e governança de identidades.

## 🚀 Tecnologias Utilizadas

* **Backend:** Python (FastAPI, SQLAlchemy, PyJWT, bcrypt)
* **Frontend:** React, TypeScript, Vite, CSS Inline Customizado (Tema Cyberpunk)
* **Banco de Dados (Nuvem):** PostgreSQL hospedado no **Neon**
* **Agente Coletor (Alta Escala):** Go (Golang) com concorrência nativa (`goroutines` e `tickers`)

---

## 🛠️ Arquitetura e Funções do Sistema

### 1. Banco de Dados (`models.py`)
* **`users`**: Cadastro de operadores do SOC com senhas protegidas por hash (bcrypt).
* **`alerts`**: Registro de incidentes e ataques simulados pelo Cyber Range.
* **`incidents`**: Central de triagem e tickets de segurança (CRUD completo).
* **`audit_logs`**: Trilha de auditoria para ações sensíveis e automações SOAR.
* **`raw_logs`**: Tabela de alta performance para armazenamento de telemetria bruta.

### 2. API & Backend (`main.py`)
* **Autenticação:** Emissão de tokens JWT com validade de 30 minutos e rotas protegidas de cadastro/login.
* **Motor SIEM:** Endpoints dedicados a simular ataques corporativos (*Impossible Travel*, *Brute Force*, *Nmap Scan*, *Bypass MFA*).
* **Ingestão em Massa (`/api/telemetry/ingest`):** Endpoint de alta performance otimizado para receber lotes de logs (*bulk insert* via SQLAlchemy).
* **Gestão de Incidentes:** Criação, listagem e atualização de status de tickets ("Aberto" para "Mitigado").
* **SOAR & Governança:** Execução de playbooks de remediação, auditoria de contas inativas no Active Directory/Entra ID e métricas preditivas de capacidade de infraestrutura.

### 3. Agente Coletor em Go (`specter-agent-go/main.go`)
* Programa concorrente independente escrito em Go.
* Utiliza um cronômetro (`ticker`) para disparar lotes de telemetria simulada via HTTP POST de forma assíncrona para a API em Python a cada 4 segundos.

### 4. Painel Front-end (`src/App.tsx`)
* Interface reativa em React e TypeScript focada na experiência de um analista SOC.
* **Dashboard em tempo real:** Polling a cada 3 segundos atualizando o status do cluster, feed de alertas e o terminal de logs brutos enviados pelo agente em Go.
* **Central de Incidentes:** Interação direta com o banco para abrir e mitigar tickets.

---

## ⚙️ Como Rodar o Projeto

1. **Backend (Python):**
   ```bash
   uvicorn main:app --reload
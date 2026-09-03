# Specter SIEM & Governance Platform

Painel de Operações de Cibersegurança, Identidade e Capacity Planning em tempo real. Desenvolvido para transformar monitoramento complexo em automação e resposta rápida a incidentes.

## O Que É Essa Joia?
O **Specter** nasceu da necessidade de centralizar telemetria de infraestrutura e segurança sem aquela poluição de alertas falsos (*alert fatigue*) que consome o dia a dia do SysAdmin. Ele combina um motor de **SIEM & SOAR** (Security Orchestration, Automation, and Response) com ferramentas de **Governança de Identidade** e **Capacity Planning Preditivo**.

## Arquitetura & Tecnologias
* **Backend**: Python puro com **FastAPI**, autenticação via tokens **JWT** corporativos, e endpoints otimizados para polling e automação de contramedidas.
* **Frontend**: **React** com **Vite**, interface totalmente customizada em estilo terminal cyberpunk, focada em legibilidade extrema, painéis dinâmicos e controle de acesso multi-usuário.

## Funcionalidades Nativas
1. **Cyber Range & Simulação de Ataques**: Injeção em tempo real de vetores de ameaça (Viagem Impossível, Força Bruta, Varreduras Nmap e Bypass de MFA no Entra ID) para testar a resiliência do ambiente.
2. **Auto-Remediation via SOAR**: Playbooks integrados que executam contramedidas instantâneas (como revogação de tokens OAuth, bloqueio de contas e logoff global de sessão).
3. **Auditoria de Identidade & Compliance**: Varredura de contas inativas e sem MFA no tenant corporativo com remediação em lote com um único clique.
4. **Capacity Planning Preditivo**: Análise de tendência de crescimento de recursos críticos (discos e storages) para prever o esgotamento antes que o servidor caia.
5. **Multi-Tenancy & Auth**: Sistema próprio de cadastro e autenticação de operadores, garantindo segurança e isolamento de acessos.

## Como Subir o Ambiente Localmente

### 1. Subindo o Backend
```bash
cd specter-backend
python -m venv .venv
source .venv/bin/activate  # No Windows: .venv\Scripts\activate
pip install -r requirements.txt
uvicorn main:app --reload --port 8000
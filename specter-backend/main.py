from fastapi import FastAPI, HTTPException, status
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
import jwt
from datetime import datetime, timedelta, timezone

# marcelo: Chave secreta e configurações de expiração do JWT corporativo
SECRET_KEY = "chave-super-secreta-specter"
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 30

app = FastAPI(
    title="Specter SIEM & Governance API",
    description="Backend avançado de Cibersegurança, Identidade e Gestão de Usuários.",
    version="2.3.0"
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# marcelo: Banco de dados simulado em memória contendo o admin padrão e novos cadastros
banco_usuarios = {
    "marcelo.fraitag": {
        "password": "senha123",
        "role": "SysAdmin",
        "email": "marcelo.fraitag@specter-corp.local"
    }
}

class LoginRequest(BaseModel):
    username: str
    password: str

# marcelo: Modelo Pydantic para receber novos cadastros de operadores
class RegisterRequest(BaseModel):
    username: str
    password: str
    email: str
    role: str = "Analista SOC"

class AttackSimulationRequest(BaseModel):
    scenario: str

class RemediationRequest(BaseModel):
    action: str
    target: str

ultimo_ataque_injetado = None

@app.get("/")
def root():
    return {"status": "online", "message": "Specter SIEM & Governance operacional e blindado."}

@app.get("/api/health")
def health_check():
    return {"cpu_usage": "14%", "ram_usage": "48%", "status": "healthy"}

# marcelo: Rota de Cadastro de Novos Operadores
@app.post("/api/register")
def register_user(request: RegisterRequest):
    if request.username in banco_usuarios:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Este nome de usuário já está cadastrado no sistema."
        )
    
    # marcelo: Cadastra o novo usuário na memória do sistema
    banco_usuarios[request.username] = {
        "password": request.password,
        "role": request.role,
        "email": request.email
    }
    
    return {
        "status": "sucesso",
        "message": f"Usuário '{request.username}' cadastrado com sucesso! Faça login para prosseguir."
    }

# marcelo: Rota de Login Dinâmico validada contra a base de cadastros
@app.post("/api/login")
def login(request: LoginRequest):
    usuario = banco_usuarios.get(request.username)
    
    if not usuario or usuario["password"] != request.password:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Credenciais inválidas. Verifique usuário e senha."
        )
    
    tempo_expiracao = datetime.now(timezone.utc) + timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    payload = {
        "sub": request.username,     
        "role": usuario["role"],          
        "exp": tempo_expiracao       
    }
    token = jwt.encode(payload, SECRET_KEY, algorithm=ALGORITHM)
    
    return {
        "access_token": token, 
        "token_type": "bearer",
        "message": f"Acesso autorizado. Bem-vindo, {usuario['role']}."
    }

@app.post("/api/simulate-attack")
async def simulate_attack(data: AttackSimulationRequest):
    global ultimo_ataque_injetado
    scenario = data.scenario
    
    cenarios = {
        "impossible_travel": {
            "nivel": "CRITICO", 
            "mensagem": "Alerta de Viagem Impossível: Login autenticado em Curitiba e, 15 min depois, em Munique (Alemanha)."
        },
        "brute_force": {
            "nivel": "CRITICO", 
            "mensagem": "Ataque de Força Bruta detectado: 142 tentativas de login falhas na conta admin originadas do IP 192.168.1.105."
        },
        "nmap_scan": {
            "nivel": "AVISO", 
            "mensagem": "Varredura de portas (Nmap TCP SYN) identificada vinda de segmento de rede externo não autorizado."
        },
        "azure_mfa": {
            "nivel": "CRITICO", 
            "mensagem": "Tentativa de bypass de MFA bloqueada pelo Conditional Access (Erro AADSTS135011)."
        }
    }
    
    if scenario not in cenarios:
        raise HTTPException(status_code=400, detail="Cenário de ataque inválido.")
    
    ultimo_ataque_injetado = cenarios[scenario]
    return {"status": "sucesso", "mensagem": f"Cenário '{scenario}' injetado no motor SIEM."}

@app.get("/api/alerts/poll")
def poll_alerts():
    global ultimo_ataque_injetado
    if ultimo_ataque_injetado:
        alerta = ultimo_ataque_injetado
        ultimo_ataque_injetado = None 
        return alerta
    
    return None

@app.post("/api/soar/mitigate")
async def mitigate_incident(data: RemediationRequest):
    action = data.action
    target = data.target
    
    if action == "block_user":
        resultado = f"Ação SOAR executada com sucesso: Conta '{target}' desabilitada e tokens revogados no Entra ID."
    elif action == "isolate_host":
        resultado = f"Ação SOAR executada com sucesso: Host '{target}' isolado da rede por políticas de firewall."
    else:
        raise HTTPException(status_code=400, detail="Ação de remediação desconhecida.")
    
    return {"status": "sucesso", "detalhe": resultado}

@app.get("/api/audit/identities")
def audit_identities():
    identidades_auditadas = [
        {"usuario": "paulo.terceiro", "email": "paulo.terceiro@specter-corp.local", "dias_inativo": 298, "status_mfa": "Desativado", "risco": "ALTO"},
        {"usuario": "sistema.backup", "email": "backup.infra@specter-corp.local", "dias_inativo": 83, "status_mfa": "Ativado", "risco": "MEDIO"},
        {"usuario": "estagio.suporte", "email": "estagio.suporte@specter-corp.local", "dias_inativo": 231, "status_mfa": "Desativado", "risco": "ALTO"},
        {"usuario": "ana.silva", "email": "ana.silva@specter-corp.local", "dias_inativo": 1, "status_mfa": "Ativado", "risco": "BAIXO"}
    ]
    
    total_riscos = sum(1 for i in identidades_auditadas if i["risco"] == "ALTO")
    
    return {
        "status": "sucesso",
        "total_auditados": len(identidades_auditadas),
        "alertas_criticos": total_riscos,
        "dados": identidades_auditadas
    }

@app.post("/api/audit/revoke-inactive")
async def revoke_inactive_accounts():
    return {
        "status": "sucesso",
        "detalhe": "Compliance executado: Contas inativas de alto risco foram desativadas e credenciais revogadas automaticamente."
    }

@app.get("/api/capacity/prediction")
def capacity_prediction():
    recursos_criticos = [
        {
            "recurso": "Disco C: (Fileserver Principal)",
            "uso_atual": "89%",
            "taxa_crescimento": "+2.3% / dia",
            "tempo_estimado_esgotamento": "4 dias e 12 horas",
            "previsao_estouro": "2026-09-08",
            "severidade": "CRITICO"
        },
        {
            "recurso": "Memória RAM (Cluster SQL Server)",
            "uso_atual": "78%",
            "taxa_crescimento": "+0.5% / dia",
            "tempo_estimado_esgotamento": "44 dias",
            "previsao_estouro": "2026-10-18",
            "severidade": "AVISO"
        },
        {
            "recurso": "Storage SAN (Backup Vault)",
            "uso_atual": "62%",
            "taxa_crescimento": "+0.1% / dia",
            "tempo_estimado_esgotamento": "Estável (> 6 meses)",
            "previsao_estouro": "N/A",
            "severidade": "SAUDAVEL"
        }
    ]
    
    return {
        "status": "sucesso",
        "cluster_status": "Sob Observação Preditiva",
        "metricas": recursos_criticos
    }
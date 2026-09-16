from fastapi import FastAPI, HTTPException, status, Depends
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
import jwt
from datetime import datetime, timedelta, timezone
import os
import bcrypt
from dotenv import load_dotenv

# Conexão com o banco e os models que criamos
from sqlalchemy.orm import Session
from database import engine, get_db
import models

# Sobe as tabelas direto no banco do Neon se elas ainda não existirem
models.Base.metadata.create_all(bind=engine)

load_dotenv()

# Pegando as chaves de segurança do ambiente
SECRET_KEY = os.getenv("SECRET_KEY", "chave-super-secreta-specter")
ALGORITHM = os.getenv("ALGORITHM", "HS256")
ACCESS_TOKEN_EXPIRE_MINUTES = 30

def get_password_hash(password: str) -> str:
    # Transforma a senha pura em hash seguro com bcrypt
    pwd_bytes = password.encode('utf-8')
    salt = bcrypt.gensalt()
    return bcrypt.hashpw(pwd_bytes, salt).decode('utf-8')

def verify_password(plain_password: str, hashed_password: str) -> bool:
    # Bate a senha digitada no login com o hash guardado no banco
    return bcrypt.checkpw(plain_password.encode('utf-8'), hashed_password.encode('utf-8'))

app = FastAPI(
    title="Specter SIEM & Governance API",
    description="Backend do SIEM com suporte a Neon e alta escala.",
    version="2.6.0"
)

# Libera o front (React) para falar com a API sem bloqueio de CORS
app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://localhost:5173", "http://127.0.0.1:5173"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# --- ESTRUTURAS PYDANTIC (VALIDAÇÃO DE ENTRADA) ---
class LoginRequest(BaseModel):
    username: str
    password: str

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

class IncidentCreate(BaseModel):
    title: str
    notes: str = None

class IncidentUpdate(BaseModel):
    status: str = None
    assigned_to: str = None
    notes: str = None

class BatchLogItem(BaseModel):
    source_ip: str = "127.0.0.1"
    event_type: str
    payload: str

class TelemetryBatchRequest(BaseModel):
    logs: list[BatchLogItem]


# --- ROTAS DE SAÚDE E BASE ---
@app.get("/")
def root():
    return {"status": "online", "message": "API do Specter rodando com banco Neon!"}

@app.get("/api/health")
def health_check():
    # Métricas simuladas do servidor
    return {"cpu_usage": "14%", "ram_usage": "48%", "status": "healthy"}


# --- AUTENTICAÇÃO E CADASTRO ---
@app.post("/api/register")
def register_user(request: RegisterRequest, db: Session = Depends(get_db)):
    # Valida se o user ou email já existem antes de criar
    if db.query(models.User).filter(models.User.username == request.username).first():
        raise HTTPException(status_code=400, detail="Usuário já cadastrado.")
    
    if db.query(models.User).filter(models.User.email == request.email).first():
        raise HTTPException(status_code=400, detail="E-mail já está em uso.")
    
    novo_usuario = models.User(
        username=request.username,
        email=request.email,
        hashed_password=get_password_hash(request.password),
        role=request.role
    )
    db.add(novo_usuario)
    db.commit()
    db.refresh(novo_usuario)
    return {"status": "sucesso", "message": f"Usuário '{novo_usuario.username}' criado!"}

@app.post("/api/login")
def login(request: LoginRequest, db: Session = Depends(get_db)):
    usuario = db.query(models.User).filter(models.User.username == request.username).first()
    if not usuario or not verify_password(request.password, usuario.hashed_password):
        raise HTTPException(status_code=401, detail="Credenciais inválidas.")
    
    # Gera o token JWT com validade de 30 minutos
    payload = {
        "sub": usuario.username,
        "role": usuario.role,
        "exp": datetime.now(timezone.utc) + timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    }
    token = jwt.encode(payload, SECRET_KEY, algorithm=ALGORITHM)
    return {"access_token": token, "token_type": "bearer", "message": "Login autorizado."}


# --- MOTOR SIEM (ALERTAS E ATAQUES) ---
@app.post("/api/simulate-attack")
def simulate_attack(data: AttackSimulationRequest, db: Session = Depends(get_db)):
    cenarios = {
        "impossible_travel": {"nivel": "CRITICO", "mensagem": "Alerta de Viagem Impossível no AD."},
        "brute_force": {"nivel": "CRITICO", "mensagem": "Força bruta detectada na porta SSH/RDP."},
        "nmap_scan": {"nivel": "AVISO", "mensagem": "Varredura de portas (Nmap) identificada."},
        "azure_mfa": {"nivel": "CRITICO", "mensagem": "Tentativa de bypass de MFA bloqueada no Entra ID."}
    }
    
    if data.scenario not in cenarios:
        raise HTTPException(status_code=400, detail="Cenário inválido.")
    
    info = cenarios[data.scenario]
    alerta = models.Alert(severity=info["nivel"], source=data.scenario, description=info["mensagem"])
    db.add(alerta)
    db.commit()
    return {"status": "sucesso", "mensagem": "Ataque injetado."}

@app.get("/api/alerts/poll")
def poll_alerts(db: Session = Depends(get_db)):
    # Pega o alerta mais recente não resolvido para o feed ao vivo
    alerta = db.query(models.Alert).filter(models.Alert.is_resolved == False).order_by(models.Alert.created_at.desc()).first()
    if not alerta:
        return None
    return {"nivel": alerta.severity, "mensagem": alerta.description}


# --- INGESTÃO DE TELEMETRIA EM MASSA (AGENTE GO) ---
@app.post("/api/telemetry/ingest", status_code=202)
def ingest_telemetry(batch: TelemetryBatchRequest, db: Session = Depends(get_db)):
    # Recebe os lotes do script em Go e joga no banco de uma vez só (bulk)
    if not batch.logs:
        return {"status": "ignorado", "processados": 0}

    db_logs = [
        models.RawLog(source_ip=item.source_ip, event_type=item.event_type, payload=item.payload)
        for item in batch.logs
    ]
    db.bulk_save_objects(db_logs)
    db.commit()
    return {"status": "sucesso", "processados": len(db_logs)}

@app.get("/api/telemetry/feed")
def get_recent_telemetry(db: Session = Depends(get_db)):
    # Retorna os últimos 15 logs brutos que o Go mandou para o painel exibir
    logs = db.query(models.RawLog).order_by(models.RawLog.received_at.desc()).limit(15).all()
    return {"status": "sucesso", "total": len(logs), "logs": logs}


# --- CENTRAL DE INCIDENTES (CRUD) ---
@app.post("/api/incidents")
def create_incident(incident: IncidentCreate, db: Session = Depends(get_db)):
    novo = models.Incident(title=incident.title, notes=incident.notes)
    db.add(novo)
    db.commit()
    db.refresh(novo)
    return {"status": "sucesso", "incidente_id": novo.id}

@app.get("/api/incidents")
def list_incidents(db: Session = Depends(get_db)):
    # Lista todos os incidentes salvos na nuvem ordenados do mais recente
    incidentes = db.query(models.Incident).order_by(models.Incident.created_at.desc()).all()
    return {"status": "sucesso", "total": len(incidentes), "incidentes": incidentes}

@app.put("/api/incidents/{incident_id}")
def update_incident(incident_id: int, data: IncidentUpdate, db: Session = Depends(get_db)):
    incidente = db.query(models.Incident).filter(models.Incident.id == incident_id).first()
    if not incidente:
        raise HTTPException(status_code=404, detail="Incidente não encontrado.")
    
    if data.status: incidente.status = data.status
    if data.assigned_to: incidente.assigned_to = data.assigned_to
    if data.notes: incidente.notes = data.notes
        
    db.commit()
    db.refresh(incidente)
    return {"status": "sucesso", "detalhes": incidente}


# --- SOAR E GOVERNANÇA ---
@app.post("/api/soar/mitigate")
def mitigate_incident(data: RemediationRequest, db: Session = Depends(get_db)):
    # Simula bloqueio de conta ou isolamento de host via playbook
    if data.action == "block_user":
        resultado = f"Conta '{data.target}' desabilitada no Active Directory."
    elif data.action == "isolate_host":
        resultado = f"Host '{data.target}' isolado da rede por firewall."
    else:
        raise HTTPException(status_code=400, detail="Ação desconhecida.")
    
    log = models.AuditLog(action=f"SOAR: {data.action}", actor="System", target=data.target)
    db.add(log)
    db.commit()
    return {"status": "sucesso", "detalhe": resultado}

@app.get("/api/audit/identities")
def audit_identities():
    # Simula dados de compliance e contas inativas
    return {
        "status": "sucesso",
        "total_auditados": 3,
        "alertas_criticos": 1,
        "dados": [
            {"usuario": "paulo.terceiro", "email": "paulo@specter.local", "dias_inativo": 120, "status_mfa": "Desativado", "risco": "ALTO"},
            {"usuario": "carlos.silva", "email": "carlos@specter.local", "dias_inativo": 10, "status_mfa": "Ativo", "risco": "BAIXO"},
            {"usuario": "ana.souza", "email": "ana@specter.local", "dias_inativo": 5, "status_mfa": "Ativo", "risco": "BAIXO"}
        ]
    }

@app.post("/api/audit/revoke-inactive")
def revoke_inactive_accounts():
    return {"status": "sucesso", "detalhe": "Contas inativas bloqueadas com sucesso."}

@app.get("/api/capacity/prediction")
def capacity_prediction():
    return {
        "status": "sucesso",
        "metricas": [
            {"recurso": "Neon Postgres DB", "uso_atual": "78%", "taxa_crescimento": "+2.4%/dia", "tempo_estimado_esgotamento": "9 dias", "severidade": "CRITICO"},
            {"recurso": "Storage Logs SIEM", "uso_atual": "45%", "taxa_crescimento": "+0.5%/dia", "tempo_estimado_esgotamento": "110 dias", "severidade": "NORMAL"},
            {"recurso": "Pool RAM Workers", "uso_atual": "62%", "taxa_crescimento": "+1.1%/dia", "tempo_estimado_esgotamento": "34 dias", "severidade": "NORMAL"}
        ]
    }
from fastapi import FastAPI, HTTPException, status, Depends
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
import jwt
from datetime import datetime, timedelta, timezone
import os
import bcrypt
from dotenv import load_dotenv

# ---------------------------------------------------------
# BANCO DE DADOS (SQLAlchemy)
# ---------------------------------------------------------
from sqlalchemy.orm import Session
from database import engine, get_db
import models

# Cria todas as tabelas no banco de dados automaticamente (incluindo raw_logs)
models.Base.metadata.create_all(bind=engine)

# Carrega as variáveis de ambiente do arquivo .env
load_dotenv()

# Puxa as configurações seguras
SECRET_KEY = os.getenv("SECRET_KEY", "chave-super-secreta-specter")
ALGORITHM = os.getenv("ALGORITHM", "HS256")
ACCESS_TOKEN_EXPIRE_MINUTES = 30

def get_password_hash(password: str) -> str:
    """Recebe a senha em texto puro, gera o salt e retorna o hash."""
    pwd_bytes = password.encode('utf-8')
    salt = bcrypt.gensalt()
    hashed_password = bcrypt.hashpw(pwd_bytes, salt)
    return hashed_password.decode('utf-8')

def verify_password(plain_password: str, hashed_password: str) -> bool:
    """Compara a senha digitada no login com o hash salvo na base."""
    password_byte_enc = plain_password.encode('utf-8')
    hashed_password_bytes = hashed_password.encode('utf-8')
    return bcrypt.checkpw(password_byte_enc, hashed_password_bytes)

# ---------------------------------------------------------
# CONFIGURAÇÃO DA API (FASTAPI)
# ---------------------------------------------------------
app = FastAPI(
    title="Specter SIEM & Governance API",
    description="Backend avançado de Cibersegurança, Identidade, Incidentes e Telemetria em Alta Escala.",
    version="2.6.0"
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://localhost:5173", "http://127.0.0.1:5173"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# ---------------------------------------------------------
# MODELOS PYDANTIC
# ---------------------------------------------------------
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

# ---------------------------------------------------------
# ROTAS BASE
# ---------------------------------------------------------
@app.get("/")
def root():
    return {"status": "online", "message": "Specter SIEM conectado ao Banco Neon com suporte a Alta Escala!"}

@app.get("/api/health")
def health_check():
    return {"cpu_usage": "14%", "ram_usage": "48%", "status": "healthy"}

# ---------------------------------------------------------
# ROTAS DE AUTENTICAÇÃO E CADASTRO
# ---------------------------------------------------------
@app.post("/api/register")
def register_user(request: RegisterRequest, db: Session = Depends(get_db)):
    usuario_existente = db.query(models.User).filter(models.User.username == request.username).first()
    if usuario_existente:
        raise HTTPException(status_code=400, detail="Este nome de usuário já está cadastrado no sistema.")
    
    email_existente = db.query(models.User).filter(models.User.email == request.email).first()
    if email_existente:
        raise HTTPException(status_code=400, detail="Este e-mail já está em uso por outro operador.")
    
    senha_segura = get_password_hash(request.password)
    novo_usuario = models.User(
        username=request.username, email=request.email, hashed_password=senha_segura, role=request.role
    )
    
    db.add(novo_usuario)
    db.commit()
    db.refresh(novo_usuario)
    return {"status": "sucesso", "message": f"Usuário '{novo_usuario.username}' cadastrado com sucesso!"}

@app.post("/api/login")
def login(request: LoginRequest, db: Session = Depends(get_db)):
    usuario = db.query(models.User).filter(models.User.username == request.username).first()
    if not usuario or not verify_password(request.password, usuario.hashed_password):
        raise HTTPException(status_code=401, detail="Credenciais inválidas.")
    
    tempo_expiracao = datetime.now(timezone.utc) + timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    payload = {"sub": usuario.username, "role": usuario.role, "exp": tempo_expiracao}
    token = jwt.encode(payload, SECRET_KEY, algorithm=ALGORITHM)
    
    return {"access_token": token, "token_type": "bearer", "message": f"Bem-vindo, {usuario.role}."}

# ---------------------------------------------------------
# ROTAS DE SIEM E ALERTAS
# ---------------------------------------------------------
@app.post("/api/simulate-attack")
def simulate_attack(data: AttackSimulationRequest, db: Session = Depends(get_db)):
    cenarios = {
        "impossible_travel": {"nivel": "CRITICO", "mensagem": "Alerta de Viagem Impossível detectado em Active Directory."},
        "brute_force": {"nivel": "CRITICO", "mensagem": "Ataque de Força Bruta detectado na porta SSH/RDP."},
        "nmap_scan": {"nivel": "AVISO", "mensagem": "Varredura de portas (Nmap TCP SYN) identificada."},
        "azure_mfa": {"nivel": "CRITICO", "mensagem": "Tentativa de bypass de MFA bloqueada no Entra ID."}
    }
    
    if data.scenario not in cenarios:
        raise HTTPException(status_code=400, detail="Cenário de ataque inválido.")
    
    info = cenarios[data.scenario]
    novo_alerta = models.Alert(severity=info["nivel"], source=data.scenario, description=info["mensagem"])
    db.add(novo_alerta)
    db.commit()
    return {"status": "sucesso", "mensagem": "Ataque injetado com sucesso."}

@app.get("/api/alerts/poll")
def poll_alerts(db: Session = Depends(get_db)):
    alerta = db.query(models.Alert).filter(models.Alert.is_resolved == False).order_by(models.Alert.created_at.desc()).first()
    if not alerta:
        return None
    return {"nivel": alerta.severity, "mensagem": alerta.description}

# ---------------------------------------------------------
# TELEMETRIA EM ALTA ESCALA (RAW LOGS INGESTION)
# ---------------------------------------------------------
@app.post("/api/telemetry/ingest", status_code=202)
def ingest_telemetry(batch: TelemetryBatchRequest, db: Session = Depends(get_db)):
    """Recebe lotes de telemetria de agentes ou coletores externos e armazena na nuvem."""
    if not batch.logs:
        return {"status": "ignorado", "processados": 0}

    db_logs = [
        models.RawLog(
            source_ip=item.source_ip,
            event_type=item.event_type,
            payload=item.payload
        )
        for item in batch.logs
    ]
    
    db.bulk_save_objects(db_logs)
    db.commit()
    
    return {
        "status": "sucesso", 
        "processados": len(db_logs),
        "mensagem": "Lote de telemetria indexado com sucesso no PostgreSQL."
    }

@app.get("/api/telemetry/feed")
def get_recent_telemetry(db: Session = Depends(get_db)):
    """Retorna os últimos logs brutos capturados."""
    logs = db.query(models.RawLog).order_by(models.RawLog.received_at.desc()).limit(15).all()
    return {"status": "sucesso", "total": len(logs), "logs": logs}

# ---------------------------------------------------------
# CENTRAL DE INCIDENTES (CRUD)
# ---------------------------------------------------------
@app.post("/api/incidents")
def create_incident(incident: IncidentCreate, db: Session = Depends(get_db)):
    novo_incidente = models.Incident(title=incident.title, notes=incident.notes)
    db.add(novo_incidente)
    db.commit()
    db.refresh(novo_incidente)
    return {"status": "sucesso", "incidente_id": novo_incidente.id}

@app.get("/api/incidents")
def list_incidents(db: Session = Depends(get_db)):
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

# ---------------------------------------------------------
# ROTAS SOAR E GOVERNANÇA
# ---------------------------------------------------------
@app.post("/api/soar/mitigate")
def mitigate_incident(data: RemediationRequest, db: Session = Depends(get_db)):
    action = data.action
    target = data.target
    
    if action == "block_user":
        resultado = f"Conta '{target}' desabilitada no Active Directory / Entra ID."
    elif action == "isolate_host":
        resultado = f"Host '{target}' isolado da rede por políticas de firewall."
    else:
        raise HTTPException(status_code=400, detail="Ação de remediação desconhecida.")
    
    log_auditoria = models.AuditLog(
        action=f"SOAR_MITIGATION: {action}",
        actor="System (Automated)",
        target=target
    )
    db.add(log_auditoria)
    db.commit()
    
    return {"status": "sucesso", "detalhe": resultado}

@app.get("/api/audit/identities")
def audit_identities():
    return {
        "status": "sucesso",
        "total_auditados": 3,
        "alertas_criticos": 1,
        "dados": [
            {"usuario": "paulo.terceiro", "email": "paulo@specter-corp.local", "dias_inativo": 120, "status_mfa": "Desativado", "risco": "ALTO"},
            {"usuario": "carlos.silva", "email": "carlos@specter-corp.local", "dias_inativo": 10, "status_mfa": "Ativo", "risco": "BAIXO"},
            {"usuario": "ana.souza", "email": "ana@specter-corp.local", "dias_inativo": 5, "status_mfa": "Ativo", "risco": "BAIXO"}
        ]
    }

@app.post("/api/audit/revoke-inactive")
def revoke_inactive_accounts():
    return {
        "status": "sucesso",
        "detalhe": "Compliance executado: Contas inativas de alto risco foram bloqueadas com sucesso."
    }

@app.get("/api/capacity/prediction")
def capacity_prediction():
    return {
        "status": "sucesso",
        "metricas": [
            {"recurso": "Cluster Database (Neon Postgres)", "uso_atual": "78%", "taxa_crescimento": "+2.4%/dia", "tempo_estimado_esgotamento": "9 dias", "severidade": "CRITICO"},
            {"recurso": "Storage Logs SIEM", "uso_atual": "45%", "taxa_crescimento": "+0.5%/dia", "tempo_estimado_esgotamento": "110 dias", "severidade": "NORMAL"},
            {"recurso": "Pool Memória RAM (Workers)", "uso_atual": "62%", "taxa_crescimento": "+1.1%/dia", "tempo_estimado_esgotamento": "34 dias", "severidade": "NORMAL"}
        ]
    }
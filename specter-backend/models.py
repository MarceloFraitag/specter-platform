from sqlalchemy import Column, Integer, String, Text, Boolean, DateTime
from sqlalchemy.sql import func
from database import Base

class User(Base):
    __tablename__ = "users"

    id = Column(Integer, primary_key=True, index=True)
    username = Column(String, unique=True, index=True, nullable=False)
    email = Column(String, unique=True, index=True, nullable=False)
    hashed_password = Column(String, nullable=False)
    role = Column(String, default="Analista SOC")
    is_active = Column(Boolean, default=True)
    created_at = Column(DateTime(timezone=True), server_default=func.now())

class Alert(Base):
    __tablename__ = "alerts"

    id = Column(Integer, primary_key=True, index=True)
    severity = Column(String, nullable=False)  # Ex: CRITICO, AVISO
    source = Column(String, nullable=False)    # Ex: impossible_travel
    description = Column(String, nullable=False)
    created_at = Column(DateTime(timezone=True), server_default=func.now())
    is_resolved = Column(Boolean, default=False)

class Incident(Base):
    __tablename__ = "incidents"

    id = Column(Integer, primary_key=True, index=True)
    title = Column(String, nullable=False)
    status = Column(String, default="Aberto") # Aberto, Em Análise, Fechado
    assigned_to = Column(String, nullable=True) # Nome do analista
    notes = Column(String, nullable=True)
    created_at = Column(DateTime(timezone=True), server_default=func.now())

class AuditLog(Base):
    __tablename__ = "audit_logs"

    id = Column(Integer, primary_key=True, index=True)
    action = Column(String, nullable=False) # Ex: LOGIN, BLOCK_USER
    actor = Column(String, nullable=False)  # Quem fez a ação
    target = Column(String, nullable=True)  # Quem sofreu a ação
    timestamp = Column(DateTime(timezone=True), server_default=func.now())

class RawLog(Base):
    __tablename__ = "raw_logs"

    id = Column(Integer, primary_key=True, index=True)
    source_ip = Column(String(50), nullable=True)
    event_type = Column(String(100), index=True) # Ex: 'SYSLOG', 'WINDOWS_EVENT', 'AUTH_FAIL'
    payload = Column(Text, nullable=False)       # JSON ou texto bruto do log
    received_at = Column(DateTime(timezone=True), server_default=func.now())
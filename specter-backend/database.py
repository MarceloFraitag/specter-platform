import os
from sqlalchemy import create_engine
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import sessionmaker
from dotenv import load_dotenv

# Carrega as variáveis de ambiente do arquivo .env
load_dotenv()

# URL do PostgreSQL no Neon (com fallback para o SQLite local caso o .env não seja encontrado)
SQLALCHEMY_DATABASE_URL = os.getenv(
    "DATABASE_URL", 
    "postgresql://neondb_owner:npg_kdFbgBXm9K5c@ep-frosty-bread-ac7oxwzt-pooler.sa-east-1.aws.neon.tech/neondb?sslmode=require&channel_binding=require"
)

# Configuração do Engine do SQLAlchemy dependendo do tipo de banco
if SQLALCHEMY_DATABASE_URL.startswith("sqlite"):
    engine = create_engine(
        SQLALCHEMY_DATABASE_URL, connect_args={"check_same_thread": False}
    )
else:
    engine = create_engine(SQLALCHEMY_DATABASE_URL)

SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)

Base = declarative_base()

def get_db():
    """Gera uma sessão de conexão com o banco de dados por requisição."""
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()
# Puxa uma imagem oficial e leve do Python
FROM python:3.11-slim

# Define o diretório de trabalho de dentro do container
WORKDIR /app

# Copia e instala as dependências do projeto
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copia todo o resto do código do backend para dentro do container
COPY . .

# Expõe a porta padrão do FastAPI
EXPOSE 8000

# Comando para iniciar o servidor Uvicorn quando o container subir
CMD ["uvicorn", "main:app", "--host", "0.0.0.0", "--port", "8000"]
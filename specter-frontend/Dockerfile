# Imagem oficial do Node para build do React/Vite
FROM node:20-alpine

WORKDIR /app

# Copia arquivos de dependência primeiro (aproveita cache)
COPY package.json package-lock.json ./
RUN npm install

# Copia o restante do código do frontend
COPY . .

# Expõe a porta padrão do Vite
EXPOSE 5173

# Sobe o servidor de desenvolvimento acessível de fora do container
CMD ["npm", "run", "dev", "--", "--host", "0.0.0.0"]
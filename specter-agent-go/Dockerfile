# Imagem oficial do Go para build
FROM golang:1.27-alpine AS builder

WORKDIR /app

# Copia os arquivos de dependência primeiro (aproveita cache)
COPY go.mod ./
RUN go mod download

# Copia o restante do código do agente
COPY . .

# Compila o binário
RUN go build -o specter-agent .

# Imagem final, mais enxuta, só com o binário compilado
FROM alpine:latest

WORKDIR /app
COPY --from=builder /app/specter-agent .

CMD ["./specter-agent"]
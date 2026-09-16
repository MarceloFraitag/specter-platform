package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"time"
)

// Estrutura que mapeia exatamente o que o FastAPI espera no endpoint /api/telemetry/ingest
type LogItem struct {
	SourceIP  string `json:"source_ip"`
	EventType string `json:"event_type"`
	Payload   string `json:"payload"`
}

type TelemetryBatch struct {
	Logs []LogItem `json:"logs"`
}

func main() {
	// Endereço da nossa API em Python
	apiURL := "http://specter-backend:8000/api/telemetry/ingest"

	fmt.Println("==================================================")
	fmt.Println(" [SPECTER GO AGENT] Iniciando Coletor de Telemetria")
	fmt.Println(" Destino da API:", apiURL)
	fmt.Println("==================================================")

	// Listas de dados fictícios para simular eventos corporativos variados
	eventTypes := []string{"SYSLOG_AUTH", "WINDOWS_SECURITY_AUDIT", "FIREWALL_DROP", "EDP_ENDPOINT_ALERT"}
	sampleIPs := []string{"192.168.1.55", "10.0.4.12", "172.16.0.99", "203.0.113.45"}
	payloads := []string{
		"Failed password for root from 203.0.113.45 port 52311 ssh2",
		"Active Directory: User lockout threshold reached for account 'paulo.terceiro'",
		"Firewall Alert: Outbound connection blocked to known C2 server destination",
		"Sysmon: Process creation detected -> powershell.exe -enc JABh...",
	}

	// Cria um cronômetro (ticker) que dispara a cada 4 segundos
	ticker := time.NewTicker(4 * time.Second)
	defer ticker.Stop()

	counter := 1

	// Loop infinito que roda a cada tique do relógio
	for range ticker.C {
		// Monta o lote com 2 eventos simulados
		batch := TelemetryBatch{
			Logs: []LogItem{
				{
					SourceIP:  sampleIPs[counter%len(sampleIPs)],
					EventType: eventTypes[counter%len(eventTypes)],
					Payload:   payloads[counter%len(payloads)],
				},
				{
					SourceIP:  "192.168.1.100",
					EventType: "HEARTBEAT_AGENT",
					Payload:   fmt.Sprintf("Agent telemetry pulse #%d - System stable", counter),
				},
			},
		}

		// Converte a struct do Go para formato JSON bruto
		jsonData, err := json.Marshal(batch)
		if err != nil {
			fmt.Println("[ERRO] Falha ao serializar JSON:", err)
			continue
		}

		// Dispara a requisição HTTP POST assíncrona mandando o lote para o FastAPI
		resp, err := http.Post(apiURL, "application/json", bytes.NewBuffer(jsonData))
		if err != nil {
			fmt.Printf("[ERRO DE CONEXÃO]: FastAPI inacessível (%v)\n", err)
			continue
		}
		resp.Body.Close()

		// Confere se o backend aceitou o lote (Status 202 Accepted)
		if resp.StatusCode == http.StatusAccepted {
			fmt.Printf("[SUCESSO] Lote #%d enviado com 2 eventos de telemetria para o Neon DB.\n", counter)
		} else {
			fmt.Printf("[AVISO] Servidor respondeu com status code: %d\n", resp.StatusCode)
		}

		counter++
	}
}

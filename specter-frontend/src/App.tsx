import { useState, useEffect } from 'react';

// Aponta para o backend FastAPI rodando local
const API_URL = import.meta.env.VITE_API_URL || 'http://127.0.0.1:8000';

function App() {
  // Estados de controle de tela e autenticação
  const [isRegistering, setIsRegistering] = useState(false);
  const [username, setUsername] = useState('');
  const [password, setPassword] = useState('');
  const [email, setEmail] = useState('');
  const [role] = useState('Analista SOC');
  
  const [token, setToken] = useState<string | null>(null);
  const [error, setError] = useState('');
  const [successMessage, setSuccessMessage] = useState('');
  
  // Estados dos módulos do SIEM (Alertas, Incidentes, Logs do Go, etc)
  const [alerts, setAlerts] = useState<Array<{ nivel: string; mensagem: string }>>([]);
  const [systemHealth, setSystemHealth] = useState({ cpu_usage: '14%', ram_usage: '48%', status: 'healthy' });
  const [simulationStatus, setSimulationStatus] = useState<string | null>(null);

  const [identities, setIdentities] = useState<any[]>([]);
  const [auditSummary, setAuditSummary] = useState({ total_auditados: 0, alertas_criticos: 0 });
  const [complianceStatus, setComplianceStatus] = useState<string | null>(null);
  const [capacityMetrics, setCapacityMetrics] = useState<any[]>([]);
  
  const [incidents, setIncidents] = useState<any[]>([]);
  const [newIncidentTitle, setNewIncidentTitle] = useState('');
  const [rawLogs, setRawLogs] = useState<any[]>([]);

  // Faz o login e guarda o token JWT
  const handleLogin = async (e: React.FormEvent) => {
    e.preventDefault();
    setError('');
    setSuccessMessage('');

    try {
      const res = await fetch(`${API_URL}/api/login`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ username, password }),
      });
      const data = await res.json();
      if (!res.ok) throw new Error(data.detail || 'Falha ao logar.');
      setToken(data.access_token);
    } catch (err: any) {
      setError(err.message);
    }
  };

  // Cadastra um novo operador no banco
  const handleRegister = async (e: React.FormEvent) => {
    e.preventDefault();
    setError('');
    setSuccessMessage('');

    try {
      const res = await fetch(`${API_URL}/api/register`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ username, password, email, role }),
      });
      const data = await res.json();
      if (!res.ok) throw new Error(data.detail || 'Erro ao registrar.');
      setSuccessMessage(data.message);
      setIsRegistering(false);
      setPassword('');
    } catch (err: any) {
      setError(err.message);
    }
  };

  // Busca os incidentes salvos na nuvem
  const fetchIncidents = async () => {
    try {
      const res = await fetch(`${API_URL}/api/incidents`);
      const data = await res.json();
      if (data.status === 'sucesso') setIncidents(data.incidentes);
    } catch (e) {
      console.error("Erro ao buscar incidentes:", e);
    }
  };

  // Puxa os logs brutos que o script em Go está enviando
  const fetchRawLogs = async () => {
    try {
      const res = await fetch(`${API_URL}/api/telemetry/feed`);
      const data = await res.json();
      if (data.status === 'sucesso') setRawLogs(data.logs);
    } catch (e) {
      console.error("Erro ao buscar raw logs:", e);
    }
  };

  // Roda assim que o operador faz login (busca dados iniciais e ativa o polling de 3 em 3 segundos)
  useEffect(() => {
    if (!token) return;

    fetch(`${API_URL}/api/health`).then(res => res.json()).then(data => setSystemHealth(data));
    fetch(`${API_URL}/api/audit/identities`).then(res => res.json()).then(data => {
      if (data.status === 'sucesso') {
        setIdentities(data.dados);
        setAuditSummary({ total_auditados: data.total_auditados, alertas_criticos: data.alertas_criticos });
      }
    });
    fetch(`${API_URL}/api/capacity/prediction`).then(res => res.json()).then(data => {
      if (data.status === 'sucesso') setCapacityMetrics(data.metricas);
    });

    fetchIncidents();
    fetchRawLogs();

    // Loop que atualiza os alertas do simulador e o feed de logs do Go ao vivo
    const interval = setInterval(async () => {
      try {
        const res = await fetch(`${API_URL}/api/alerts/poll`);
        const newAlert = await res.json();
        if (newAlert && newAlert.mensagem) {
          setAlerts((prev) => {
            const list = prev || [];
            if (list.length > 0 && list[0].mensagem === newAlert.mensagem) return list;
            return [newAlert, ...list].slice(0, 8);
          });
        }
        fetchRawLogs();
      } catch (e) {
        console.error("Erro no polling:", e);
      }
    }, 3000);

    return () => clearInterval(interval);
  }, [token]);

  // Simula um ataque no Cyber Range
  const triggerAttack = async (scenario: string) => {
    setSimulationStatus(`Injetando: ${scenario}...`);
    try {
      const res = await fetch(`${API_URL}/api/simulate-attack`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ scenario }),
      });
      const data = await res.json();
      setSimulationStatus(res.ok ? `[SUCESSO] ${data.mensagem}` : `[ERRO] ${data.detail}`);
    } catch (err) {
      setSimulationStatus('[ERRO] Falha ao comunicar com o simulador.');
    }
    setTimeout(() => setSimulationStatus(null), 4000);
  };

  // Executa o compliance para revogar contas inativas de alto risco
  const handleRevokeInactive = async () => {
    try {
      const res = await fetch(`${API_URL}/api/audit/revoke-inactive`, { method: 'POST' });
      const data = await res.json();
      setComplianceStatus(data.detalhe);
      setIdentities(prev => (prev || []).map(item => item.risco === 'ALTO' ? { ...item, risco: 'REVOGADO', status_mfa: 'Bloqueado' } : item));
      setAuditSummary(prev => ({ ...prev, alertas_criticos: 0 }));
    } catch (e) {
      window.alert('Erro ao executar compliance.');
    }
  };

  // --- SE ESTIVER LOGADO: MOSTRA O PAINEL SOC COMPLETO ---
  if (token) {
    return (
      <div style={{ minHeight: '100vh', backgroundColor: '#050505', color: '#00ffff', fontFamily: 'Courier New, monospace', padding: '30px', boxSizing: 'border-box' }}>
        
        {/* Cabeçalho do Painel */}
        <header style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', borderBottom: '2px solid #ff007f', paddingBottom: '20px', marginBottom: '30px' }}>
          <div>
            <h1 style={{ fontSize: '28px', color: '#fcee0a', margin: 0, textTransform: 'uppercase', letterSpacing: '2px' }}>
              Specter SIEM & Governance Platform
            </h1>
            <p style={{ fontSize: '12px', color: '#00ffff', opacity: 0.8, margin: '5px 0 0 0' }}>
              Operador: <span style={{ color: '#ff007f' }}>{username}</span> | Domínio: specter-corp.local
            </p>
          </div>
          <button onClick={() => setToken(null)} style={{ all: 'unset', backgroundColor: 'transparent', border: '2px solid #ff007f', color: '#ff007f', padding: '10px 20px', fontWeight: 'bold', cursor: 'pointer', textTransform: 'uppercase' }}>
            Encerrar Sessão
          </button>
        </header>

        {/* Cards de Status do Servidor */}
        <div style={{ display: 'grid', gridTemplateColumns: 'repeat(3, 1fr)', gap: '20px', marginBottom: '30px' }}>
          <div style={{ backgroundColor: '#000', border: '2px solid #00ffff', padding: '20px' }}>
            <p style={{ fontSize: '12px', color: '#fcee0a', margin: '0 0 10px 0', textTransform: 'uppercase' }}>Cluster</p>
            <p style={{ fontSize: '20px', fontWeight: 'bold', margin: 0 }}>{systemHealth.status.toUpperCase()}</p>
          </div>
          <div style={{ backgroundColor: '#000', border: '2px solid #00ffff', padding: '20px' }}>
            <p style={{ fontSize: '12px', color: '#fcee0a', margin: '0 0 10px 0', textTransform: 'uppercase' }}>CPU</p>
            <p style={{ fontSize: '20px', fontWeight: 'bold', margin: 0, color: '#ff007f' }}>{systemHealth.cpu_usage}</p>
          </div>
          <div style={{ backgroundColor: '#000', border: '2px solid #00ffff', padding: '20px' }}>
            <p style={{ fontSize: '12px', color: '#fcee0a', margin: '0 0 10px 0', textTransform: 'uppercase' }}>Memória RAM</p>
            <p style={{ fontSize: '20px', fontWeight: 'bold', margin: 0 }}>{systemHealth.ram_usage}</p>
          </div>
        </div>

        {/* Central de Incidentes */}
        <div style={{ backgroundColor: '#000', border: '2px solid #00ffff', padding: '25px', marginBottom: '30px' }}>
          <h2 style={{ fontSize: '18px', color: '#fcee0a', marginTop: 0, marginBottom: '15px', textTransform: 'uppercase' }}>
            [Incident Command] Gestão de Incidentes (Banco Neon)
          </h2>
          <div style={{ display: 'flex', gap: '10px', marginBottom: '20px' }}>
            <input
              type="text"
              placeholder="Descrever novo incidente de segurança..."
              value={newIncidentTitle}
              onChange={(e) => setNewIncidentTitle(e.target.value)}
              style={{ flex: 1, backgroundColor: '#050505', border: '1px solid #00ffff', padding: '12px', color: '#00ffff', outline: 'none', fontFamily: 'Courier New, monospace' }}
            />
            <button
              onClick={async () => {
                if (!newIncidentTitle) return;
                const res = await fetch(`${API_URL}/api/incidents`, {
                  method: 'POST',
                  headers: { 'Content-Type': 'application/json' },
                  body: JSON.stringify({ title: newIncidentTitle, notes: `Aberto por ${username}` })
                });
                if (res.ok) { setNewIncidentTitle(''); fetchIncidents(); }
              }}
              style={{ all: 'unset', backgroundColor: '#fcee0a', color: '#000', padding: '12px 20px', fontWeight: 'bold', cursor: 'pointer', textTransform: 'uppercase', fontSize: '12px' }}
            >
              Criar Incidente
            </button>
          </div>

          <table style={{ width: '100%', borderCollapse: 'collapse', fontSize: '13px', textAlign: 'left' }}>
            <thead>
              <tr style={{ borderBottom: '2px solid #00ffff', color: '#fcee0a' }}>
                <th style={{ padding: '10px' }}>ID</th>
                <th style={{ padding: '10px' }}>Título</th>
                <th style={{ padding: '10px' }}>Status</th>
                <th style={{ padding: '10px' }}>Responsável</th>
                <th style={{ padding: '10px' }}>Ações</th>
              </tr>
            </thead>
            <tbody>
              {(incidents || []).length === 0 ? (
                <tr><td colSpan={5} style={{ padding: '15px', textAlign: 'center', opacity: 0.6 }}>Nenhum incidente registrado.</td></tr>
              ) : (
                (incidents || []).map((inc) => (
                  <tr key={inc.id} style={{ borderBottom: '1px solid rgba(255,255,255,0.1)' }}>
                    <td style={{ padding: '10px', color: '#fcee0a' }}>#{inc.id}</td>
                    <td style={{ padding: '10px' }}>{inc.title}</td>
                    <td style={{ padding: '10px', fontWeight: 'bold', color: inc.status === 'Aberto' ? '#ff007f' : '#00ff00' }}>{inc.status}</td>
                    <td style={{ padding: '10px', opacity: 0.8 }}>{inc.assigned_to || 'Não atribuído'}</td>
                    <td style={{ padding: '10px' }}>
                      <button
                        onClick={async () => {
                          await fetch(`${API_URL}/api/incidents/${inc.id}`, {
                            method: 'PUT',
                            headers: { 'Content-Type': 'application/json' },
                            body: JSON.stringify({ status: 'Mitigado', assigned_to: username })
                          });
                          fetchIncidents();
                        }}
                        style={{ all: 'unset', border: '1px solid #00ffff', color: '#00ffff', padding: '6px 10px', cursor: 'pointer', fontSize: '11px', textTransform: 'uppercase' }}
                      >
                        Mitigar
                      </button>
                    </td>
                  </tr>
                ))
              )}
            </tbody>
          </table>
        </div>

        {/* Stream de Telemetria do Agente Go */}
        <div style={{ backgroundColor: '#000', border: '2px solid #00ffff', padding: '25px', marginBottom: '30px' }}>
          <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '15px' }}>
            <h2 style={{ fontSize: '18px', color: '#fcee0a', margin: 0, textTransform: 'uppercase' }}>
              [Raw Telemetry Stream] Agente Go em Alta Escala
            </h2>
            <span style={{ fontSize: '11px', backgroundColor: '#00ffff', color: '#000', padding: '4px 8px', fontWeight: 'bold' }}>Live</span>
          </div>
          <div style={{ maxHeight: '220px', overflowY: 'auto', backgroundColor: '#050505', border: '1px solid rgba(0,255,255,0.3)', padding: '15px' }}>
            {(rawLogs || []).length === 0 ? (
              <p style={{ color: '#00ffff', opacity: 0.5, fontStyle: 'italic', textAlign: 'center', margin: 0 }}>Aguardando pacotes do agente Go (`go run main.go`)...</p>
            ) : (
              <div style={{ display: 'flex', flexDirection: 'column', gap: '8px', fontSize: '12px' }}>
                {(rawLogs || []).map((log) => (
                  <div key={log.id} style={{ display: 'flex', justifyContent: 'space-between', borderBottom: '1px dashed rgba(255,255,255,0.1)', paddingBottom: '6px' }}>
                    <div>
                      <span style={{ color: '#fcee0a', marginRight: '10px' }}>[{log.event_type}]</span>
                      <span>{log.payload}</span>
                    </div>
                    <div style={{ textAlign: 'right', fontSize: '11px', opacity: 0.6 }}>
                      <span style={{ color: '#ff007f', marginRight: '8px' }}>IP: {log.source_ip}</span>
                      <span>{new Date(log.received_at).toLocaleTimeString()}</span>
                    </div>
                  </div>
                ))}
              </div>
            )}
          </div>
        </div>

        {/* Governança e Contas Inativas */}
        <div style={{ backgroundColor: '#000', border: '2px solid #00ffff', padding: '25px', marginBottom: '30px' }}>
          <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '15px' }}>
            <h2 style={{ fontSize: '18px', color: '#fcee0a', margin: 0, textTransform: 'uppercase' }}>[Governance] Auditoria de Contas Inativas</h2>
            <span style={{ fontSize: '12px', backgroundColor: auditSummary.alertas_criticos > 0 ? '#ff007f' : '#00ff00', color: '#000', padding: '4px 10px', fontWeight: 'bold' }}>
              {auditSummary.alertas_criticos} Riscos Críticos
            </span>
          </div>
          <table style={{ width: '100%', borderCollapse: 'collapse', fontSize: '13px', textAlign: 'left', marginBottom: '15px' }}>
            <thead>
              <tr style={{ borderBottom: '2px solid #00ffff', color: '#fcee0a' }}>
                <th style={{ padding: '10px' }}>Usuário</th>
                <th style={{ padding: '10px' }}>E-mail</th>
                <th style={{ padding: '10px' }}>Inativo há</th>
                <th style={{ padding: '10px' }}>MFA</th>
                <th style={{ padding: '10px' }}>Risco</th>
              </tr>
            </thead>
            <tbody>
              {(identities || []).map((item, idx) => (
                <tr key={idx} style={{ borderBottom: '1px solid rgba(255,255,255,0.1)' }}>
                  <td style={{ padding: '10px' }}>{item.usuario}</td>
                  <td style={{ padding: '10px', opacity: 0.8 }}>{item.email}</td>
                  <td style={{ padding: '10px' }}>{item.dias_inativo} dias</td>
                  <td style={{ padding: '10px' }}>{item.status_mfa}</td>
                  <td style={{ padding: '10px', fontWeight: 'bold', color: item.risco === 'ALTO' ? '#ff007f' : '#fcee0a' }}>{item.risco}</td>
                </tr>
              ))}
            </tbody>
          </table>
          <button onClick={handleRevokeInactive} style={{ all: 'unset', backgroundColor: '#00ffff', color: '#000', padding: '10px 18px', fontWeight: 'bold', fontSize: '12px', cursor: 'pointer', textTransform: 'uppercase' }}>
            Revogar Contas Inativas em Lote
          </button>
          {complianceStatus && <span style={{ fontSize: '12px', color: '#fcee0a', marginLeft: '15px' }}>{complianceStatus}</span>}
        </div>

        {/* Capacity Planning */}
        <div style={{ backgroundColor: '#000', border: '2px solid #fcee0a', padding: '25px', marginBottom: '30px' }}>
          <h2 style={{ fontSize: '18px', color: '#fcee0a', marginTop: 0, marginBottom: '15px', textTransform: 'uppercase' }}>[Capacity Planning] Previsão de Infraestrutura</h2>
          <div style={{ display: 'grid', gridTemplateColumns: 'repeat(3, 1fr)', gap: '15px' }}>
            {(capacityMetrics || []).map((cap, idx) => (
              <div key={idx} style={{ padding: '15px', backgroundColor: cap.severidade === 'CRITICO' ? 'rgba(255,0,127,0.1)' : 'rgba(0,255,255,0.05)', border: `1px solid ${cap.severidade === 'CRITICO' ? '#ff007f' : '#00ffff'}` }}>
                <p style={{ fontSize: '13px', color: '#fcee0a', fontWeight: 'bold', margin: '0 0 8px 0' }}>{cap.recurso}</p>
                <p style={{ fontSize: '12px', margin: '4px 0' }}>Uso: <strong style={{ color: '#ff007f' }}>{cap.uso_atual}</strong></p>
                <p style={{ fontSize: '12px', margin: '8px 0 0 0', fontWeight: 'bold' }}>Esgotamento em: {cap.tempo_estimado_esgotamento}</p>
              </div>
            ))}
          </div>
        </div>

        {/* Simulador de Ataques (Cyber Range) */}
        <div style={{ backgroundColor: '#000', border: '2px solid #fcee0a', padding: '20px', marginBottom: '30px' }}>
          <h2 style={{ fontSize: '16px', color: '#fcee0a', marginTop: 0, marginBottom: '15px', textTransform: 'uppercase' }}>[Cyber Range] Simulador de Ataques</h2>
          <div style={{ display: 'grid', gridTemplateColumns: 'repeat(4, 1fr)', gap: '15px' }}>
            <button onClick={() => triggerAttack('impossible_travel')} style={{ all: 'unset', textAlign: 'center', backgroundColor: '#050505', border: '2px solid #ff007f', color: '#ff007f', padding: '12px', fontWeight: 'bold', cursor: 'pointer', fontSize: '12px', textTransform: 'uppercase' }}>Viagem Impossível</button>
            <button onClick={() => triggerAttack('brute_force')} style={{ all: 'unset', textAlign: 'center', backgroundColor: '#050505', border: '2px solid #ff007f', color: '#ff007f', padding: '12px', fontWeight: 'bold', cursor: 'pointer', fontSize: '12px', textTransform: 'uppercase' }}>Força Bruta</button>
            <button onClick={() => triggerAttack('nmap_scan')} style={{ all: 'unset', textAlign: 'center', backgroundColor: '#050505', border: '2px solid #fcee0a', color: '#fcee0a', padding: '12px', fontWeight: 'bold', cursor: 'pointer', fontSize: '12px', textTransform: 'uppercase' }}>Varredura Nmap</button>
            <button onClick={() => triggerAttack('azure_mfa')} style={{ all: 'unset', textAlign: 'center', backgroundColor: '#050505', border: '2px solid #fcee0a', color: '#fcee0a', padding: '12px', fontWeight: 'bold', cursor: 'pointer', fontSize: '12px', textTransform: 'uppercase' }}>Bypass MFA</button>
          </div>
          {simulationStatus && <div style={{ marginTop: '12px', padding: '8px', backgroundColor: 'rgba(252,238,10,0.1)', border: '1px solid #fcee0a', fontSize: '12px', color: '#fcee0a', textAlign: 'center' }}>{simulationStatus}</div>}
        </div>

        {/* Live Feed de Alertas e SOAR */}
        <div style={{ backgroundColor: '#000', border: '2px solid #ff007f', padding: '25px' }}>
          <h2 style={{ fontSize: '18px', color: '#fcee0a', marginTop: 0, marginBottom: '20px', textTransform: 'uppercase' }}>[Live Feed] Alertas & Playbooks SOAR</h2>
          {(alerts || []).length === 0 ? (
            <p style={{ color: '#00ffff', opacity: 0.7, fontStyle: 'italic' }}>Aguardando eventos...</p>
          ) : (
            <div style={{ display: 'flex', flexDirection: 'column', gap: '15px' }}>
              {(alerts || []).map((alert, index) => (
                <div key={index} style={{ padding: '16px', backgroundColor: 'rgba(255,0,127,0.15)', borderLeft: '4px solid #ff007f' }}>
                  <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '10px' }}>
                    <span>{alert.mensagem}</span>
                    <span style={{ fontSize: '11px', fontWeight: 'bold', padding: '4px 8px', backgroundColor: '#ff007f', color: '#000' }}>{alert.nivel}</span>
                  </div>
                  <button
                    onClick={async () => {
                      const res = await fetch(`${API_URL}/api/soar/mitigate`, {
                        method: 'POST',
                        headers: { 'Content-Type': 'application/json' },
                        body: JSON.stringify({ action: 'block_user', target: username })
                      });
                      const result = await res.json();
                      window.alert(result.detalhe + "\nSessão encerrada.");
                      setToken(null);
                    }}
                    style={{ all: 'unset', backgroundColor: '#ff007f', color: '#000', padding: '8px 14px', fontWeight: 'bold', fontSize: '11px', cursor: 'pointer', textTransform: 'uppercase' }}
                  >
                    [SOAR] Bloquear Conta / Encerrar Sessão
                  </button>
                </div>
              ))}
            </div>
          )}
        </div>
      </div>
    );
  }

  // --- TELA DE LOGIN / CADASTRO ---
  return (
    <div style={{ position: 'fixed', top: 0, left: 0, width: '100vw', height: '100vh', backgroundColor: '#050505', color: '#00ffff', display: 'flex', alignItems: 'center', justifyContent: 'center', fontFamily: 'Courier New, monospace' }}>
      <div style={{ width: '100%', maxWidth: '520px', backgroundColor: '#000000', border: '2px solid #00ffff', padding: '40px', boxSizing: 'border-box' }}>
        <h1 style={{ fontSize: '24px', color: '#fcee0a', textAlign: 'center', marginBottom: '30px', textTransform: 'uppercase', borderBottom: '2px solid #ff007f', paddingBottom: '15px' }}>
          {isRegistering ? 'Specter [Cadastro]' : 'Specter [Auth]'}
        </h1>

        <form onSubmit={isRegistering ? handleRegister : handleLogin} style={{ display: 'flex', flexDirection: 'column', gap: '20px' }}>
          <div>
            <label style={{ display: 'block', fontSize: '14px', marginBottom: '8px', fontWeight: 'bold', textTransform: 'uppercase' }}>Usuário:</label>
            <input type="text" value={username} onChange={(e) => setUsername(e.target.value)} style={{ width: '100%', backgroundColor: '#050505', border: '2px solid rgba(0,255,255,0.6)', padding: '14px', color: '#00ffff', outline: 'none', boxSizing: 'border-box' }} required />
          </div>

          {isRegistering && (
            <div>
              <label style={{ display: 'block', fontSize: '14px', marginBottom: '8px', fontWeight: 'bold', textTransform: 'uppercase' }}>E-mail:</label>
              <input type="email" value={email} onChange={(e) => setEmail(e.target.value)} style={{ width: '100%', backgroundColor: '#050505', border: '2px solid rgba(0,255,255,0.6)', padding: '14px', color: '#00ffff', outline: 'none', boxSizing: 'border-box' }} required />
            </div>
          )}

          <div>
            <label style={{ display: 'block', fontSize: '14px', marginBottom: '8px', fontWeight: 'bold', textTransform: 'uppercase' }}>Senha:</label>
            <input type="password" value={password} onChange={(e) => setPassword(e.target.value)} style={{ width: '100%', backgroundColor: '#050505', border: '2px solid rgba(0,255,255,0.6)', padding: '14px', color: '#00ffff', outline: 'none', boxSizing: 'border-box' }} required />
          </div>

          {error && <div style={{ padding: '12px', backgroundColor: 'rgba(255,0,127,0.2)', border: '2px solid #ff007f', color: '#ff007f', fontSize: '13px', textAlign: 'center', fontWeight: 'bold' }}>{error}</div>}
          {successMessage && <div style={{ padding: '12px', backgroundColor: 'rgba(0,255,255,0.1)', border: '2px solid #00ffff', color: '#00ffff', fontSize: '13px', textAlign: 'center', fontWeight: 'bold' }}>{successMessage}</div>}

          <button type="submit" style={{ all: 'unset', display: 'block', textAlign: 'center', width: '100%', backgroundColor: '#ff007f', color: '#000', fontWeight: 'bold', padding: '16px', cursor: 'pointer', textTransform: 'uppercase' }}>
            {isRegistering ? 'Cadastrar Operador' : 'Entrar na Plataforma'}
          </button>

          <button type="button" onClick={() => { setIsRegistering(!isRegistering); setError(''); setSuccessMessage(''); }} style={{ all: 'unset', textAlign: 'center', cursor: 'pointer', fontSize: '12px', color: '#00ffff', opacity: 0.8, textTransform: 'uppercase' }}>
            {isRegistering ? 'Já tem conta? Fazer Login' : 'Não tem acesso? Cadastre-se'}
          </button>
        </form>
      </div>
    </div>
  );
}

export default App;
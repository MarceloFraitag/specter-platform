import { useState, useEffect } from 'react';

// marcelo: Define a URL da API dinamicamente (pega a variável de ambiente da Vercel ou cai para o localhost)
const API_URL = import.meta.env.VITE_API_URL || 'http://localhost:8000';

function App() {
  // marcelo: Controla se a tela atual é o Login (false) ou o Cadastro (true)
  const [isRegistering, setIsRegistering] = useState(false);

  // marcelo: Estados para captação dos dados de formulário (removido setRole não utilizado)
  const [username, setUsername] = useState('');
  const [password, setPassword] = useState('');
  const [email, setEmail] = useState('');
  const [role] = useState('Analista SOC');
  
  const [token, setToken] = useState<string | null>(null);
  const [error, setError] = useState('');
  const [successMessage, setSuccessMessage] = useState('');
  
  // marcelo: Estados do SOC e Governança
  const [alerts, setAlerts] = useState<Array<{ nivel: string; mensagem: string }>>([]);
  const [systemHealth, setSystemHealth] = useState({ cpu_usage: '14%', ram_usage: '48%', status: 'healthy' });
  const [simulationStatus, setSimulationStatus] = useState<string | null>(null);

  const [identities, setIdentities] = useState<any[]>([]);
  const [auditSummary, setAuditSummary] = useState({ total_auditados: 0, alertas_criticos: 0 });
  const [capacityMetrics, setCapacityMetrics] = useState<any[]>([]);
  const [complianceStatus, setComplianceStatus] = useState<string | null>(null);

  // marcelo: Função de Autenticação utilizando o API_URL dinâmico
  const handleLogin = async (e: React.FormEvent) => {
    e.preventDefault();
    setError('');
    setSuccessMessage('');

    try {
      const response = await fetch(`${API_URL}/api/login`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ username, password }),
      });

      const data = await response.json();

      if (!response.ok) {
        throw new Error(data.detail || 'Falha na autenticação.');
      }

      setToken(data.access_token);
    } catch (err: any) {
      setError(err.message || 'Erro de conexão com o servidor.');
    }
  };

  // marcelo: Função de Registro de Novo Operador utilizando o API_URL dinâmico
  const handleRegister = async (e: React.FormEvent) => {
    e.preventDefault();
    setError('');
    setSuccessMessage('');

    try {
      const response = await fetch(`${API_URL}/api/register`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ username, password, email, role }),
      });

      const data = await response.json();

      if (!response.ok) {
        throw new Error(data.detail || 'Falha ao registrar usuário.');
      }

      setSuccessMessage(data.message);
      setIsRegistering(false); // Retorna para o login após o cadastro
      setPassword('');
    } catch (err: any) {
      setError(err.message || 'Erro de conexão com o servidor.');
    }
  };

  // marcelo: Carregamento de dados pós-login utilizando o API_URL dinâmico
  useEffect(() => {
    if (!token) return;

    fetch(`${API_URL}/api/health`)
      .then(res => res.json())
      .then(data => setSystemHealth(data))
      .catch(err => console.error("Erro ao buscar health:", err));

    fetch(`${API_URL}/api/audit/identities`)
      .then(res => res.json())
      .then(data => {
        if (data.status === 'sucesso') {
          setIdentities(data.dados);
          setAuditSummary({ total_auditados: data.total_auditados, alertas_criticos: data.alertas_criticos });
        }
      })
      .catch(err => console.error("Erro ao buscar identidades:", err));

    fetch(`${API_URL}/api/capacity/prediction`)
      .then(res => res.json())
      .then(data => {
        if (data.status === 'sucesso') {
          setCapacityMetrics(data.metricas);
        }
      })
      .catch(err => console.error("Erro ao buscar capacity planning:", err));

    const interval = setInterval(async () => {
      try {
        const res = await fetch(`${API_URL}/api/alerts/poll`);
        const newAlert = await res.json();
        
        if (newAlert) {
          setAlerts((prev) => {
            if (prev.length > 0 && prev[0].mensagem === newAlert.mensagem) {
              return prev;
            }
            return [newAlert, ...prev].slice(0, 8);
          });
        }
      } catch (e) {
        console.error("Erro ao buscar telemetria:", e);
      }
    }, 3000);

    return () => clearInterval(interval);
  }, [token]);

  const triggerAttack = async (scenario: string) => {
    setSimulationStatus(`Injetando cenário: ${scenario}...`);
    try {
      const res = await fetch(`${API_URL}/api/simulate-attack`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ scenario }),
      });
      const data = await res.json();
      if (res.ok) {
        setSimulationStatus(`[SUCESSO] ${data.mensagem}`);
      } else {
        setSimulationStatus(`[ERRO] ${data.detail}`);
      }
    } catch (err) {
      setSimulationStatus('[ERRO] Falha ao comunicar com o simulador.');
    }
    setTimeout(() => setSimulationStatus(null), 4000);
  };

  const handleRevokeInactive = async () => {
    try {
      const res = await fetch(`${API_URL}/api/audit/revoke-inactive`, {
        method: 'POST',
      });
      const data = await res.json();
      setComplianceStatus(data.detalhe);
      setIdentities(prev => prev.map(item => item.risco === 'ALTO' ? { ...item, risco: 'REVOGADO', status_mfa: 'Desativado (Bloqueado)' } : item));
      setAuditSummary(prev => ({ ...prev, alertas_criticos: 0 }));
    } catch (e) {
      window.alert('Erro ao executar compliance automatizado.');
    }
  };

  // marcelo: Dashboard Principal do SIEM
  if (token) {
    return (
      <div style={{
        minHeight: '100vh',
        backgroundColor: '#050505',
        color: '#00ffff',
        fontFamily: 'Courier New, monospace',
        padding: '30px',
        boxSizing: 'border-box'
      }}>
        <header style={{
          display: 'flex',
          justifyContent: 'space-between',
          alignItems: 'center',
          borderBottom: '2px solid #ff007f',
          paddingBottom: '20px',
          marginBottom: '30px'
        }}>
          <div>
            <h1 style={{ fontSize: '28px', color: '#fcee0a', margin: 0, textTransform: 'uppercase', letterSpacing: '2px', textShadow: '0 0 10px rgba(252, 238, 10, 0.8)' }}>
              Specter SIEM & Governance Platform
            </h1>
            <p style={{ fontSize: '12px', color: '#00ffff', opacity: 0.8, margin: '5px 0 0 0' }}>
              Operador Ativo: <span style={{ color: '#ff007f' }}>{username}</span> | Domínio: specter-corp.local
            </p>
          </div>
          <button
            onClick={() => setToken(null)}
            style={{
              all: 'unset',
              boxSizing: 'border-box',
              display: 'inline-block',
              backgroundColor: 'transparent',
              border: '2px solid #ff007f',
              color: '#ff007f',
              padding: '10px 20px',
              fontWeight: 'bold',
              cursor: 'pointer',
              textTransform: 'uppercase',
              letterSpacing: '1px',
              boxShadow: '0 0 10px rgba(255, 0, 127, 0.4)'
            }}
          >
            Encerrar Sessão
          </button>
        </header>

        <div style={{ display: 'grid', gridTemplateColumns: 'repeat(3, 1fr)', gap: '20px', marginBottom: '30px' }}>
          <div style={{ backgroundColor: '#000', border: '2px solid #00ffff', padding: '20px', boxShadow: '0 0 15px rgba(0, 255, 255, 0.2)' }}>
            <p style={{ fontSize: '12px', color: '#fcee0a', margin: '0 0 10px 0', textTransform: 'uppercase' }}>Status do Cluster</p>
            <p style={{ fontSize: '20px', fontWeight: 'bold', margin: 0, color: '#00ffff' }}>{systemHealth.status.toUpperCase()}</p>
          </div>
          <div style={{ backgroundColor: '#000', border: '2px solid #00ffff', padding: '20px', boxShadow: '0 0 15px rgba(0, 255, 255, 0.2)' }}>
            <p style={{ fontSize: '12px', color: '#fcee0a', margin: '0 0 10px 0', textTransform: 'uppercase' }}>Carga de CPU</p>
            <p style={{ fontSize: '20px', fontWeight: 'bold', margin: 0, color: '#ff007f' }}>{systemHealth.cpu_usage}</p>
          </div>
          <div style={{ backgroundColor: '#000', border: '2px solid #00ffff', padding: '20px', boxShadow: '0 0 15px rgba(0, 255, 255, 0.2)' }}>
            <p style={{ fontSize: '12px', color: '#fcee0a', margin: '0 0 10px 0', textTransform: 'uppercase' }}>Uso de Memória RAM</p>
            <p style={{ fontSize: '20px', fontWeight: 'bold', margin: 0, color: '#00ffff' }}>{systemHealth.ram_usage}</p>
          </div>
        </div>

        <div style={{ backgroundColor: '#000', border: '2px solid #00ffff', padding: '25px', marginBottom: '30px', boxShadow: '0 0 25px rgba(0, 255, 255, 0.2)' }}>
          <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '15px' }}>
            <h2 style={{ fontSize: '18px', color: '#fcee0a', margin: 0, textTransform: 'uppercase', letterSpacing: '1px' }}>
              [Governance] Auditoria de Contas Inativas & Risco de Identidade
            </h2>
            <span style={{ fontSize: '12px', backgroundColor: auditSummary.alertas_criticos > 0 ? '#ff007f' : '#00ff00', color: '#000', padding: '4px 10px', fontWeight: 'bold' }}>
              {auditSummary.alertas_criticos} Riscos Críticos Encontrados
            </span>
          </div>
          <p style={{ fontSize: '12px', color: '#00ffff', opacity: 0.8, marginBottom: '20px' }}>
            Monitoramento de contas corporativas sem login há mais de 90 dias e ausência de MFA:
          </p>

          <div style={{ overflowX: 'auto', marginBottom: '15px' }}>
            <table style={{ width: '100%', borderCollapse: 'collapse', fontSize: '13px', textAlign: 'left' }}>
              <thead>
                <tr style={{ borderBottom: '2px solid #00ffff', color: '#fcee0a' }}>
                  <th style={{ padding: '10px' }}>Usuário</th>
                  <th style={{ padding: '10px' }}>E-mail</th>
                  <th style={{ padding: '10px' }}>Dias Inativo</th>
                  <th style={{ padding: '10px' }}>Status MFA</th>
                  <th style={{ padding: '10px' }}>Nível de Risco</th>
                </tr>
              </thead>
              <tbody>
                {identities.map((item, idx) => (
                  <tr key={idx} style={{ borderBottom: '1px solid rgba(255,255,255,0.1)' }}>
                    <td style={{ padding: '10px', color: '#00ffff' }}>{item.usuario}</td>
                    <td style={{ padding: '10px', opacity: 0.8 }}>{item.email}</td>
                    <td style={{ padding: '10px' }}>{item.dias_inativo} dias</td>
                    <td style={{ padding: '10px' }}>{item.status_mfa}</td>
                    <td style={{ padding: '10px', fontWeight: 'bold', color: item.risco === 'ALTO' ? '#ff007f' : item.risco === 'REVOGADO' ? '#888' : '#fcee0a' }}>
                      {item.risco}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>

          <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
            <button
              onClick={handleRevokeInactive}
              style={{
                all: 'unset',
                boxSizing: 'border-box',
                backgroundColor: '#00ffff',
                color: '#000000',
                padding: '10px 18px',
                fontWeight: '900',
                fontSize: '12px',
                cursor: 'pointer',
                textTransform: 'uppercase',
                letterSpacing: '1px',
                boxShadow: '0 0 10px rgba(0, 255, 255, 0.6)'
              }}
            >
              [SOAR Compliance] Revogar Contas Inativas em Lote
            </button>
            {complianceStatus && (
              <span style={{ fontSize: '12px', color: '#fcee0a' }}>{complianceStatus}</span>
            )}
          </div>
        </div>

        <div style={{ backgroundColor: '#000', border: '2px solid #fcee0a', padding: '25px', marginBottom: '30px', boxShadow: '0 0 25px rgba(252, 238, 10, 0.2)' }}>
          <h2 style={{ fontSize: '18px', color: '#fcee0a', marginTop: 0, marginBottom: '15px', textTransform: 'uppercase', letterSpacing: '1px' }}>
            [Capacity Planning] Previsão Preditiva de Esgotamento de Infraestrutura
          </h2>
          <p style={{ fontSize: '12px', color: '#00ffff', opacity: 0.8, marginBottom: '20px' }}>
            Análise baseada em tendência de crescimento para evitar quedas inesperadas de servidores:
          </p>

          <div style={{ display: 'grid', gridTemplateColumns: 'repeat(3, 1fr)', gap: '15px' }}>
            {capacityMetrics.map((cap, idx) => {
              const isCrit = cap.severidade === 'CRITICO';
              return (
                <div key={idx} style={{
                  padding: '15px',
                  backgroundColor: isCrit ? 'rgba(255, 0, 127, 0.1)' : 'rgba(0, 255, 255, 0.05)',
                  border: `1px solid ${isCrit ? '#ff007f' : '#00ffff'}`,
                  boxShadow: isCrit ? '0 0 10px rgba(255, 0, 127, 0.3)' : 'none'
                }}>
                  <p style={{ fontSize: '13px', color: '#fcee0a', fontWeight: 'bold', margin: '0 0 8px 0' }}>{cap.recurso}</p>
                  <p style={{ fontSize: '12px', margin: '4px 0' }}>Uso Atual: <strong style={{ color: isCrit ? '#ff007f' : '#00ffff' }}>{cap.uso_atual}</strong></p>
                  <p style={{ fontSize: '12px', margin: '4px 0', opacity: 0.8 }}>Crescimento: {cap.taxa_crescimento}</p>
                  <p style={{ fontSize: '12px', margin: '8px 0 0 0', fontWeight: 'bold', color: isCrit ? '#ff007f' : '#00ffff' }}>
                    Esgotamento em: {cap.tempo_estimado_esgotamento}
                  </p>
                </div>
              );
            })}
          </div>
        </div>

        <div style={{ backgroundColor: '#000', border: '2px solid #fcee0a', padding: '20px', marginBottom: '30px', boxShadow: '0 0 20px rgba(252, 238, 10, 0.2)' }}>
          <h2 style={{ fontSize: '16px', color: '#fcee0a', marginTop: 0, marginBottom: '15px', textTransform: 'uppercase', letterSpacing: '1px' }}>
            [Cyber Range] Simulador de Injeção de Ataques SIEM
          </h2>
          <div style={{ display: 'grid', gridTemplateColumns: 'repeat(4, 1fr)', gap: '15px' }}>
            <button
              onClick={() => triggerAttack('impossible_travel')}
              style={{ all: 'unset', boxSizing: 'border-box', display: 'inline-block', textAlign: 'center', backgroundColor: '#050505', border: '2px solid #ff007f', color: '#ff007f', padding: '12px', fontWeight: 'bold', cursor: 'pointer', fontSize: '12px', textTransform: 'uppercase' }}
            >
              Viagem Impossível
            </button>
            <button
              onClick={() => triggerAttack('brute_force')}
              style={{ all: 'unset', boxSizing: 'border-box', display: 'inline-block', textAlign: 'center', backgroundColor: '#050505', border: '2px solid #ff007f', color: '#ff007f', padding: '12px', fontWeight: 'bold', cursor: 'pointer', fontSize: '12px', textTransform: 'uppercase' }}
            >
              Força Bruta
            </button>
            <button
              onClick={() => triggerAttack('nmap_scan')}
              style={{ all: 'unset', boxSizing: 'border-box', display: 'inline-block', textAlign: 'center', backgroundColor: '#050505', border: '2px solid #fcee0a', color: '#fcee0a', padding: '12px', fontWeight: 'bold', cursor: 'pointer', fontSize: '12px', textTransform: 'uppercase' }}
            >
              Varredura Nmap
            </button>
            <button
              onClick={() => triggerAttack('azure_mfa')}
              style={{ all: 'unset', boxSizing: 'border-box', display: 'inline-block', textAlign: 'center', backgroundColor: '#050505', border: '2px solid #fcee0a', color: '#fcee0a', padding: '12px', fontWeight: 'bold', cursor: 'pointer', fontSize: '12px', textTransform: 'uppercase' }}
            >
              Bypass MFA (Entra ID)
            </button>
          </div>
          {simulationStatus && (
            <div style={{ marginTop: '12px', padding: '8px', backgroundColor: 'rgba(252, 238, 10, 0.1)', border: '1px solid #fcee0a', fontSize: '12px', color: '#fcee0a', textAlign: 'center' }}>
              {simulationStatus}
            </div>
          )}
        </div>

        <div style={{ backgroundColor: '#000', border: '2px solid #ff007f', padding: '25px', boxShadow: '0 0 25px rgba(255, 0, 127, 0.3)' }}>
          <h2 style={{ fontSize: '18px', color: '#fcee0a', marginTop: 0, marginBottom: '20px', textTransform: 'uppercase', letterSpacing: '1px' }}>
            [Live Feed] Alertas de Segurança & Playbooks SOAR
          </h2>
          
          {alerts.length === 0 ? (
            <p style={{ color: '#00ffff', opacity: 0.7, fontStyle: 'italic' }}>Aguardando injeção de eventos de telemetria no Cyber Range...</p>
          ) : (
            <div style={{ display: 'flex', flexDirection: 'column', gap: '15px' }}>
              {alerts.map((alert, index) => {
                const isCritico = alert.nivel === 'CRITICO' || alert.nivel === 'Crítico';

                return (
                  <div key={index} style={{
                    padding: '16px',
                    backgroundColor: isCritico ? 'rgba(255, 0, 127, 0.15)' : 'rgba(0, 255, 255, 0.05)',
                    borderTop: '1px solid rgba(255, 255, 255, 0.1)',
                    borderRight: '1px solid rgba(255, 255, 255, 0.1)',
                    borderBottom: '1px solid rgba(255, 255, 255, 0.1)',
                    borderLeft: `4px solid ${isCritico ? '#ff007f' : '#fcee0a'}`,
                  }}>
                    <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '10px' }}>
                      <span style={{ fontSize: '14px', color: '#00ffff' }}>{alert.mensagem}</span>
                      <span style={{
                        fontSize: '11px',
                        fontWeight: 'bold',
                        padding: '4px 8px',
                        backgroundColor: isCritico ? '#ff007f' : '#fcee0a',
                        color: '#000'
                      }}>
                        {alert.nivel}
                      </span>
                    </div>

                    {isCritico && (
                      <div style={{ display: 'flex', gap: '10px', marginTop: '10px', paddingTop: '10px', borderTop: '1px dashed rgba(255,0,127,0.4)' }}>
                        <button
                          onClick={async () => {
                            try {
                              const res = await fetch(`${API_URL}/api/soar/mitigate`, {
                                method: 'POST',
                                headers: { 'Content-Type': 'application/json' },
                                body: JSON.stringify({ action: 'block_user', target: username })
                              });
                              const result = await res.json();
                              window.alert(result.detalhe + "\n\n[MEDIDA DE SEGURANÇA]: Sessão invalidada e encerrada.");
                              setToken(null);
                            } catch (e) {
                              window.alert('Erro ao executar playbook SOAR.');
                            }
                          }}
                          style={{
                            all: 'unset',
                            boxSizing: 'border-box',
                            display: 'inline-block',
                            backgroundColor: '#ff007f',
                            color: '#000000',
                            padding: '8px 14px',
                            fontWeight: '900',
                            fontSize: '11px',
                            cursor: 'pointer',
                            textTransform: 'uppercase',
                            letterSpacing: '1px',
                            boxShadow: '0 0 10px rgba(255, 0, 127, 0.8)'
                          }}
                        >
                          [SOAR Playbook] Revogar Sessão / Bloquear Conta
                        </button>
                      </div>
                    )}
                  </div>
                );
              })}
            </div>
          )}
        </div>
      </div>
    );
  }

  // marcelo: Tela de Autenticação / Cadastro
  return (
    <div style={{
      position: 'fixed',
      top: 0,
      left: 0,
      width: '100vw',
      height: '100vh',
      backgroundColor: '#050505',
      color: '#00ffff',
      display: 'flex',
      alignItems: 'center',
      justifyContent: 'center',
      fontFamily: 'Courier New, monospace',
      margin: 0,
      padding: 0,
      zIndex: 9999
    }}>
      <div style={{
        width: '100%',
        maxWidth: '520px',
        backgroundColor: '#000000',
        border: '2px solid #00ffff',
        boxShadow: '0 0 35px rgba(0, 255, 255, 0.4)',
        padding: '40px',
        boxSizing: 'border-box',
        position: 'relative'
      }}>
        
        <h1 style={{
          fontSize: '24px',
          fontWeight: 'bold',
          color: '#fcee0a',
          textAlign: 'center',
          marginBottom: '30px',
          letterSpacing: '2px',
          textTransform: 'uppercase',
          borderBottom: '2px solid #ff007f',
          paddingBottom: '15px',
          textShadow: '0 0 10px rgba(252, 238, 10, 0.8)'
        }}>
          {isRegistering ? 'Specter Platform [Cadastro]' : 'Specter Platform [Auth]'}
        </h1>

        <form onSubmit={isRegistering ? handleRegister : handleLogin} style={{ display: 'flex', flexDirection: 'column', gap: '20px' }}>
          <div>
            <label style={{ display: 'block', fontSize: '14px', marginBottom: '8px', color: '#00ffff', fontWeight: 'bold', textTransform: 'uppercase' }}>
              Nome de Usuário:
            </label>
            <input
              type="text"
              value={username}
              onChange={(e) => setUsername(e.target.value)}
              style={{
                width: '100%',
                backgroundColor: '#050505',
                border: '2px solid rgba(0, 255, 255, 0.6)',
                padding: '14px',
                color: '#00ffff',
                outline: 'none',
                fontSize: '16px',
                boxSizing: 'border-box'
              }}
              placeholder="ex: marcelo.fraitag"
              required
            />
          </div>

          {isRegistering && (
            <div>
              <label style={{ display: 'block', fontSize: '14px', marginBottom: '8px', color: '#00ffff', fontWeight: 'bold', textTransform: 'uppercase' }}>
                E-mail Corporativo:
              </label>
              <input
                type="email"
                value={email}
                onChange={(e) => setEmail(e.target.value)}
                style={{
                  width: '100%',
                  backgroundColor: '#050505',
                  border: '2px solid rgba(0, 255, 255, 0.6)',
                  padding: '14px',
                  color: '#00ffff',
                  outline: 'none',
                  fontSize: '16px',
                  boxSizing: 'border-box'
                }}
                placeholder="ex: operador@specter-corp.local"
                required
              />
            </div>
          )}

          <div>
            <label style={{ display: 'block', fontSize: '14px', marginBottom: '8px', color: '#00ffff', fontWeight: 'bold', textTransform: 'uppercase' }}>
              Senha de Acesso:
            </label>
            <input
              type="password"
              value={password}
              onChange={(e) => setPassword(e.target.value)}
              style={{
                width: '100%',
                backgroundColor: '#050505',
                border: '2px solid rgba(0, 255, 255, 0.6)',
                padding: '14px',
                color: '#00ffff',
                outline: 'none',
                fontSize: '16px',
                boxSizing: 'border-box'
              }}
              placeholder="••••••••"
              required
            />
          </div>

          {error && (
            <div style={{
              padding: '12px',
              backgroundColor: 'rgba(255, 0, 127, 0.2)',
              border: '2px solid #ff007f',
              color: '#ff007f',
              fontSize: '13px',
              textAlign: 'center',
              fontWeight: 'bold',
              textTransform: 'uppercase',
              boxShadow: '0 0 15px rgba(255, 0, 127, 0.8)'
            }}>
              [ERRO] {error}
            </div>
          )}

          {successMessage && (
            <div style={{
              padding: '12px',
              backgroundColor: 'rgba(0, 255, 255, 0.1)',
              border: '2px solid #00ffff',
              color: '#00ffff',
              fontSize: '13px',
              textAlign: 'center',
              fontWeight: 'bold',
              textTransform: 'uppercase',
              boxShadow: '0 0 15px rgba(0, 255, 255, 0.2)'
            }}>
              [SUCESSO] {successMessage}
            </div>
          )}

          <button
            type="submit"
            style={{
              all: 'unset',
              boxSizing: 'border-box',
              display: 'block',
              textAlign: 'center',
              width: '100%',
              backgroundColor: '#ff007f',
              color: '#000000',
              fontWeight: '900',
              padding: '16px',
              marginTop: '10px',
              cursor: 'pointer',
              letterSpacing: '2px',
              textTransform: 'uppercase',
              fontSize: '16px',
              border: '1px solid rgba(255, 255, 255, 0.3)',
              boxShadow: '0 0 25px rgba(255, 0, 127, 0.8)'
            }}
          >
            {isRegistering ? 'Cadastrar Novo Operador' : 'Estabelecer Conexão'}
          </button>

          <button
            type="button"
            onClick={() => {
              setIsRegistering(!isRegistering);
              setError('');
              setSuccessMessage('');
            }}
            style={{
              all: 'unset',
              textAlign: 'center',
              cursor: 'pointer',
              fontSize: '12px',
              color: '#00ffff',
              opacity: 0.8,
              marginTop: '5px',
              textTransform: 'uppercase',
              letterSpacing: '1px'
            }}
          >
            {isRegistering ? 'Já tem uma conta? Faça login' : 'Não tem conta? Cadastre um novo operador'}
          </button>
        </form>
      </div>
    </div>
  );
}

export default App;
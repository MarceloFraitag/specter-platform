import React, { useState } from 'react';

export default function Login() {
  const [username, setUsername] = useState('');
  const [password, setPassword] = useState('');
  const [errorMessage, setErrorMessage] = useState('');
  const [isLoading, setIsLoading] = useState(false);
  const [loginSuccess, setLoginSuccess] = useState(false);

  const handleLogin = async (e: React.FormEvent) => {
    e.preventDefault();
    setErrorMessage('');
    setIsLoading(true);

    try {
      // Bate na porta do nosso backend rodando no Uvicorn
      const response = await fetch('http://127.0.0.1:8000/api/login', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
        },
        body: JSON.stringify({
          username: username,
          password: password,
        }),
      });

      const data = await response.json();

      if (!response.ok) {
        throw new Error(data.detail || 'Erro ao fazer login. Verifique suas credenciais.');
      }

      // SUCESSO! Guarda o token no navegador
      localStorage.setItem('specter_token', data.access_token);
      setLoginSuccess(true);

    } catch (error: any) {
      setErrorMessage(error.message);
    } finally {
      setIsLoading(false);
    }
  };

  return (
    <div className="min-h-screen flex items-center justify-center bg-gray-950 px-4 font-sans">
      <div className="max-w-md w-full bg-gray-900 border border-gray-800 rounded-lg shadow-2xl p-8">
        
        {/* Cabeçalho da Tela de Login */}
        <div className="text-center mb-8">
          <h1 className="text-3xl font-bold text-white tracking-widest">
            SPECTER<span className="text-blue-600">SIEM</span>
          </h1>
          <p className="text-gray-400 mt-2 text-sm">Centro de Operações de Segurança</p>
        </div>

        {/* Mensagem de Erro (Fica vermelha) */}
        {errorMessage && (
          <div className="mb-6 bg-red-900/30 border border-red-500/50 text-red-400 px-4 py-3 rounded text-sm text-center">
            {errorMessage}
          </div>
        )}

        {/* Mensagem de Sucesso (Fica verde) */}
        {loginSuccess ? (
          <div className="mb-6 bg-green-900/30 border border-green-500/50 text-green-400 px-4 py-6 rounded text-center">
            <svg className="w-12 h-12 text-green-500 mx-auto mb-2" fill="none" stroke="currentColor" viewBox="0 0 24 24">
              <path strokeLinecap="round" strokeLinejoin="round" strokeWidth="2" d="M9 12l2 2 4-4m6 2a9 9 0 11-18 0 9 9 0 0118 0z"></path>
            </svg>
            Acesso Autorizado!<br/>
            <span className="text-xs text-green-500/70 mt-2 block">Token JWT gravado no LocalStorage.</span>
          </div>
        ) : (
          /* Formulário de Login */
          <form onSubmit={handleLogin} className="space-y-6">
            <div>
              <label className="block text-sm font-medium text-gray-400 mb-1">Credencial de Acesso</label>
              <input
                type="text"
                value={username}
                onChange={(e) => setUsername(e.target.value)}
                required
                placeholder="ex: marcelo.fraitag"
                className="w-full bg-gray-950 border border-gray-700 rounded px-4 py-3 text-gray-200 focus:outline-none focus:border-blue-500 focus:ring-1 focus:ring-blue-500 transition-colors"
              />
            </div>

            <div>
              <label className="block text-sm font-medium text-gray-400 mb-1">Senha</label>
              <input
                type="password"
                value={password}
                onChange={(e) => setPassword(e.target.value)}
                required
                placeholder="••••••••"
                className="w-full bg-gray-950 border border-gray-700 rounded px-4 py-3 text-gray-200 focus:outline-none focus:border-blue-500 focus:ring-1 focus:ring-blue-500 transition-colors"
              />
            </div>

            <button
              type="submit"
              disabled={isLoading}
              className="w-full bg-blue-600 hover:bg-blue-700 text-white font-semibold py-3 px-4 rounded transition-colors disabled:opacity-50 disabled:cursor-not-allowed shadow-lg shadow-blue-900/20"
            >
              {isLoading ? 'Autenticando via Backend...' : 'Iniciar Sessão'}
            </button>
          </form>
        )}
      </div>
    </div>
  );
}
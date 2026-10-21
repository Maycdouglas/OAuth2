const { ROLES_PERMISSIONS } = require("../config/rbac");

// ============================================================================
// 4. MIDDLEWARES DE SEGURANÇA (AUTENTICAÇÃO E AUTORIZAÇÃO RBAC)
// ============================================================================

// Middleware 1: Verifica se o usuário passou pelo OAuth2 (Autenticação)
function exigirAutenticacao(req, res, next) {
  if (req.isAuthenticated()) {
    return next();
  }
  res.redirect("/");
}

// Middleware 2: Motor RBAC (Policy Enforcement Point) para proteger rotas
function exigirPermissaoRBAC(acaoNecessaria) {
  return (req, res, next) => {
    const usuario = req.user;

    // Negação por padrão (Fail-Safe Defaults)
    if (!usuario || !usuario.papel || !ROLES_PERMISSIONS[usuario.papel]) {
      return res
        .status(403)
        .send(renderizarResultadoAcao(usuario, acaoNecessaria, false));
    }

    const permissoesDoUsuario = ROLES_PERMISSIONS[usuario.papel];
    const autorizado = permissoesDoUsuario.includes(acaoNecessaria);

    if (autorizado) {
      return next();
    } else {
      return res
        .status(403)
        .send(renderizarResultadoAcao(usuario, acaoNecessaria, false));
    }
  };
}

// Função auxiliar para renderizar a página de resposta ao testar uma rota protegida
function renderizarResultadoAcao(usuario, acao, permitido) {
  return `
    <!DOCTYPE html>
    <html lang="pt-BR">
    <head><meta charset="UTF-8"><title>Resultado de Acesso</title></head>
    <body style="font-family: system-ui, sans-serif; padding: 3rem; background: #f8fafc;">
      <div style="max-width: 600px; margin: 0 auto; background: white; padding: 2rem; border-radius: 10px; border-top: 6px solid ${
        permitido ? "#16a34a" : "#dc2626"
      }; box-shadow: 0 4px 12px rgba(0,0,0,0.08);">
        <h2>${
          permitido
            ? "HTTP 200 - Acesso Autorizado pelo RBAC"
            : "HTTP 403 - Acesso Negado pelo RBAC"
        }</h2>
        <p><strong>Usuário Autenticado (OAuth2):</strong> ${
          usuario ? usuario.email : "Anônimo"
        }</p>
        <p><strong>Papel Atual (Role):</strong> <code>${
          usuario ? usuario.papel : "nenhum"
        }</code></p>
        <p><strong>Ação Solicitada:</strong> <code>${acao}</code></p>
        <hr style="border: none; border-top: 1px solid #e2e8f0; margin: 1.5rem 0;">
        <p>${
          permitido
            ? "O seu papel possui a permissão necessária. O recurso protegido foi executado com sucesso!"
            : "Princípio do Menor Privilégio: O seu papel atual não inclui esta permissão na matriz RBAC."
        }</p>
        <a href="/painel" style="display:inline-block; margin-top: 1rem; color: #2563eb; font-weight: bold;">Voltar ao Painel</a>
      </div>
    </body>
    </html>
  `;
}

module.exports = {
  exigirAutenticacao,
  exigirPermissaoRBAC,
  renderizarResultadoAcao,
};

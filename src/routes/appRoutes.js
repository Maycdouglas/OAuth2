const express = require("express");
const router = express.Router();
const passport = require("../config/passport");
const { ROLES_PERMISSIONS, TODAS_ACOES_SISTEMA } = require("../config/rbac");
const {
  exigirAutenticacao,
  exigirPermissaoRBAC,
  renderizarResultadoAcao,
} = require("../middleware/security");

// ============================================================================
// 5. ROTAS DA APLICAÇÃO (FLUXO OAUTH2 E PÁGINAS)
// ============================================================================

// Rota Inicial (Página de Login)
router.get("/", (req, res) => {
  if (req.isAuthenticated()) {
    return res.redirect("/painel");
  }

  res.send(`
    <!DOCTYPE html>
    <html lang="pt-BR">
    <head>
      <meta charset="UTF-8">
      <title>Atividade 2 - OAuth2 + RBAC</title>
      <style>
        body { font-family: system-ui, sans-serif; background: #0f172a; color: #f8fafc; display: flex; align-items: center; justify-content: center; height: 100vh; margin: 0; }
        .card { background: #1e293b; padding: 2.5rem; border-radius: 12px; box-shadow: 0 10px 25px rgba(0,0,0,0.4); text-align: center; max-width: 440px; }
        .btn { display: inline-block; margin-top: 1.5rem; padding: 12px 24px; background: #3b82f6; color: #fff; text-decoration: none; border-radius: 8px; font-weight: bold; }
        .btn:hover { background: #2563eb; }
        p { color: #94a3b8; line-height: 1.5; }
      </style>
    </head>
    <body>
      <div class="card">
        <h2>Segurança de Sistemas</h2>
        <p>Prática 2: Autenticação Federada via <strong>Google OAuth 2.0</strong> integrada ao Controle de Acesso Baseado em Papéis (<strong>RBAC</strong>).</p>
        <a class="btn" href="/auth/google">Entrar com Conta Google</a>
      </div>
    </body>
    </html>
  `);
});

// Passo 1 do OAuth2: Redireciona o usuário para o servidor de autorização do Google
// Solicitamos os escopos 'profile' e 'email' para receber os atributos necessários ao RBAC
router.get(
  "/auth/google",
  passport.authenticate("google", { scope: ["profile", "email"] })
);

// Passo 2 do OAuth2: Callback para onde o Google devolve o código de autorização
router.get(
  "/auth/google/callback",
  passport.authenticate("google", { failureRedirect: "/" }),
  (req, res) => {
    // Autenticação concluída e papel RBAC já atribuído! Redireciona para a página autenticada.
    res.redirect("/painel");
  }
);

// Página Autenticada: Exibe os atributos OAuth2 e o resultado do controle de acesso RBAC
router.get("/painel", exigirAutenticacao, (req, res) => {
  const u = req.user;

  // Monta as linhas da tabela de permissões para mostrar claramente o que é permitido ou negado
  const linhasPermissoes = TODAS_ACOES_SISTEMA.map((acao) => {
    const permitido = u.permissoes.includes(acao.codigo);
    return `
      <tr>
        <td><code>${acao.codigo}</code></td>
        <td>${acao.nome}</td>
        <td>
          <span class="badge ${permitido ? "ok" : "denied"}">
            ${permitido ? "PERMITIDO" : "NEGADO"}
          </span>
        </td>
        <td>
          <a class="test-link" href="/acao/${acao.codigo}">Testar Acesso</a>
        </td>
      </tr>
    `;
  }).join("");

  res.send(`
    <!DOCTYPE html>
    <html lang="pt-BR">
    <head>
      <meta charset="UTF-8">
      <title>Painel Autenticado - OAuth2 + RBAC</title>
      <style>
        body { font-family: system-ui, sans-serif; background: #f1f5f9; color: #1e293b; margin: 0; padding: 2rem; }
        .container { max-width: 900px; margin: 0 auto; background: #fff; padding: 2rem; border-radius: 12px; box-shadow: 0 4px 12px rgba(0,0,0,0.08); }
        .header { display: flex; justify-content: space-between; align-items: center; border-bottom: 1px solid #e2e8f0; padding-bottom: 1rem; }
        .box { background: #f8fafc; border: 1px solid #cbd5e1; border-radius: 8px; padding: 1rem 1.25rem; margin-top: 1.5rem; }
        .role-tag { display: inline-block; padding: 4px 12px; border-radius: 6px; background: #1d4ed8; color: #fff; font-weight: bold; text-transform: uppercase; }
        table { width: 100%; border-collapse: collapse; margin-top: 1rem; }
        th, td { text-align: left; padding: 12px; border-bottom: 1px solid #e2e8f0; }
        .badge { padding: 4px 10px; border-radius: 999px; font-size: 0.8rem; font-weight: bold; }
        .ok { background: #dcfce7; color: #166534; }
        .denied { background: #fee2e2; color: #991b1b; }
        .btn-logout { background: #ef4444; color: white; text-decoration: none; padding: 8px 16px; border-radius: 6px; font-weight: 600; }
        .sim-bar { margin-top: 1.5rem; padding: 1rem; background: #eff6ff; border-left: 4px solid #3b82f6; border-radius: 4px; }
        .sim-btn { margin-right: 8px; padding: 6px 12px; background: #fff; border: 1px solid #3b82f6; color: #1d4ed8; border-radius: 4px; text-decoration: none; font-size: 0.9rem; }
        .test-link { color: #2563eb; text-decoration: none; font-weight: 600; }
      </style>
    </head>
    <body>
      <div class="container">
        <div class="header">
          <div>
            <h2>Painel de Controle de Acesso (OAuth2 + RBAC)</h2>
            <p>Usuário autenticado via provedor de identidade Google</p>
          </div>
          <a class="btn-logout" href="/logout">Encerrar Sessão</a>
        </div>

        <!-- 1. ATRIBUTOS RECEBIDOS DA AUTENTICAÇÃO OAUTH2 -->
        <div class="box">
          <h3>1. Atributos Recebidos do Google (Autenticação - AuthN)</h3>
          <ul>
            <li><strong>ID Google (sub):</strong> <code>${
              u.googleId
            }</code></li>
            <li><strong>Nome Completo:</strong> ${u.nome}</li>
            <li><strong>Atributo E-mail:</strong> <code>${
              u.email
            }</code> (Verificado: ${u.emailVerificado ? "Sim" : "Não"})</li>
            <li><strong>Atributo Domínio Extraído:</strong> <code>@${
              u.dominio
            }</code></li>
          </ul>
        </div>

        <!-- 2. DECISÃO DO MOTOR RBAC -->
        <div class="box">
          <h3>2. Decisão de Autorização (RBAC - AuthZ)</h3>
          <p><strong>Papel (Role) Atribuído:</strong> <span class="role-tag">${
            u.papel
          }</span></p>
          <p><strong>Regra de Atributo Utilizada:</strong> ${u.regraRBAC}</p>
        </div>

        <!-- 3. MATRIZ DE ACESSO NA PÁGINA AUTENTICADA -->
        <div class="box">
          <h3>3. Permissões Efetivas no Sistema</h3>
          <table>
            <thead>
              <tr>
                <th>Permissão</th>
                <th>Descrição do Recurso</th>
                <th>Status RBAC</th>
                <th>Validação Prática</th>
              </tr>
            </thead>
            <tbody>
              ${linhasPermissoes}
            </tbody>
          </table>
        </div>

        <!-- SIMULADOR DIDÁTICO PARA DEMONSTRAÇÃO EM AULA -->
        <div class="sim-bar">
          <strong>Modo de Demonstração Acadêmica:</strong>
          Alterne temporariamente seu papel na sessão para testar o comportamento do RBAC com a mesma conta Google:
          <div style="margin-top: 8px;">
            <a class="sim-btn" href="/simular-papel/leitor">Simular Papel: LEITOR</a>
            <a class="sim-btn" href="/simular-papel/editor">Simular Papel: EDITOR</a>
            <a class="sim-btn" href="/simular-papel/admin">Simular Papel: ADMIN</a>
          </div>
        </div>
      </div>
    </body>
    </html>
  `);
});

// Rota protegida para testar na prática o bloqueio (HTTP 403) ou liberação (HTTP 200) de cada permissão
router.get("/acao/:permissao", exigirAutenticacao, (req, res, next) => {
  const permissao = req.params.permissao;
  // Aciona dinamicamente o middleware RBAC para a permissão requisitada
  exigirPermissaoRBAC(permissao)(req, res, () => {
    res.status(200).send(renderizarResultadoAcao(req.user, permissao, true));
  });
});

// Rota auxiliar apenas para fins didáticos: permite demonstrar os 3 papéis ao professor sem precisar logar em 3 contas diferentes
router.get("/simular-papel/:novoPapel", exigirAutenticacao, (req, res) => {
  const novoPapel = req.params.novoPapel;
  if (ROLES_PERMISSIONS[novoPapel]) {
    req.user.papel = novoPapel;
    req.user.permissoes = ROLES_PERMISSIONS[novoPapel];
    req.user.regraRBAC = `Papel alterado manualmente no Simulador Acadêmico para '${novoPapel}'.`;
  }
  res.redirect("/painel");
});

// Rota de Logout
router.get("/logout", (req, res, next) => {
  req.logout((err) => {
    if (err) return next(err);
    req.session.destroy(() => res.redirect("/"));
  });
});

module.exports = router;

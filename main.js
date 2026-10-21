/**
 * ATIVIDADE 2 - AUTENTICAÇÃO (OAUTH2 GOOGLE) + AUTORIZAÇÃO (RBAC)
 * Disciplina: Segurança em Sistemas de Computação
 */

require("dotenv").config();
const express = require("express");
const session = require("express-session");
const passport = require("passport");
const GoogleStrategy = require("passport-google-oauth20").Strategy;

const app = express();
const PORT = process.env.PORT || 3000;

// ============================================================================
// 1. DEFINIÇÃO DA MATRIZ RBAC (PAPÉIS E PERMISSÕES)
// ============================================================================
// Congelamos o objeto para garantir integridade da política em tempo de execução
const ROLES_PERMISSIONS = Object.freeze({
  leitor: ["ler_relatorios"],
  editor: ["ler_relatorios", "publicar_documentos", "editar_documentos"],
  admin: [
    "ler_relatorios",
    "publicar_documentos",
    "editar_documentos",
    "excluir_registros",
    "auditar_usuarios",
  ],
});

// Lista de todas as ações existentes no sistema para exibição comparativa no painel
const TODAS_ACOES_SISTEMA = [
  { codigo: "ler_relatorios", nome: "Visualizar Relatórios Internos" },
  { codigo: "publicar_documentos", nome: "Publicar Novos Documentos" },
  { codigo: "editar_documentos", nome: "Editar Documentos Existentes" },
  { codigo: "excluir_registros", nome: "Excluir Registros Críticos" },
  { codigo: "auditar_usuarios", nome: "Acessar Logs de Auditoria de Usuários" },
];

// ============================================================================
// 2. MAPEAMENTO DE ATRIBUTO DO OAUTH2 PARA PAPEL RBAC
// ============================================================================
/**
 * Analisa os atributos retornados pelo provedor OAuth2 (Google) e define
 * qual Papel (Role) o usuário receberá na aplicação.
 *
 * @param {Object} profile - Perfil retornado pelo Google após autenticação.
 * @returns {Object} - Papel atribuído e justificativa baseada no atributo.
 */
function atribuirPapelPorAtributo(profile) {
  // Extrai o atributo de e-mail e verificação retornados pelo Google
  const emailObj = profile.emails && profile.emails[0];
  const email = emailObj ? emailObj.value.toLowerCase() : "";
  const emailVerificado = emailObj ? emailObj.verified : false;

  // Extrai o domínio do e-mail (ex: "gmail.com" ou "ufjf.br")
  const dominio = email.split("@")[1] || "";

  // SEGURANÇA: Se o e-mail não foi verificado pelo Google, nega privilégios
  if (!emailVerificado) {
    return {
      papel: "sem_acesso",
      regraAplicada: "Atributo 'email_verified' é falso.",
    };
  }

  // REGRA 1 (Atributo: E-mail específico de Administrador)
  // Permite definir administradores pelo atributo 'email' vindo do OAuth2
  const listaAdmins = [
    (process.env.ADMIN_EMAIL || "").toLowerCase(),
    "admin@sistema.edu.br",
  ];

  if (listaAdmins.includes(email)) {
    return {
      papel: "admin",
      regraAplicada: `Atributo 'email' (${email}) consta na lista de Administradores.`,
    };
  }

  // REGRA 2 (Atributo: Domínio Institucional / Acadêmico)
  // Se o atributo de domínio pertencer a uma instituição de ensino/pesquisa, recebe 'editor'
  if (dominio.endsWith(".edu.br") || dominio.endsWith("ufjf.br")) {
    return {
      papel: "editor",
      regraAplicada: `Atributo de domínio institucional detectado (@${dominio}).`,
    };
  }

  // REGRA 3 (Menor Privilégio / Default Role para usuários autenticados comuns)
  // Qualquer outra conta Google válida (ex: @gmail.com comum) entra como 'leitor'
  return {
    papel: "leitor",
    regraAplicada: `Conta Google padrão verificada (@${dominio}) -> Menor Privilégio aplicado.`,
  };
}

// ============================================================================
// 3. CONFIGURAÇÃO DO PASSSPORT E ESTRATÉGIA GOOGLE OAUTH 2.0
// ============================================================================
app.use(
  session({
    secret: process.env.SESSION_SECRET || "chave_secreta_padrao_lab",
    resave: false,
    saveUninitialized: false,
    cookie: { httpOnly: true }, // Mitigação contra roubo de sessão via XSS
  })
);

app.use(passport.initialize());
app.use(passport.session());

passport.use(
  new GoogleStrategy(
    {
      clientID: process.env.GOOGLE_CLIENT_ID,
      clientSecret: process.env.GOOGLE_CLIENT_SECRET,
      callbackURL: "http://localhost:3000/auth/google/callback",
    },
    (accessToken, refreshToken, profile, done) => {
      // ESTE BLOCO EXECUTA LOGO APÓS O GOOGLE AUTENTICAR O USUÁRIO
      // Inserimos aqui o fluxo RBAC baseado nos atributos recebidos do Google!
      const resultadoRBAC = atribuirPapelPorAtributo(profile);
      const email = profile.emails?.[0]?.value || "N/A";
      const dominio = email.split("@")[1] || "N/A";

      // Construímos o objeto do usuário autenticado + autorizado
      const usuarioSessao = {
        googleId: profile.id,
        nome: profile.displayName,
        email: email,
        emailVerificado: profile.emails?.[0]?.verified || false,
        dominio: dominio,
        foto: profile.photos?.[0]?.value || "",
        papel: resultadoRBAC.papel,
        regraRBAC: resultadoRBAC.regraAplicada,
        permissoes: ROLES_PERMISSIONS[resultadoRBAC.papel] || [],
      };

      console.log(
        `[OAUTH2 + RBAC] Login: ${usuarioSessao.email} | Papel atribuído: ${usuarioSessao.papel}`
      );
      return done(null, usuarioSessao);
    }
  )
);

// Serialização do usuário na sessão
passport.serializeUser((user, done) => done(null, user));
passport.deserializeUser((user, done) => done(null, user));

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

// ============================================================================
// 5. ROTAS DA APLICAÇÃO (FLUXO OAUTH2 E PÁGINAS)
// ============================================================================

// Rota Inicial (Página de Login)
app.get("/", (req, res) => {
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
app.get(
  "/auth/google",
  passport.authenticate("google", { scope: ["profile", "email"] })
);

// Passo 2 do OAuth2: Callback para onde o Google devolve o código de autorização
app.get(
  "/auth/google/callback",
  passport.authenticate("google", { failureRedirect: "/" }),
  (req, res) => {
    // Autenticação concluída e papel RBAC já atribuído! Redireciona para a página autenticada.
    res.redirect("/painel");
  }
);

// Página Autenticada: Exibe os atributos OAuth2 e o resultado do controle de acesso RBAC
app.get("/painel", exigirAutenticacao, (req, res) => {
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
app.get("/acao/:permissao", exigirAutenticacao, (req, res, next) => {
  const permissao = req.params.permissao;
  // Aciona dinamicamente o middleware RBAC para a permissão requisitada
  exigirPermissaoRBAC(permissao)(req, res, () => {
    res.status(200).send(renderizarResultadoAcao(req.user, permissao, true));
  });
});

// Rota auxiliar apenas para fins didáticos: permite demonstrar os 3 papéis ao professor sem precisar logar em 3 contas diferentes
app.get("/simular-papel/:novoPapel", exigirAutenticacao, (req, res) => {
  const novoPapel = req.params.novoPapel;
  if (ROLES_PERMISSIONS[novoPapel]) {
    req.user.papel = novoPapel;
    req.user.permissoes = ROLES_PERMISSIONS[novoPapel];
    req.user.regraRBAC = `Papel alterado manualmente no Simulador Acadêmico para '${novoPapel}'.`;
  }
  res.redirect("/painel");
});

// Rota de Logout
app.get("/logout", (req, res, next) => {
  req.logout((err) => {
    if (err) return next(err);
    req.session.destroy(() => res.redirect("/"));
  });
});

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

app.listen(PORT, () => {
  console.log(`Servidor rodando em http://localhost:${PORT}`);
});

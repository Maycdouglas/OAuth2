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

module.exports = {
  ROLES_PERMISSIONS,
  TODAS_ACOES_SISTEMA,
  atribuirPapelPorAtributo,
};

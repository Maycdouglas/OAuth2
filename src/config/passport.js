const passport = require("passport");
const GoogleStrategy = require("passport-google-oauth20").Strategy;
const { ROLES_PERMISSIONS, atribuirPapelPorAtributo } = require("./rbac");

// ============================================================================
// 3. CONFIGURAÇÃO DO PASSSPORT E ESTRATÉGIA GOOGLE OAUTH 2.0
// ============================================================================
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

module.exports = passport;

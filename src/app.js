require("dotenv").config();
const express = require("express");
const session = require("express-session");
const passport = require("./config/passport");
const routes = require("./routes/appRoutes");

const app = express();

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
app.use(routes);

module.exports = app;

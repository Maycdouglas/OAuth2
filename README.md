# OAuth2 + RBAC

Projeto de autenticação via Google OAuth 2.0 com controle de acesso por papéis (RBAC), desenvolvido como atividade de Segurança em Sistemas de Informação.

## Requisitos

Antes de executar o projeto, verifique se o ambiente possui:

- Node.js 18 ou superior
- npm
- Uma conta no Google Cloud Console para gerar as credenciais OAuth

## Instalação

1. Abra o terminal no diretório do projeto.
2. Instale as dependências:

```bash
npm install
```

## Configuração das variáveis de ambiente

Crie um arquivo `.env` na raiz do projeto com o conteúdo abaixo:

```env
GOOGLE_CLIENT_ID=sua_chave_google_client_id
GOOGLE_CLIENT_SECRET=sua_chave_google_client_secret
SESSION_SECRET=sua_chave_secreta_para_sessao
ADMIN_EMAIL=professor@dominio.com
PORT=3000
```

Você também pode copiar o exemplo do arquivo `.env.example`:

```bash
copy .env.example .env
```

> Ajuste os valores conforme a sua conta Google OAuth e o e-mail do professor ou administrador que deseja testar.

## Execução

No terminal, dentro da pasta do projeto, execute:

```bash
npm start
```

A aplicação será iniciada em:

```text
http://localhost:3000
```

## Como testar

1. Abra o navegador em `http://localhost:3000`.
2. Clique em "Entrar com Conta Google".
3. Faça login com sua conta Google.
4. O sistema atribui automaticamente um papel com base no e-mail e no domínio:
   - admin
   - editor
   - leitor
5. Após autenticar, o professor pode testar as permissões na página do painel.

## Observações

- Se a conta autenticada for o e-mail informado em `ADMIN_EMAIL`, o sistema a tratará como administrador.

## Estrutura principal

- `main.js` — servidor principal e lógica OAuth2/RBAC
- `package.json` — dependências e scripts do projeto
- `.env` — variáveis sensíveis do ambiente

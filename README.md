# Sistema de Mensageria Segura Multi-Cliente

Chat multi-cliente com **criptografia ponta-a-ponta (E2E)** em Python. O servidor funciona só como *relay*: ele autentica o handshake e distribui as chaves públicas, mas **não tem como decifrar** as mensagens trocadas entre os clientes.

> Trabalho Prático 2 da disciplina de Segurança - UFC (Prof.Michel Sales).

## Garantias de segurança

| Propriedade | Mecanismo |
|---|---|
| Confidencialidade | AES-128-GCM (AEAD) |
| Integridade | Tag de autenticação do GCM (16 bytes) |
| Autenticidade do servidor | Certificado RSA autoassinado e pinado + assinatura RSA-PSS/SHA-256 |
| Sigilo perfeito (*forward secrecy*) | Chaves efêmeras X25519 (ECDHE) |
| Anti-replay | `seq_no` monotônico por direção |
| Servidor cego | Chaves E2E derivadas apenas nos clientes (HKDF-SHA256) |

## Como funciona

```
Cliente A (1º a conectar)         Servidor                  Cliente B (2º a conectar)
    | HELLO: id_A + pk_A + nome -->  |                              |
    | <-- HELLO_RESP: cert + salt + assinatura                      |
    |                                |  <-- HELLO: id_B + pk_B + nome
    |                                |  HELLO_RESP -->              |
    |                                |  gera salt_AB do par         |
    | <-- PEER_JOIN: B, pk_B, salt_AB, assinatura                   |
    |                                |  PEER_JOIN: A, pk_A, salt_AB, assinatura -->
    |                                                               |
    |   Z_AB = X25519(sk_A, pk_B)        Z_AB = X25519(sk_B, pk_A)  |
    |   PRK  = HKDF-Extract(salt_AB, Z_AB)                          |
    |   Key_A2B / Key_B2A = HKDF-Expand(PRK, "A2B"/"B2A", 16)       |
    |                                                               |
    | -- E2E cifrado -->             | -- encaminha bytes -->       |
    |                                |            decifra + valida tag
```

1. **Handshake:** o cliente gera um par X25519 efêmero e envia `HELLO` com `client_id` (UUID v4, 16 B), `pk_client` (32 B raw) e seu nome.
2. **Autenticação do servidor:** o servidor responde `HELLO_RESP` com seu certificado, um `salt` de 16 B e a assinatura RSA-PSS de `SHA256(pk_S || pk_client || client_id || salt)`, onde `pk_S` é a chave pública RSA do servidor em DER. O cliente verifica a assinatura com o certificado pinado (`certs/public/server.crt`).
3. **Rendezvous:** para cada par de clientes, o servidor gera um `salt_AB` aleatório e envia aos dois um `PEER_JOIN` com o `client_id`, a chave pública e o nome do outro, o `salt_AB` e um contador `seq_send`, tudo assinado com RSA-PSS. Um MITM não consegue trocar a chave de um peer sem invalidar a assinatura.
4. **Derivação:** cada par calcula o segredo ECDH e deriva uma chave AES por direção via HKDF com o `salt_AB` do par.
5. **Mensagens:** cada mensagem é cifrada com AES-128-GCM e o servidor só a encaminha.

### Formato dos frames

Todo frame em TCP começa com o tamanho (4 bytes, big-endian, contando tipo + corpo) e um byte de tipo:

```
| tamanho (4B) | tipo (1B) | corpo |
```

| Tipo | Valor | Direção | Corpo |
|---|---|---|---|
| `HELLO` | `0x01` | cliente → servidor | client_id + pk_client + nome |
| `HELLO_RESP` | `0x02` | servidor → cliente | certificado + salt + assinatura |
| `PEER_JOIN` | `0x03` | servidor → cliente | client_id + pk + nome do peer + salt_AB + seq_send + assinatura |
| `PEER_LEAVE` | `0x04` | servidor → cliente | client_id do peer + seq_send + assinatura |
| `E2E` | `0x10` | cliente → cliente (relay) | frame E2E abaixo |
| `ERROR` | `0x7F` | servidor → cliente | código de erro (1 B) |

Tipo desconhecido ou tamanho inválido é tratado como erro de framing: a conexão é encerrada.

O corpo de um frame `E2E` é exatamente o frame do enunciado:

```
| nonce (12B) | sender_id (16B) | recipient_id (16B) | seq_no (8B) | ciphertext || tag (16B) |

nonce = IV_base (4B) || seq_no (8B, big-endian)
AAD   = sender_id || recipient_id || seq_no
```

O destinatário rejeita o frame se a tag GCM não confere (adulteração) ou se `seq_no <= último seq_no aceito` (replay).

### Decisões de protocolo

Pontos que o enunciado deixa em aberto e como o grupo resolveu:

| # | Ponto | Decisão | Motivo |
|---|---|---|---|
| 1 | Salt da derivação E2E | Um `salt_AB` por **par** de clientes, gerado pelo servidor e enviado igual aos dois | Com um salt por cliente, A e B derivariam chaves diferentes |
| 2 | Autenticidade das chaves dos peers | `PEER_JOIN` e `PEER_LEAVE` assinados com RSA-PSS e com `seq_send` | Sem assinatura, um MITM poderia trocar a chave pública de um peer |
| 3 | Quem é A e quem é B | Em cada par, **A é quem conectou primeiro**. Quem recebe um `PEER_JOIN` de alguém que já estava conectado é B; quem é avisado da chegada de alguém novo é A | Os dois lados precisam escolher os labels `"A2B"`/`"B2A"` iguais. Na reconexão, o cliente vira o mais novo |
| 4 | `pk_S` no hash assinado | Chave pública RSA do servidor em DER (SubjectPublicKeyInfo) | O enunciado não define o formato |
| 5 | IV_base do outro lado | O receptor lê o nonce do frame e confere que `nonce[4:] == seq_no` | Cada lado sorteia o próprio IV_base, e o nonce já viaja no frame |
| 6 | Tipo de mensagem | 1 byte de tipo após o prefixo de tamanho | O frame do enunciado não distingue handshake, controle e E2E |
| 7 | Certificado | Cada integrante gera o seu; nada em `certs/` é versionado. Na apresentação, servidor e clientes rodam no mesmo notebook | Certificados versionados entrariam em conflito entre os integrantes |
| 8 | Nome do cliente | Enviado no `HELLO` e repassado no `PEER_JOIN` assinado. De 1 a 32 caracteres `[A-Za-z0-9_-]`; o servidor recusa nomes repetidos | O enunciado só tem `client_id`, mas o chat precisa de `/msg <nome>` |
| 9 | `client_id` | UUID v4 novo a cada execução; `--id <uuid>` reutiliza um id (teste de reconexão) | O enunciado exige testar a reconexão com o mesmo `client_id` |

## Estrutura do projeto

```
.
├── common/
│   ├── framing.py      # leitura/escrita de frames com prefixo de tamanho
│   ├── protocol.py     # tipos de mensagem, serialização, constantes
│   └── crypto.py       # X25519, HKDF, AES-GCM, RSA-PSS
├── server/
│   └── server.py       # relay asyncio + tabela de sessões
├── client/
│   └── client.py       # cliente CLI + tabela de peers
├── scripts/
│   └── gen_cert.py     # gera chave RSA e certificado autoassinado
├── tools/
│   └── mitm_proxy.py   # proxy para demonstrar bitflip e replay
├── tests/              # testes automatizados (pytest)
└── certs/              # gerado localmente, nada aqui é versionado
    ├── server.key      #   chave privada (só na máquina do servidor)
    └── public/
        └── server.crt  #   certificado pinado (copiado para os clientes)
```

## Requisitos

- Python 3.10+ (o CI testa em 3.10 e 3.13)
- [`cryptography`](https://cryptography.io/) e [`python-dotenv`](https://github.com/theskumar/python-dotenv), em versões fixas no `requirements.txt` para que todas as máquinas instalem exatamente o mesmo

```bash
python -m venv .venv
source .venv/bin/activate        # Windows: .venv\Scripts\activate
pip install -r requirements-dev.txt
```

## Configuração

As configurações vêm de variáveis de ambiente. Para usar um arquivo local, copie o exemplo (o `.env` não é versionado):

```bash
cp .env.example .env
```

| Variável | Padrão | Usada por | Descrição |
|---|---|---|---|
| `SERVER_BIND_HOST` | `127.0.0.1` | servidor | interface de escuta (`0.0.0.0` aceita outras máquinas) |
| `SERVER_HOST` | `127.0.0.1` | cliente | endereço do servidor |
| `SERVER_PORT` | `9000` | servidor / cliente | porta TCP |
| `MAX_CLIENTS` | `64` | servidor | conexões simultâneas aceitas |
| `HANDSHAKE_TIMEOUT` | `10` | servidor | segundos para concluir o handshake |
| `SERVER_KEY_PATH` | `certs/server.key` | servidor | chave privada RSA |
| `SERVER_CERT_PATH` | `certs/public/server.crt` | servidor | certificado autoassinado |
| `PINNED_CERT_PATH` | `certs/public/server.crt` | cliente | certificado pinado do servidor |
| `LOG_LEVEL` | `INFO` | ambos | `DEBUG`, `INFO`, `WARNING` ou `ERROR` |

Os argumentos `--host` e `--port` têm prioridade sobre as variáveis. Variáveis vazias usam o padrão, e caminhos relativos partem da raiz do projeto. Os comandos `python -m ...` devem ser rodados na raiz do projeto. As constantes do protocolo (tamanhos de salt, nonce, tag e plaintext máximo) ficam em `common/protocol.py` e não são configuráveis, porque cliente e servidor precisam concordar nelas.

## Uso

**1. Gerar o certificado do servidor** (uma vez):

```bash
python scripts/gen_cert.py
```

Isso cria `certs/server.key` (privada, ignorada pelo git) e `certs/public/server.crt` (pública, pinada nos clientes).

**2. Subir o servidor:**

```bash
python -m server.server
```

**3. Conectar clientes** (um terminal para cada):

```bash
python -m client.client --name alice
python -m client.client --name bob
```

O nome aceita de 1 a 32 caracteres entre letras, números, `_` e `-`. A cada execução o cliente gera um `client_id` novo, mostrado no log; para reconectar com o mesmo id, use `--id <uuid>`.

**4. Comandos no cliente:**

| Comando | Ação |
|---|---|
| `/peers` | lista os clientes conectados |
| `/msg <nome> <texto>` | envia uma mensagem E2E |
| `/quit` | desconecta |

### Em máquinas diferentes (mesma rede)

Todas as máquinas precisam estar na mesma rede (mesmo Wi-Fi ou hotspot).

**1. Na máquina do servidor**

```bash
python scripts/gen_cert.py
```

No `.env`:

```
SERVER_BIND_HOST=0.0.0.0
```

```bash
python -m server.server
```

Na primeira execução, o Windows pergunta sobre o Firewall: permita o acesso marcando **rede privada**. Anote o IP da máquina (`ipconfig` no Windows, `ip addr` no Linux, campo "Endereço IPv4"), por exemplo `192.168.0.16`.

**2. Em cada máquina de cliente**

Copie **apenas** o `certs/public/server.crt` da máquina do servidor para `certs/public/server.crt` do projeto (pen drive, Discord, etc.). Cada integrante gerar o próprio certificado não funciona: o cliente só confia no certificado do servidor em que vai conectar. O `server.key` nunca sai da máquina do servidor.

No `.env`:

```
SERVER_HOST=192.168.0.16   # IP anotado no passo 1
```

```bash
python -m client.client --name bob
```

**3. Resultado esperado**

O servidor mostra `conexão de ('<IP do cliente>', ...)` e o cliente mostra `bob conectado a 192.168.0.16:9000`.

**Se não conectar**

| Sintoma | Causa provável | Solução |
|---|---|---|
| Cliente demora e dá timeout | Firewall da máquina do servidor bloqueando a porta | Permita o Python no Firewall do Windows para redes privadas, ou libere a porta do `SERVER_PORT` |
| Timeout mesmo com o firewall liberado | A rede (ex.: Wi-Fi da faculdade) bloqueia comunicação entre aparelhos | Use um hotspot de celular |
| `Connection refused` | Servidor não está rodando ou está com `SERVER_BIND_HOST=127.0.0.1` | Confira o `.env` do servidor e reinicie |
| `certificado pinado não encontrado` | `server.crt` não foi copiado para o cliente | Copie para `certs/public/server.crt` ou ajuste `PINNED_CERT_PATH` |

### Com Docker

Gere o certificado antes (passo 1). Ele entra por volume, nunca na imagem. As variáveis do `.env` são lidas pelo Compose; os caminhos dos certificados são fixos dentro do container.

```bash
docker compose up --build server                # servidor na porta do .env (padrão 9000)
docker compose run --rm client --name alice     # cliente, em outro terminal
```

## Testes

```bash
pytest -v
```

Os testes cobrem os cenários obrigatórios:

- troca de mensagens E2E entre 2+ clientes
- frame adulterado (bitflip) → rejeitado por falha na tag GCM
- frame reenviado (replay) → rejeitado por `seq_no` repetido
- framing inválido → erro e desconexão segura
- reconexão com o mesmo `client_id` → handshake completo e chaves novas

## Parâmetros

| Parâmetro | Valor |
|---|---|
| Curva ECDHE | X25519 (chave pública raw de 32 B) |
| RSA | 2048 bits, RSA-PSS + SHA-256 |
| Salt | 16 B |
| Nonce | 12 B |
| Tag GCM | 16 B |
| Plaintext máximo por mensagem | 4096 B |

## Política de logs

Os logs **nunca** contêm chaves privadas, segredos ECDH, salts, nonces ou conteúdo de mensagens. Ficam registrados só eventos de conexão/desconexão, `client_id`, tamanhos de frame, motivos de rejeição e fingerprints (SHA-256 truncado) das chaves públicas.


# Sistema de Mensageria Segura Multi-Cliente

Chat multi-cliente com **criptografia ponta-a-ponta (E2E)** em Python. O servidor funciona só como *relay*: ele autentica o handshake e distribui as chaves públicas, mas **não tem como decifrar** as mensagens trocadas entre os clientes.

> Trabalho Prático 3 da disciplina **Segurança da Informação** (Prof. Michel Sales).

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
Cliente A                     Servidor                      Cliente B
    | client_id_A + pk_A  -->    |                              |
    | <-- pk_S + cert + sig + salt                              |
    |                            |  <-- client_id_B + pk_B      |
    |                            |  registra {client_id -> pk}  |
    | <-- pk_B                   |                  pk_A -->    |
    |                                                           |
    |   Z_AB = X25519(sk_A, pk_B)    Z_AB = X25519(sk_B, pk_A)  |
    |   PRK  = HKDF-Extract(salt, Z_AB)                         |
    |   Key_A2B / Key_B2A = HKDF-Expand(PRK, "A2B"/"B2A", 16)   |
    |                                                           |
    | -- frame E2E cifrado -->   | -- encaminha bytes -->       |
    |                            |            decifra + valida tag
```

1. **Handshake:** o cliente gera um par X25519 efêmero e envia `client_id` (UUID v4, 16 B) + `pk_client` (32 B raw).
2. **Autenticação do servidor:** o servidor responde com seu certificado, um `salt` de 16 B e a assinatura RSA-PSS de `SHA256(pk_server || pk_client || client_id || salt)`. O cliente verifica a assinatura com o certificado pinado (`certs/server.crt`).
3. **Rendezvous:** o servidor anuncia a chave pública do novo cliente aos demais e envia ao novo cliente as chaves dos que já estão conectados.
4. **Derivação:** cada par de clientes calcula o segredo ECDH e deriva uma chave AES por direção via HKDF.
5. **Mensagens:** cada mensagem é cifrada com AES-128-GCM e o servidor só a encaminha.

### Formato do frame E2E

Todo frame em TCP é prefixado por um comprimento de 4 bytes (big-endian).

```
| nonce (12B) | sender_id (16B) | recipient_id (16B) | seq_no (8B) | ciphertext || tag (16B) |

nonce = IV_base (4B) || seq_no (8B, big-endian)
AAD   = sender_id || recipient_id || seq_no
```

O destinatário rejeita o frame se a tag GCM não confere (adulteração) ou se `seq_no <= último seq_no aceito` (replay).

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
└── certs/              # server.crt (pinado) — a chave privada NÃO é versionada
```

## Requisitos

- Python 3.10+
- [`cryptography`](https://cryptography.io/)

```bash
python -m venv .venv
source .venv/bin/activate        # Windows: .venv\Scripts\activate
pip install -r requirements.txt
```

## Uso

**1. Gerar o certificado do servidor** (uma vez):

```bash
python scripts/gen_cert.py
```

Isso cria `certs/server.key` (privada, ignorada pelo git) e `certs/server.crt` (pública, pinada nos clientes).

**2. Subir o servidor:**

```bash
python -m server.server --host 127.0.0.1 --port 9000
```

**3. Conectar clientes** (um terminal para cada):

```bash
python -m client.client --host 127.0.0.1 --port 9000 --name alice
python -m client.client --host 127.0.0.1 --port 9000 --name bob
```

**4. Comandos no cliente:**

| Comando | Ação |
|---|---|
| `/peers` | lista os clientes conectados |
| `/msg <nome> <texto>` | envia uma mensagem E2E |
| `/quit` | desconecta |

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

## Contribuindo

Veja o [CONTRIBUTING.md](CONTRIBUTING.md) para o fluxo de branches, PRs e as regras de segurança do código.

## Autores

- Guilherme Cardoso
- _adicione os demais integrantes_

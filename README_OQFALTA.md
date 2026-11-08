# 🧭 O que falta: guia para quem vai continuar

Este arquivo diz **onde o projeto está** e **o que falta fazer, em ordem**, com o arquivo e a função de cada tarefa. O `README.md` descreve o protocolo; leia as seções "Como funciona" e "Decisões de protocolo" antes de começar.

> Andamento estimado pelos critérios de nota do PDF: **~50%**.

---

## 1. Preparar o ambiente

```bash
git clone https://github.com/guilherme-luna/Sistema-de-Mensageria-Segura-Multi-Cliente.git
cd Sistema-de-Mensageria-Segura-Multi-Cliente
git switch integracao
python -m venv .venv
.venv\Scripts\activate            # Linux/Mac: source .venv/bin/activate
pip install -r requirements-dev.txt
python scripts/gen_cert.py        # gera certs/server.key e certs/public/server.crt (não versionados)
ruff check . && pytest -q         # tudo deve passar antes de você mexer em algo
```

---

## 2. O que já está pronto

| Parte | Onde | O que faz |
|---|---|---|
| Framing | `common/framing.py` | `encode_frame` / `read_frame`: prefixo de 4 B + tipo, limite de tamanho, erro em frame inválido |
| Criptografia | `common/crypto.py` | X25519, HKDF-SHA256, AES-128-GCM (`seal_e2e` / `open_e2e`), RSA-PSS, certificado pinado |
| Mensagens de controle | `common/messages.py` | `Hello`, `HelloResp`, `PeerJoin`, `PeerLeave` com `encode()` / `parse()` e o material assinado |
| Servidor | `server/server.py` | handshake assinado, tabela `sessions`, anúncio de peers com `salt_AB` por par, relay por `recipient_id` |
| Cliente | `client/client.py` | autentica o servidor, verifica `PEER_JOIN`/`PEER_LEAVE`, deriva as chaves por par, `encrypt()` / `decrypt()` com anti-replay |
| Testes | `tests/` | 173 testes: vetores oficiais, handshake, MITM, rendezvous, relay, bitflip e replay |

**O que ainda não funciona:** o cliente não lê o teclado. Ele conecta, autentica e mostra mensagens recebidas, mas ainda não há como enviar pelo terminal.

Utilitários úteis nos testes (`tests/helpers.py`):
- `running_server(identity)`: sobe o servidor numa porta livre;
- `connect(port, cert, nome)`: cliente já autenticado;
- `process(conn, n)`: lê e processa `n` frames;
- `tampering_proxy(port, função)`: proxy MITM que altera os frames do servidor para o cliente.

---

## 3. O que falta, em ordem

### Tarefa 1 — CLI do cliente (fase 3, a mais importante)

**Onde:** `client/client.py`, função `run()`, no `TODO(fase 3)`.

Hoje `run()` só fica num laço lendo frames do servidor. Falta ler o teclado **ao mesmo tempo**:

- [ ] Rodar duas tarefas em paralelo: uma lendo frames (o laço que já existe) e outra lendo linhas do teclado. No Windows, `input()` bloqueia; use `await asyncio.to_thread(input)` para não travar o laço.
- [ ] `/peers`: listar `client.peers.values()` (nome e `client_id`).
- [ ] `/msg <nome> <texto>`: `writer.write(client.encrypt(nome, texto))` e `await writer.drain()`. Tratar `SendError` mostrando a mensagem, sem encerrar.
- [ ] `/quit`: fechar a conexão e sair.
- [ ] Comando desconhecido: mostrar a ajuda.
- [ ] Quando uma tarefa terminar (servidor caiu ou `/quit`), cancelar a outra.
- [ ] Testes em `tests/test_cli.py`: separar a interpretação do comando numa função pura (ex.: `parse_command(linha)`) e testá-la sem rede.

**Regra:** o texto das mensagens vai para a tela com `print()`, **nunca** para o `log`.

### Tarefa 2 — Ajustes já aprovados na revisão

- [ ] **Timeout do cliente pela configuração.** Em `client/client.py`, `HANDSHAKE_TIMEOUT = 10` está fixo. Adicione `handshake_timeout` ao `ClientConfig` em `common/config.py`, lendo a mesma variável `HANDSHAKE_TIMEOUT` que o servidor usa. Atualize `tests/test_config.py`.
- [ ] **Limite de buffer no servidor.** Em `server/server.py`, `_relay()` e `_send_control()` escrevem sem esperar o envio. Se `recipient.writer.transport.get_write_buffer_size()` passar de um limite (ex.: 1 MiB), feche a conexão desse destinatário. Escreva um teste com um cliente que nunca lê.
- [ ] **README: frase sobre o servidor.** Trocar "não tem como decifrar" por algo como "um servidor honesto não consegue decifrar". Adicionar uma nota: um servidor malicioso, que assina o que quiser, poderia anunciar uma chave falsa no `PEER_JOIN`.

### Tarefa 3 — Cenários obrigatórios ponta a ponta (fase 4)

Bitflip e replay já são rejeitados e testados em `tests/test_e2e.py`. Falta:

- [ ] **Reconexão com troca de mensagens:** cliente sai, volta com o mesmo `--id`, e os dois trocam mensagens com as chaves novas. Base: `test_reconnection_gets_fresh_keys` em `tests/test_rendezvous.py`.
- [ ] **Framing inválido depois do handshake** derruba só aquele cliente e os outros continuam conversando.
- [ ] Conferir se a seção "Testes" do `README.md` corresponde aos testes que existem.

### Tarefa 4 — Proxy MITM para a demonstração (fase 5)

**Onde:** criar `tools/mitm_proxy.py`, já citado na estrutura do README.

- [ ] Fica entre cliente e servidor: `--listen 9001 --upstream 127.0.0.1:9000`.
- [ ] Modo `--bitflip`: inverte um bit do próximo frame `E2E`. O destinatário deve mostrar "frame adulterado".
- [ ] Modo `--replay`: reenvia o último frame `E2E`. O destinatário deve mostrar "replay".
- [ ] Reaproveitar a lógica de `tampering_proxy` em `tests/helpers.py`.

### Tarefa 5 — Acabamento (fase 6 e apresentação)

- [ ] Revisar os logs: só `fingerprint()`, nunca chave, salt, nonce ou texto.
- [ ] `scripts/gen_cert.py`: o certificado é marcado como CA (`ca=True`), mas só assina o handshake. Trocar para `ca=False` com uso restrito a assinatura digital.
- [ ] README: no Windows, a permissão `0o600` da chave privada não tem efeito.
- [ ] Roteiro da apresentação dividido por integrante: handshake / derivação / criptografia / roteamento.

---

## 4. Regras do projeto

- **Nunca** versionar `certs/`, `.env` ou qualquer chave. O `.gitignore` já bloqueia esses arquivos; não force com `git add -f`.
- **Logs:** nunca chaves privadas, segredos ECDH, salts, nonces ou texto de mensagens. Use `fingerprint()` de `common/log.py` para identificar chaves públicas.
- **Nonce:** o `seq_no` é incrementado **antes** de cifrar. Nunca cifre duas mensagens com o mesmo `(chave, IV_base, seq_no)`.
- **Mudou o protocolo?** Atualize a tabela "Decisões de protocolo" do `README.md` e os testes.
- Todo código novo vem com teste, e `ruff check .` e `pytest -q` devem passar antes do commit.

## 5. Fluxo de git

```bash
git switch integracao
git pull
git switch -c feat/cli-cliente         # uma branch por tarefa
# ... código + testes ...
git add -A
git commit -m "feat: CLI do cliente com /peers, /msg e /quit"
git push -u origin feat/cli-cliente
```

Depois abra um PR para `integracao`; o CI roda nos PRs. Mensagens de commit seguem o padrão `feat:` / `fix:` / `docs:` / `test:`, em português.

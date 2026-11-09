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

**Atualização — Tarefa 1:** a CLI foi implementada com leitura simultânea do teclado e da rede. Veja a seção de CLI no `README.md`. Validação completa aprovada no terminal local: `ruff` sem erros e 200 testes passando.

Utilitários úteis nos testes (`tests/helpers.py`):
- `running_server(identity)`: sobe o servidor numa porta livre;
- `connect(port, cert, nome)`: cliente já autenticado;
- `process(conn, n)`: lê e processa `n` frames;
- `tampering_proxy(port, função)`: proxy MITM que altera os frames do servidor para o cliente.

---

## 3. O que falta, em ordem

### Tarefa 1 — CLI do cliente (fase 3, a mais importante)

**Onde:** `client/client.py`: `parse_command()`, `read_commands()`, `receive_messages()`, `chat()` e `run()`.

Implementação da CLI concluída e validada:

- [x] Rodar duas tarefas em paralelo: uma lendo frames (o laço que já existe) e outra lendo linhas do teclado. No Windows, `input()` bloqueia; use `await asyncio.to_thread(input)` para não travar o laço.
- [x] `/peers`: listar `client.peers.values()` (nome e `client_id`).
- [x] `/msg <nome> <texto>`: `writer.write(client.encrypt(nome, texto))` e `await writer.drain()`. Tratar `SendError` mostrando a mensagem, sem encerrar.
- [x] `/quit`: fechar a conexão e sair.
- [x] Comando desconhecido: mostrar a ajuda.
- [x] Quando uma tarefa terminar (servidor caiu ou `/quit`), cancelar a outra.
- [x] Testes em `tests/test_cli.py`: separar a interpretação do comando numa função pura (ex.: `parse_command(linha)`) e cobri-la sem rede; foram acrescentados também testes de CLI com rede e de encerramento em subprocesso.

**Regra:** o texto das mensagens vai para a tela com `print()`, **nunca** para o `log`.

**Validação desta etapa:** no terminal local do integrante, após instalar as dependências, `ruff check .` retornou `All checks passed!` e `pytest -q` retornou **200 passed in 3.24s** (27 testes de CLI). Inicialmente, o ambiente do assistente não tinha as dependências e a instalação falhou por DNS; não há resultado da suíte anterior às mudanças para comparação. A suíte da Tarefa 1 foi aprovada antes do início da Tarefa 2.

**Git da Tarefa 1:** base `integracao` (commit `891f963`); branch `feat/cli-cliente`, com a CLI registrada no commit `29c4cd5`.

### Tarefa 2 — Ajustes já aprovados na revisão

Implementação concluída e validação completa aprovada no terminal local:

- [x] **Timeout do cliente pela configuração:** `ClientConfig.handshake_timeout` lê `HANDSHAKE_TIMEOUT` (padrão 10, faixa 1–300), e `run()` passa esse prazo ao handshake. Testes de configuração e do prazo em `tests/test_config.py` e `tests/test_handshake.py`.
- [x] **Limite de buffer no servidor:** `_send_bounded()` limita a fila a 1 MiB antes de cada escrita de relay/controle. Ao ultrapassar, aborta só a conexão lenta; o fluxo existente remove a sessão. `tests/test_server_buffers.py` inclui testes determinísticos e uma conexão real que para de ler.
- [x] **README: confiança no servidor:** esclarecido que um servidor honesto não consegue decifrar e que um servidor malicioso poderia assinar anúncios de chaves falsas.

**Validação:** no terminal local, `ruff check .` retornou `All checks passed!` e `pytest -q` retornou **225 passed in 3.67s**. Inclui os testes assíncronos novos e a conexão real que para de ler, sem prejudicar os outros clientes. O bloqueio do event loop no ambiente do assistente não ocorreu no terminal local.

**Git:** branch `feat/ajustes-seguranca` criada pelo integrante. O commit `512a6ef` já contém parte da etapa (cliente e documentação), apesar da mensagem da CLI. Os arquivos restantes e o registro da validação estão prontos para revisão e commit. Sem commit, push ou PR automático. A Tarefa 3 ainda não foi iniciada.

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

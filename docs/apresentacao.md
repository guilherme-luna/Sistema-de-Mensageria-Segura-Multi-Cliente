# Roteiro da apresentação

Esqueleto que segue o checklist do enunciado. Os trechos `[PREENCHER]` ficam com o João, que fecha o roteiro e conduz o ensaio.

| Integrante | Parte do código | Parte da demo |
|---|---|---|
| Guilherme | Handshake (ECDHE + RSA-PSS + certificado pinado) e derivação de chaves (HKDF, `salt_AB`, papéis A/B) | Sobe servidor e clientes, explica o que aparece nos logs |
| João | Criptografia (AES-128-GCM, nonce, `seq_no`, anti-replay) e roteamento (relay, tabela `sessions`) | Conduz os ataques no proxy MITM |

Tempo total: `[PREENCHER: minutos disponíveis]`.

---

## 1. Abertura `[PREENCHER: tempo]`

- Cada integrante se apresenta e diz qual parte vai explicar.
- O problema em uma frase: um chat em que o servidor encaminha as mensagens, mas um servidor honesto não consegue lê-las.

## 2. Protocolo `[PREENCHER: tempo]` (Guilherme)

Usar o diagrama da seção "Como funciona" do `README.md`.

1. **Handshake:** o cliente gera um par X25519 efêmero e manda `HELLO`. O servidor responde com o certificado, um salt e a assinatura RSA-PSS de `SHA256(pk_S ‖ pk_C ‖ client_id ‖ salt)`. O cliente só aceita se o certificado for idêntico ao pinado e a assinatura conferir.
2. **Rendezvous:** para cada par de clientes, o servidor sorteia um `salt_AB` e envia a cada um a chave pública do outro num `PEER_JOIN` assinado.
3. **Derivação:** `Z_AB = X25519(sk_A, pk_B)`, `PRK = HKDF-Extract(salt_AB, Z_AB)`, `Key_A2B` e `Key_B2A` com `HKDF-Expand`. Uma chave por direção.
4. **Mensagens (João):** AES-128-GCM com `nonce = IV_base ‖ seq_no` e `AAD = sender_id ‖ recipient_id ‖ seq_no`.

## 3. Demonstração prática `[PREENCHER: tempo]`

Preparar antes (5 terminais, fonte grande):

```bash
python scripts/gen_cert.py                                    # só se ainda não existir
python -m server.server                                       # terminal 1
python -m tools.mitm_proxy --listen 9001 --upstream 127.0.0.1:9000   # terminal 2
python -m client.client --name alice --port 9001              # terminal 3 (passa pelo proxy)
python -m client.client --name bob                            # terminal 4
python -m client.client --name carol                          # terminal 5 (só no fim, para o ataque k)
```

| Passo | Quem | Ação | O que mostrar |
|---|---|---|---|
| 1 | Guilherme | Subir servidor, alice e bob | Logs de "servidor autenticado" e "peer ... entrou, papel A/B" |
| 2 | Guilherme | `/peers` e `/msg bob oi` na alice | bob mostra `[alice] oi` |
| 3 | João | Apontar o terminal do proxy | A mensagem passou como `ciphertext: ...` ilegível: **só o destinatário decifra** |
| 4 | João | `b` no proxy, depois `/msg bob teste` na alice | bob: `tag GCM inválida (frame adulterado)` |
| 5 | João | `/msg bob de novo` na alice, depois `r` no proxy | bob recebe a mensagem e depois rejeita a cópia: `seq_no N já visto (replay)` |
| 6 | João | `/msg bob ainda funciona` | A conversa continua: o ataque só descartou o frame atacado |
| 7 | João | `k` no proxy e subir a carol | alice aborta: `assinatura RSA-PSS inválida` (um MITM não troca chaves) |
| 8 | Guilherme | Framing inválido e reconexão | `python -m pytest -v tests/test_scenarios.py`: só o cliente infrator cai; reconexão com o mesmo `--id` gera chaves novas |

`[PREENCHER: plano B se a demo falhar ao vivo, ex.: vídeo gravado no ensaio]`

## 4. Estrutura de dados do servidor `[PREENCHER: tempo]` (João)

- `RelayServer.sessions` (`server/server.py`): `client_id → Session(nome, pk, salt da sessão, writer, seq_send)`.
- O servidor guarda só chaves **públicas**; nunca recebe nem deriva chaves E2E.
- `seq_send` por destinatário numera os `PEER_JOIN`/`PEER_LEAVE`; a assinatura cobre tipo, destinatário e o salt da conexão, então um anúncio não pode ser repetido nem desviado.
- No cliente, `ChatClient.peers` (`client/client.py`): por peer, `send_key`, `recv_key`, `IV_base`, `send_seq` e `recv_seq`.

## 5. Código `[PREENCHER: tempo]`

| Parte | Quem | Onde mostrar |
|---|---|---|
| Handshake | Guilherme | `ChatClient.handshake()` em `client/client.py`; `RelayServer._handshake()` em `server/server.py`; `verify_pinned_certificate()` e `sign_pss()` em `common/crypto.py` |
| Derivação de chaves | Guilherme | `derive_e2e_keys()` em `common/crypto.py`; `ChatClient._on_peer_join()` (papel A/B) |
| Criptografia | João | `seal_e2e()` / `open_e2e()` em `common/crypto.py`; `ChatClient.encrypt()` / `decrypt()` (anti-replay) |
| Roteamento | João | `RelayServer._relay()` e `_send_bounded()` em `server/server.py` |

## 6. Encerramento `[PREENCHER: tempo]`

| Garantia | Como foi mostrada |
|---|---|
| Confidencialidade | Proxy só vê ciphertext |
| Integridade | Bitflip rejeitado pela tag GCM |
| Autenticidade do servidor | Certificado pinado + RSA-PSS; ataque `k` rejeitado |
| Anti-replay | Reenvio rejeitado pelo `seq_no` |
| Sigilo perfeito | Chaves X25519 efêmeras: reconexão gera chaves novas |
| Logs seguros | `tests/test_logs.py`: sessão completa sem nenhum segredo no log |

Limitação a citar com honestidade: a confiança nas chaves depende de um servidor honesto; um servidor malicioso, que assina o que quiser, poderia anunciar uma chave falsa.

`[PREENCHER: perguntas prováveis do professor e respostas]`

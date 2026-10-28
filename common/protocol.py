"""Constantes do protocolo definidas no enunciado.

Estes valores precisam ser iguais no cliente e no servidor, por isso não são
configuráveis por variável de ambiente.
"""

CLIENT_ID_LEN = 16       # UUID v4 binário
X25519_PUBKEY_LEN = 32   # chave pública raw
SALT_LEN = 16
NONCE_LEN = 12           # IV_base (4B) || seq_no (8B)
IV_BASE_LEN = 4
SEQ_NO_LEN = 8           # big-endian
GCM_TAG_LEN = 16
AES_KEY_LEN = 16         # AES-128
RSA_KEY_BITS = 2048

LENGTH_PREFIX_LEN = 4    # prefixo de tamanho de cada frame TCP (big-endian)
MAX_PLAINTEXT_LEN = 4096

# Cabeçalho do frame E2E: nonce | sender_id | recipient_id | seq_no
E2E_HEADER_LEN = NONCE_LEN + 2 * CLIENT_ID_LEN + SEQ_NO_LEN
MAX_E2E_FRAME_LEN = E2E_HEADER_LEN + MAX_PLAINTEXT_LEN + GCM_TAG_LEN

# Limite absoluto aceito pelo framing. Frames maiores são erro de protocolo.
# Folga para mensagens de controle (ex.: handshake com certificado).
MAX_FRAME_LEN = 16 * 1024

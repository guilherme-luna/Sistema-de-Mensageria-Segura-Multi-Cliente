FROM python:3.12-slim

WORKDIR /app
ENV PYTHONUNBUFFERED=1

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY common/ common/
COPY server/ server/
COPY client/ client/
COPY scripts/ scripts/

# Roda sem privilégios. UID 1000 coincide com o usuário padrão na maioria dos
# Linux, para conseguir ler o server.key (permissão 600) montado do host.
RUN useradd --uid 1000 --no-create-home --shell /usr/sbin/nologin app
USER app

# Certificados entram por volume (ver docker-compose.yml), nunca na imagem
CMD ["python", "-m", "server.server"]

FROM python:3.12-slim

WORKDIR /app
ENV PYTHONUNBUFFERED=1

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY common/ common/
COPY server/ server/
COPY client/ client/
COPY scripts/ scripts/

# Certificados entram por volume (ver docker-compose.yml), nunca na imagem
CMD ["python", "-m", "server.server"]

# Usa imagem oficial do Python
FROM python:3.10-slim

# Informações do mantenedor
LABEL maintainer="TecHack Security Team"
LABEL description="Web Security Scanner - Ferramenta profissional de análise de vulnerabilidades"

# Define diretório de trabalho
WORKDIR /app

# Variáveis de ambiente para Python
ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    PIP_NO_CACHE_DIR=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1

# Instala dependências do sistema
RUN apt-get update && apt-get install -y --no-install-recommends \
    gcc \
    && rm -rf /var/lib/apt/lists/*

# Copia requirements primeiro (cache de layers)
COPY requirements.txt .

# Instala dependências Python
RUN pip install --no-cache-dir -r requirements.txt

# Copia todo o código da aplicação
COPY . .

# Cria diretórios necessários
RUN mkdir -p /app/src/web/data && \
    mkdir -p /app/logs

# Expõe a porta da aplicação
EXPOSE 5001

# Define variável de ambiente para produção
ENV FLASK_ENV=production

# Cria usuário não-root para segurança
RUN useradd -m -u 1000 scanner && \
    chown -R scanner:scanner /app

# Muda para usuário não-root
USER scanner

# Comando para iniciar a aplicação
CMD ["python3", "src/web/app_auth.py"]

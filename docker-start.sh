#!/bin/bash

# Script de inicialização do Web Security Scanner com Docker
# Fase 5: Containerização Completa

set -e

# Cores para output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

echo -e "${BLUE}"
echo "╔════════════════════════════════════════════════════════════╗"
echo "║         Web Security Scanner - Docker Setup              ║"
echo "║              Fase 5: Containerizacao                     ║"
echo "╚════════════════════════════════════════════════════════════╝"
echo -e "${NC}"

# Verificar se Docker está instalado
if ! command -v docker &> /dev/null; then
    echo -e "${RED}[ERRO] Docker nao esta instalado!${NC}"
    echo "Por favor, instale o Docker primeiro:"
    echo "  https://docs.docker.com/get-docker/"
    exit 1
fi

# Verifica se tem docker compose (versão moderna integrada)
if docker compose version &> /dev/null; then
    DOCKER_COMPOSE="docker compose"
elif command -v docker-compose &> /dev/null; then
    DOCKER_COMPOSE="docker-compose"
else
    echo -e "${RED}[ERRO] Docker Compose nao esta instalado!${NC}"
    echo "Por favor, instale o Docker Compose primeiro:"
    echo "  https://docs.docker.com/compose/install/"
    exit 1
fi

echo -e "${GREEN}[OK] Docker instalado:${NC} $(docker --version)"
echo -e "${GREEN}[OK] Docker Compose instalado:${NC} $($DOCKER_COMPOSE version)"
echo ""

# Verificar se há containers rodando
if docker ps | grep -q "web-security-scanner"; then
    echo -e "${YELLOW}[AVISO] Container ja esta rodando!${NC}"
    read -p "Deseja reiniciar? (s/N): " -n 1 -r
    echo
    if [[ $REPLY =~ ^[Ss]$ ]]; then
        echo -e "${YELLOW}Parando containers...${NC}"
        $DOCKER_COMPOSE down
    else
        echo -e "${BLUE}[INFO] Mantendo container atual.${NC}"
        exit 0
    fi
fi

# Perguntar se deseja rebuild
read -p "Deseja reconstruir a imagem? (s/N): " -n 1 -r
echo
if [[ $REPLY =~ ^[Ss]$ ]]; then
    BUILD_FLAG="--build"
    echo -e "${BLUE}Construindo imagem...${NC}"
else
    BUILD_FLAG=""
fi

# Iniciar containers
echo -e "${BLUE}Iniciando containers...${NC}"
$DOCKER_COMPOSE up -d $BUILD_FLAG

# Aguardar aplicação iniciar
echo -e "${YELLOW}Aguardando aplicacao iniciar...${NC}"
sleep 5

# Verificar se está rodando
if docker ps | grep -q "web-security-scanner"; then
    echo ""
    echo -e "${GREEN}╔════════════════════════════════════════════════════════════╗${NC}"
    echo -e "${GREEN}║           [OK] APLICACAO RODANDO COM SUCESSO!            ║${NC}"
    echo -e "${GREEN}╚════════════════════════════════════════════════════════════╝${NC}"
    echo ""
    echo -e "${BLUE}Acesse:${NC} http://localhost:5001"
    echo -e "${BLUE}Admin:${NC} admin@webscanner.com / admin123"
    echo ""
    echo -e "${YELLOW}Comandos uteis:${NC}"
    echo "  $DOCKER_COMPOSE logs -f scanner    # Ver logs"
    echo "  $DOCKER_COMPOSE ps                 # Status"
    echo "  $DOCKER_COMPOSE down               # Parar"
    echo "  $DOCKER_COMPOSE restart scanner    # Reiniciar"
    echo ""
else
    echo -e "${RED}[ERRO] Erro ao iniciar container!${NC}"
    echo "Verifique os logs:"
    echo "  $DOCKER_COMPOSE logs scanner"
    exit 1
fi

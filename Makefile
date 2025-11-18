.PHONY: help build up down restart logs status clean backup

# Cores
GREEN  := \033[0;32m
YELLOW := \033[1;33m
BLUE   := \033[0;34m
NC     := \033[0m

help: ## Mostra esta ajuda
	@echo "$(BLUE)╔════════════════════════════════════════════════════════════╗$(NC)"
	@echo "$(BLUE)║       Web Security Scanner - Docker Commands             ║$(NC)"
	@echo "$(BLUE)╚════════════════════════════════════════════════════════════╝$(NC)"
	@echo ""
	@grep -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) | awk 'BEGIN {FS = ":.*?## "}; {printf "  $(GREEN)%-15s$(NC) %s\n", $$1, $$2}'
	@echo ""

build: ## Constrói a imagem Docker
	@echo "$(YELLOW)Construindo imagem...$(NC)"
	docker-compose build

up: ## Inicia a aplicação
	@echo "$(GREEN)Iniciando aplicacao...$(NC)"
	docker-compose up -d
	@echo "$(GREEN)[OK] Aplicacao iniciada!$(NC)"
	@echo "$(BLUE)Acesse: http://localhost:5001$(NC)"

down: ## Para a aplicação
	@echo "$(YELLOW)Parando aplicacao...$(NC)"
	docker-compose down

restart: ## Reinicia a aplicação
	@echo "$(YELLOW)Reiniciando aplicacao...$(NC)"
	docker-compose restart scanner

logs: ## Mostra logs em tempo real
	docker-compose logs -f scanner

status: ## Mostra status dos containers
	@echo "$(BLUE)Status dos containers:$(NC)"
	docker-compose ps

clean: ## Remove tudo (containers, volumes, imagens)
	@echo "$(YELLOW)[AVISO] ATENCAO: Isso removera TODOS os dados!$(NC)"
	@read -p "Tem certeza? [s/N] " -n 1 -r; \
	echo; \
	if [[ $$REPLY =~ ^[Ss]$$ ]]; then \
		docker-compose down -v; \
		docker system prune -af; \
		echo "$(GREEN)[OK] Limpeza concluida!$(NC)"; \
	fi

backup: ## Faz backup do banco de dados
	@echo "$(BLUE)Fazendo backup...$(NC)"
	@mkdir -p backups
	docker cp web-security-scanner:/app/src/web/scanner.db backups/scanner-$$(date +%Y%m%d-%H%M%S).db
	@echo "$(GREEN)[OK] Backup salvo em backups/$(NC)"

shell: ## Entra no container (bash)
	docker-compose exec scanner bash

test: ## Executa testes
	docker-compose exec scanner python3 -m pytest

dev: ## Inicia em modo desenvolvimento (com rebuild)
	@echo "$(BLUE)Iniciando em modo desenvolvimento...$(NC)"
	docker-compose up -d --build
	@echo "$(GREEN)[OK] Modo dev iniciado!$(NC)"
	$(MAKE) logs

prod: ## Inicia em modo produção
	@echo "$(GREEN)Iniciando em modo producao...$(NC)"
	FLASK_ENV=production docker-compose up -d --build

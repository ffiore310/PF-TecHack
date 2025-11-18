# Web Security Scanner

Aplicação web para varredura automatizada de vulnerabilidades em sites e aplicações web.

## Descrição

Sistema completo de análise de segurança web com interface gráfica, autenticação multi-usuário e containerização Docker. Detecta vulnerabilidades comuns como XSS, SQL Injection e CSRF, gerando relatórios detalhados em HTML.

## Funcionalidades

- Varredura automatizada de vulnerabilidades web
- Sistema de autenticação multi-usuário
- Dashboard interativo com Bootstrap 5
- Execução assíncrona de scans (não bloqueia interface)
- Geração de relatórios HTML detalhados
- Isolamento de dados por usuário
- Persistência de dados com SQLite
- Containerização completa com Docker

## Vulnerabilidades Detectadas

- Cross-Site Scripting (XSS)
- SQL Injection
- Cross-Site Request Forgery (CSRF)
- Configurações de segurança inadequadas

## Tecnologias Utilizadas

### Backend
- Python 3.10
- Flask 3.0.0
- Flask-Login 0.6.3
- Flask-SQLAlchemy 3.1.1
- SQLAlchemy 2.0.23
- Flask-WTF 1.2.1
- Werkzeug 3.0.0

### Frontend
- Bootstrap 5
- HTML5/CSS3
- JavaScript

### Infraestrutura
- Docker 27.5.1
- Docker Compose v2.31.0
- SQLite (banco de dados)

## Requisitos

- Docker e Docker Compose instalados
- OU Python 3.10+ (para execução sem Docker)

## Instalação e Execução

### Opção 1: Com Docker (Recomendado)

```bash
# Clonar repositório
git clone https://github.com/ffiore310/PF-TecHack.git
cd PF-TecHack

# Iniciar aplicação
./docker-start.sh

# OU manualmente
docker compose up -d
```

### Opção 2: Sem Docker

```bash
# Clonar repositório
git clone https://github.com/ffiore310/PF-TecHack.git
cd PF-TecHack

# Criar ambiente virtual
python3 -m venv venv
source venv/bin/activate  # Linux/Mac
# venv\Scripts\activate   # Windows

# Instalar dependências
pip install -r requirements.txt

# Executar aplicação
python src/web/app_auth.py
```

## Acesso

Após iniciar a aplicação, acesse:

```
URL: http://localhost:5001
```

### Credenciais Admin Padrão

```
Email: admin@webscanner.com
Senha: admin123
```

## Uso

1. Faça login com as credenciais admin ou registre novo usuário
2. No dashboard, clique em "Novo Scan"
3. Preencha a URL alvo e descrição
4. Aguarde a conclusão do scan
5. Visualize o relatório detalhado
6. Baixe o relatório HTML se necessário

## Comandos Docker Úteis

```bash
# Ver logs em tempo real
docker compose logs -f scanner

# Verificar status
docker compose ps

# Parar aplicação
docker compose down

# Reiniciar
docker compose restart scanner

# Reconstruir imagem
docker compose build --no-cache
```

## Estrutura do Projeto

```
PF-TecHack/
├── src/
│   ├── scanner/
│   │   ├── __init__.py
│   │   ├── scanner.py          # Motor de varredura
│   │   ├── detectors.py        # Detectores de vulnerabilidades
│   │   └── report_generator.py # Gerador de relatórios
│   └── web/
│       ├── app_auth.py          # Aplicação Flask principal
│       ├── models.py            # Modelos SQLAlchemy
│       ├── forms.py             # Formulários WTForms
│       ├── templates/           # Templates Jinja2
│       └── static/              # CSS, JS, imagens
├── Dockerfile                   # Configuração Docker
├── docker-compose.yml           # Orquestração de containers
├── requirements.txt             # Dependências Python
└── README.md                    # Este arquivo
```

## Segurança

- Senhas armazenadas com hash (Werkzeug Security)
- Proteção CSRF em todos os formulários
- Sessões HTTP seguras
- SECRET_KEY gerado aleatoriamente a cada execução
- Isolamento de dados por usuário
- Execução com usuário não-root no container

## Arquitetura

### Banco de Dados

- **Users**: Armazena usuários e credenciais
- **Scans**: Registra varreduras realizadas
- **Reports**: Armazena relatórios gerados

### Fluxo de Execução

1. Usuário cria scan via interface web
2. Scan é executado em thread separada (assíncrono)
3. Detectores analisam URL alvo
4. Vulnerabilidades são registradas no banco
5. Relatório HTML é gerado automaticamente
6. Usuário visualiza resultados no dashboard

## Persistência de Dados

Ao usar Docker, os dados são persistidos em volumes:

- **scanner_data**: Banco de dados SQLite
- **scanner_logs**: Logs da aplicação

Os dados permanecem mesmo após parar os containers.

## Desenvolvimento

### Adicionar Novo Detector

1. Criar método em `src/scanner/detectors.py`
2. Adicionar chamada em `src/scanner/scanner.py`
3. Atualizar templates para exibir novo tipo

### Executar Testes

```bash
# Instalar dependências de teste
pip install pytest pytest-cov

# Executar testes
pytest

# Com cobertura
pytest --cov=src
```

## Limitações Conhecidas

- Varreduras limitadas a sites públicos
- Não realiza testes invasivos
- Requer conectividade de rede
- Tempo de scan varia conforme tamanho do site

## Licença

Este projeto foi desenvolvido para fins educacionais como parte da avaliação final da disciplina de Tecnologias Hacker.

## Autor

Fernando Fiore (@ffiore310)

## Aviso Legal

Esta ferramenta deve ser usada apenas em sites para os quais você tem autorização explícita. O uso não autorizado pode ser ilegal. O autor não se responsabiliza por uso indevido desta ferramenta.

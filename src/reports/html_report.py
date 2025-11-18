"""
Gerador de relatório HTML interativo standalone.
"""

from datetime import datetime
import json

class HtmlReport:
    """Gera relatório HTML interativo completo"""
    
    def __init__(self, results):
        """
        Args:
            results: Dicionário com resultados do scan
        """
        self.results = results
        self.url = results.get('url', 'N/A')
        self.timestamp = results.get('timestamp', datetime.now().isoformat())
        self.vulnerabilities = results.get('vulnerabilities', [])
        self.risk_summary = results.get('risk_summary', {})
        self.heuristic_insights = results.get('heuristic_insights', {})
        self.remediation_plan = results.get('remediation_plan', {})
        
    def generate(self):
        """Gera relatório HTML completo"""
        html = f"""<!DOCTYPE html>
<html lang="pt-BR">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Relatório de Segurança - {self.url}</title>
    
    <!-- Bootstrap CSS -->
    <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.1.3/dist/css/bootstrap.min.css" rel="stylesheet">
    <link href="https://cdn.jsdelivr.net/npm/bootstrap-icons@1.7.2/font/bootstrap-icons.css" rel="stylesheet">
    
    <style>
        :root {{
            --primary-color: #0d6efd;
            --danger-color: #dc3545;
            --warning-color: #ffc107;
            --success-color: #198754;
            --info-color: #0dcaf0;
        }}
        
        body {{
            font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, "Helvetica Neue", Arial, sans-serif;
            background: #f8f9fa;
        }}
        
        .header-section {{
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            color: white;
            padding: 3rem 0;
            margin-bottom: 2rem;
        }}
        
        .metric-card {{
            border-left: 4px solid var(--primary-color);
            transition: transform 0.2s, box-shadow 0.2s;
        }}
        
        .metric-card:hover {{
            transform: translateY(-5px);
            box-shadow: 0 4px 12px rgba(0,0,0,0.15);
        }}
        
        .metric-card.critical {{
            border-left-color: var(--danger-color);
        }}
        
        .metric-card.warning {{
            border-left-color: var(--warning-color);
        }}
        
        .metric-card.success {{
            border-left-color: var(--success-color);
        }}
        
        .metric-value {{
            font-size: 2.5rem;
            font-weight: bold;
            line-height: 1;
        }}
        
        .metric-label {{
            color: #6c757d;
            font-size: 0.9rem;
            text-transform: uppercase;
            letter-spacing: 0.5px;
        }}
        
        .nav-pills .nav-link {{
            color: #495057;
            border-radius: 0.5rem;
            padding: 0.75rem 1.5rem;
            margin: 0 0.25rem;
        }}
        
        .nav-pills .nav-link.active {{
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
        }}
        
        .vuln-card {{
            border-left: 4px solid #dee2e6;
            margin-bottom: 1rem;
            transition: all 0.2s;
        }}
        
        .vuln-card:hover {{
            box-shadow: 0 2px 8px rgba(0,0,0,0.1);
        }}
        
        .vuln-card.critical {{
            border-left-color: #dc3545;
        }}
        
        .vuln-card.high {{
            border-left-color: #fd7e14;
        }}
        
        .vuln-card.medium {{
            border-left-color: #ffc107;
        }}
        
        .vuln-card.low {{
            border-left-color: #0dcaf0;
        }}
        
        .code-block {{
            background: #282c34;
            color: #abb2bf;
            padding: 1rem;
            border-radius: 0.5rem;
            overflow-x: auto;
            font-family: 'Courier New', monospace;
            font-size: 0.875rem;
        }}
        
        .code-block.vulnerable {{
            border-left: 4px solid #dc3545;
        }}
        
        .code-block.secure {{
            border-left: 4px solid #198754;
        }}
        
        .chart-container {{
            position: relative;
            height: 300px;
            margin: 1rem 0;
        }}
        
        .attack-chain {{
            background: #fff3cd;
            border-left: 4px solid #ffc107;
            padding: 1rem;
            margin-bottom: 1rem;
        }}
        
        .timeline-item {{
            padding-left: 2rem;
            border-left: 2px solid #dee2e6;
            padding-bottom: 1rem;
            position: relative;
        }}
        
        .timeline-item:before {{
            content: '';
            width: 12px;
            height: 12px;
            background: #667eea;
            border-radius: 50%;
            position: absolute;
            left: -7px;
            top: 0;
        }}
        
        .quick-win {{
            background: #d1e7dd;
            border-left: 4px solid #198754;
            padding: 1rem;
            margin-bottom: 0.5rem;
        }}
        
        @media print {{
            .no-print {{
                display: none;
            }}
            
            .chart-container {{
                page-break-inside: avoid;
            }}
        }}
    </style>
</head>
<body>
    <!-- Header -->
    <div class="header-section">
        <div class="container">
            <div class="row align-items-center">
                <div class="col-md-8">
                    <h1><i class="bi bi-shield-lock"></i> Relatório de Segurança Web</h1>
                    <p class="lead mb-0">Análise completa de vulnerabilidades e recomendações</p>
                </div>
                <div class="col-md-4 text-end">
                    <button onclick="window.print()" class="btn btn-light no-print">
                        <i class="bi bi-printer"></i> Imprimir
                    </button>
                </div>
            </div>
        </div>
    </div>
    
    <!-- Main Content -->
    <div class="container mb-5">
        <!-- Informações Gerais -->
        <div class="card mb-4">
            <div class="card-body">
                <div class="row">
                    <div class="col-md-6">
                        <h6 class="text-muted">URL Analisada</h6>
                        <p class="mb-0"><code>{self.url}</code></p>
                    </div>
                    <div class="col-md-6 text-end">
                        <h6 class="text-muted">Data do Scan</h6>
                        <p class="mb-0">{self._format_timestamp(self.timestamp)}</p>
                    </div>
                </div>
            </div>
        </div>
        
        <!-- Métricas Principais -->
        {self._generate_metrics_section()}
        
        <!-- Navegação por Abas -->
        <ul class="nav nav-pills mb-4 no-print" id="reportTabs" role="tablist">
            <li class="nav-item" role="presentation">
                <button class="nav-link active" id="overview-tab" data-bs-toggle="pill" data-bs-target="#overview" type="button">
                    <i class="bi bi-graph-up"></i> Visão Geral
                </button>
            </li>
            <li class="nav-item" role="presentation">
                <button class="nav-link" id="vulnerabilities-tab" data-bs-toggle="pill" data-bs-target="#vulnerabilities" type="button">
                    <i class="bi bi-bug"></i> Vulnerabilidades
                </button>
            </li>
            <li class="nav-item" role="presentation">
                <button class="nav-link" id="remediation-tab" data-bs-toggle="pill" data-bs-target="#remediation" type="button">
                    <i class="bi bi-tools"></i> Remediação
                </button>
            </li>
            <li class="nav-item" role="presentation">
                <button class="nav-link" id="mitigation-tab" data-bs-toggle="pill" data-bs-target="#mitigation" type="button">
                    <i class="bi bi-code-slash"></i> Guias de Mitigação
                </button>
            </li>
        </ul>
        
        <!-- Conteúdo das Abas -->
        <div class="tab-content" id="reportTabsContent">
            <!-- Aba: Visão Geral -->
            <div class="tab-pane fade show active" id="overview">
                {self._generate_overview_section()}
            </div>
            
            <!-- Aba: Vulnerabilidades -->
            <div class="tab-pane fade" id="vulnerabilities">
                {self._generate_vulnerabilities_section()}
            </div>
            
            <!-- Aba: Remediação -->
            <div class="tab-pane fade" id="remediation">
                {self._generate_remediation_section()}
            </div>
            
            <!-- Aba: Guias de Mitigação -->
            <div class="tab-pane fade" id="mitigation">
                {self._generate_mitigation_guides()}
            </div>
        </div>
    </div>
    
    <!-- Footer -->
    <footer class="bg-dark text-white text-center py-3 mt-5">
        <div class="container">
            <p class="mb-0">Gerado por Web Security Scanner | {self._format_timestamp(datetime.now().isoformat())}</p>
        </div>
    </footer>
    
    <!-- Scripts -->
    <script src="https://cdn.jsdelivr.net/npm/bootstrap@5.1.3/dist/js/bootstrap.bundle.min.js"></script>
    <script src="https://cdn.jsdelivr.net/npm/chart.js@3.9.1/dist/chart.min.js"></script>
    <script>
        {self._generate_chart_scripts()}
    </script>
</body>
</html>
"""
        return html
    
    def _format_timestamp(self, timestamp):
        """Formata timestamp para exibição"""
        try:
            dt = datetime.fromisoformat(timestamp.replace('Z', '+00:00'))
            return dt.strftime('%d/%m/%Y às %H:%M:%S')
        except:
            return timestamp
    
    def _generate_metrics_section(self):
        """Gera seção de métricas principais"""
        total_vulns = len(self.vulnerabilities)
        avg_score = self.risk_summary.get('average_score', 0)
        risk_level = self.risk_summary.get('overall_risk_level', 'LOW')
        severity_dist = self.risk_summary.get('severity_distribution', {})
        
        # Busca por ambas as formas possíveis (CRITICAL ou Critical)
        critical_count = severity_dist.get('CRITICAL', severity_dist.get('Critical', 0))
        high_count = severity_dist.get('HIGH', severity_dist.get('High', 0))
        
        risk_color = {
            'CRITICAL': 'danger',
            'HIGH': 'warning',
            'MEDIUM': 'info',
            'LOW': 'success'
        }.get(risk_level, 'secondary')
        
        return f"""
        <div class="row mb-4">
            <div class="col-md-3">
                <div class="card metric-card">
                    <div class="card-body text-center">
                        <div class="metric-label">Total de Vulnerabilidades</div>
                        <div class="metric-value text-primary">{total_vulns}</div>
                    </div>
                </div>
            </div>
            <div class="col-md-3">
                <div class="card metric-card critical">
                    <div class="card-body text-center">
                        <div class="metric-label">Críticas</div>
                        <div class="metric-value text-danger">{critical_count}</div>
                    </div>
                </div>
            </div>
            <div class="col-md-3">
                <div class="card metric-card warning">
                    <div class="card-body text-center">
                        <div class="metric-label">Risk Score Médio</div>
                        <div class="metric-value text-warning">{avg_score:.1f}/10</div>
                    </div>
                </div>
            </div>
            <div class="col-md-3">
                <div class="card metric-card {risk_color}">
                    <div class="card-body text-center">
                        <div class="metric-label">Nível de Risco</div>
                        <div class="metric-value text-{risk_color}">{risk_level}</div>
                    </div>
                </div>
            </div>
        </div>
        """
    
    def _generate_overview_section(self):
        """Gera seção de visão geral com gráficos"""
        return f"""
        <div class="row">
            <div class="col-md-6">
                <div class="card">
                    <div class="card-header">
                        <h5 class="mb-0"><i class="bi bi-pie-chart"></i> Distribuição por Severidade</h5>
                    </div>
                    <div class="card-body">
                        <div class="chart-container">
                            <canvas id="severityChart"></canvas>
                        </div>
                    </div>
                </div>
            </div>
            <div class="col-md-6">
                <div class="card">
                    <div class="card-header">
                        <h5 class="mb-0"><i class="bi bi-bar-chart"></i> Vulnerabilidades por Tipo</h5>
                    </div>
                    <div class="card-body">
                        <div class="chart-container">
                            <canvas id="typeChart"></canvas>
                        </div>
                    </div>
                </div>
            </div>
        </div>
        
        <div class="row mt-4">
            <div class="col-12">
                <div class="card">
                    <div class="card-header">
                        <h5 class="mb-0"><i class="bi bi-exclamation-triangle"></i> Top 10 Vulnerabilidades por Risk Score</h5>
                    </div>
                    <div class="card-body">
                        <div class="chart-container" style="height: 400px;">
                            <canvas id="riskScoreChart"></canvas>
                        </div>
                    </div>
                </div>
            </div>
        </div>
        
        {self._generate_attack_chains_section()}
        """
    
    def _generate_attack_chains_section(self):
        """Gera seção de attack chains"""
        attack_chains = self.heuristic_insights.get('attack_chains', [])
        
        if not attack_chains:
            return ""
        
        html = """
        <div class="row mt-4">
            <div class="col-12">
                <div class="card border-warning">
                    <div class="card-header bg-warning text-dark">
                        <h5 class="mb-0"><i class="bi bi-link-45deg"></i> Attack Chains Detectadas</h5>
                    </div>
                    <div class="card-body">
        """
        
        for chain in attack_chains:
            html += f"""
                <div class="attack-chain">
                    <h6><i class="bi bi-exclamation-triangle-fill"></i> {chain.get('chain_name', 'N/A')}</h6>
                    <p class="mb-2"><strong>Severidade:</strong> <span class="badge bg-danger">{chain.get('severity', 'N/A')}</span></p>
                    <p class="mb-2"><strong>Componentes:</strong> {', '.join(chain.get('components', []))}</p>
                    <p class="mb-2"><strong>Vulnerabilidades Envolvidas:</strong> {chain.get('vulnerabilities_involved', 0)}</p>
                    <p class="mb-0">{chain.get('description', 'N/A')}</p>
                </div>
            """
        
        html += """
                    </div>
                </div>
            </div>
        </div>
        """
        
        return html
    
    def _generate_vulnerabilities_section(self):
        """Gera seção detalhada de vulnerabilidades"""
        if not self.vulnerabilities:
            return "<p class='text-muted'>Nenhuma vulnerabilidade encontrada.</p>"
        
        # Ordena por prioridade de remediação
        sorted_vulns = sorted(self.vulnerabilities, key=lambda v: v.get('remediation_priority', 999))
        
        html = "<div class='row'><div class='col-12'>"
        
        for i, vuln in enumerate(sorted_vulns, 1):
            severity = vuln.get('severity_level', vuln.get('severity', 'Medium'))
            severity_class = severity.lower()
            risk_score = vuln.get('risk_score', 0)
            priority = vuln.get('remediation_priority', i)
            
            severity_badge_color = {
                'CRITICAL': 'danger',
                'Critical': 'danger',
                'HIGH': 'warning',
                'High': 'warning',
                'MEDIUM': 'info',
                'Medium': 'info',
                'LOW': 'secondary',
                'Low': 'secondary'
            }.get(severity, 'secondary')
            
            html += f"""
            <div class="card vuln-card {severity_class} mb-3">
                <div class="card-body">
                    <div class="d-flex justify-content-between align-items-start">
                        <h5 class="card-title">
                            <span class="badge bg-secondary">#{priority}</span>
                            {vuln.get('type', 'N/A')}
                        </h5>
                        <span class="badge bg-{severity_badge_color} fs-6">{severity} - {risk_score:.1f}/10</span>
                    </div>
                    
                    <p class="mb-2"><strong>URL:</strong> <code>{vuln.get('url', 'N/A')}</code></p>
                    <p class="mb-2"><strong>Método:</strong> {vuln.get('method', 'N/A')}</p>
                    <p class="mb-3">{vuln.get('description', 'N/A')}</p>
                    
                    {self._generate_metrics_info(vuln)}
                    {self._generate_recommendation_info(vuln)}
                </div>
            </div>
            """
        
        html += "</div></div>"
        return html
    
    def _generate_metrics_info(self, vuln):
        """Gera informações de métricas da vulnerabilidade"""
        metrics = vuln.get('metrics', {})
        if not metrics:
            return ""
        
        return f"""
        <div class="alert alert-light">
            <small class="text-muted">
                <strong>Métricas CVSS:</strong> 
                Base Score: {metrics.get('base_score', 'N/A')} | 
                Impact: {metrics.get('impact_score', 'N/A')} | 
                Exploitability: {metrics.get('exploitability', 'N/A')}x
            </small>
        </div>
        """
    
    def _generate_recommendation_info(self, vuln):
        """Gera informações de recomendação"""
        recommendation = vuln.get('recommendation')
        if not recommendation:
            return ""
        
        return f"""
        <div class="mt-3">
            <h6><i class="bi bi-lightbulb"></i> Recomendação:</h6>
            <p class="mb-0">{recommendation}</p>
        </div>
        """
    
    def _generate_remediation_section(self):
        """Gera seção de plano de remediação"""
        plan = self.remediation_plan
        timeline = plan.get('estimated_timeline', {})
        quick_wins = plan.get('quick_wins', [])
        phases = plan.get('remediation_phases', [])
        
        html = "<div class='row'>"
        
        # Timeline
        html += f"""
        <div class="col-md-6">
            <div class="card">
                <div class="card-header">
                    <h5 class="mb-0"><i class="bi bi-clock-history"></i> Timeline de Remediação</h5>
                </div>
                <div class="card-body">
                    <p><strong>Tempo Total Estimado:</strong> {timeline.get('total_hours', 0)}h ({timeline.get('total_days', 0)} dias)</p>
                    <p class="text-muted">{timeline.get('recommendation', 'N/A')}</p>
                    <hr>
                    <h6>Breakdown por Severidade:</h6>
                    <ul>
        """
        
        breakdown = timeline.get('breakdown', {})
        for sev, time in breakdown.items():
            html += f"<li><strong>{sev}:</strong> {time}</li>"
        
        html += "</ul>"
        
        if phases:
            html += "<hr><h6>Fases de Remediação:</h6>"
            for phase in phases:
                html += f"""
                <div class="timeline-item">
                    <h6>Fase {phase.get('phase', 'N/A')}: {phase.get('name', 'N/A')}</h6>
                    <p class="mb-1"><strong>Período:</strong> {phase.get('timeframe', 'N/A')}</p>
                    <p class="mb-0 text-muted">{phase.get('description', 'N/A')}</p>
                </div>
                """
        
        html += """
                </div>
            </div>
        </div>
        """
        
        # Quick Wins
        html += """
        <div class="col-md-6">
            <div class="card">
                <div class="card-header">
                    <h5 class="mb-0"><i class="bi bi-lightning"></i> Quick Wins</h5>
                </div>
                <div class="card-body">
        """
        
        if not quick_wins:
            html += "<p class='text-muted'>Nenhuma correção rápida identificada.</p>"
        else:
            for i, win in enumerate(quick_wins, 1):
                html += f"""
                <div class="quick-win">
                    <h6>{i}. {win.get('vulnerability', 'N/A')}</h6>
                    <p class="mb-1"><small class="text-muted">{win.get('location', 'N/A')}</small></p>
                    <p class="mb-1"><i class="bi bi-lightning-fill text-warning"></i> {win.get('quick_fix', 'N/A')}</p>
                    <p class="mb-0"><strong>Tempo estimado:</strong> <span class="badge bg-primary">{win.get('estimated_time', 'N/A')}</span></p>
                </div>
                """
        
        html += """
                </div>
            </div>
        </div>
        """
        
        html += "</div>"
        return html
    
    def _generate_mitigation_guides(self):
        """Gera guias detalhados de mitigação com exemplos de código"""
        
        # Agrupa vulnerabilidades por tipo
        vuln_types = {}
        for vuln in self.vulnerabilities:
            vtype = vuln.get('type', 'Unknown')
            if vtype not in vuln_types:
                vuln_types[vtype] = []
            vuln_types[vtype].append(vuln)
        
        html = "<div class='row'><div class='col-12'>"
        
        for vtype, vulns in vuln_types.items():
            guide = self._get_mitigation_guide(vtype)
            
            html += f"""
            <div class="card mb-4">
                <div class="card-header bg-primary text-white">
                    <h5 class="mb-0"><i class="bi bi-shield-check"></i> {vtype}</h5>
                </div>
                <div class="card-body">
                    <p><strong>Ocorrências:</strong> {len(vulns)}</p>
                    
                    <h6 class="mt-3"><i class="bi bi-info-circle"></i> Descrição</h6>
                    <p>{guide['description']}</p>
                    
                    <h6 class="mt-3"><i class="bi bi-exclamation-triangle"></i> Impacto</h6>
                    <p>{guide['impact']}</p>
                    
                    <h6 class="mt-3"><i class="bi bi-code-slash"></i> Exemplo de Código Vulnerável</h6>
                    <pre class="code-block vulnerable">{guide['vulnerable_code']}</pre>
                    
                    <h6 class="mt-3"><i class="bi bi-check-circle"></i> Exemplo de Código Seguro</h6>
                    <pre class="code-block secure">{guide['secure_code']}</pre>
                    
                    <h6 class="mt-3"><i class="bi bi-list-check"></i> Checklist de Verificação</h6>
                    <ul>
            """
            
            for item in guide['checklist']:
                html += f"<li>{item}</li>"
            
            html += f"""
                    </ul>
                    
                    <h6 class="mt-3"><i class="bi bi-link-45deg"></i> Referências</h6>
                    <ul>
            """
            
            for ref in guide['references']:
                html += f"<li><a href='{ref['url']}' target='_blank'>{ref['title']}</a></li>"
            
            html += """
                    </ul>
                </div>
            </div>
            """
        
        html += "</div></div>"
        return html
    
    def _get_mitigation_guide(self, vuln_type):
        """Retorna guia de mitigação específico para cada tipo de vulnerabilidade"""
        
        guides = {
            'Cross-Site Scripting (XSS)': {
                'description': 'Cross-Site Scripting (XSS) permite que atacantes injetem scripts maliciosos em páginas web visualizadas por outros usuários. Isso pode levar ao roubo de cookies, sessões, credenciais e manipulação de conteúdo.',
                'impact': 'Roubo de sessões, phishing, redirecionamento malicioso, execução de código no navegador da vítima.',
                'vulnerable_code': '''# Python/Flask - VULNERÁVEL
from flask import request, render_template_string

@app.route('/search')
def search():
    query = request.args.get('q', '')
    # Renderiza entrada do usuário diretamente (PERIGOSO!)
    return render_template_string(f'<h1>Resultados para: {query}</h1>')''',
                'secure_code': '''# Python/Flask - SEGURO
from flask import request, render_template_string, escape

@app.route('/search')
def search():
    query = request.args.get('q', '')
    # Escapa a entrada do usuário
    safe_query = escape(query)
    return render_template_string(f'<h1>Resultados para: {safe_query}</h1>')
    
# Ou use templates Jinja2 que fazem auto-escape:
# return render_template('search.html', query=query)''',
                'checklist': [
                    'Validar e sanitizar todas as entradas do usuário',
                    'Usar escape HTML em todas as saídas',
                    'Implementar Content Security Policy (CSP)',
                    'Usar bibliotecas de template com auto-escape (Jinja2, React)',
                    'Nunca usar eval() ou innerHTML com dados não confiáveis',
                    'Validar dados no servidor, não apenas no cliente'
                ],
                'references': [
                    {'title': 'OWASP XSS Prevention Cheat Sheet', 'url': 'https://cheatsheetseries.owasp.org/cheatsheets/Cross_Site_Scripting_Prevention_Cheat_Sheet.html'},
                    {'title': 'Content Security Policy Guide', 'url': 'https://developer.mozilla.org/en-US/docs/Web/HTTP/CSP'}
                ]
            },
            'SQL Injection': {
                'description': 'SQL Injection permite que atacantes executem comandos SQL arbitrários no banco de dados através de entradas não sanitizadas.',
                'impact': 'Vazamento de dados sensíveis, modificação/exclusão de dados, bypass de autenticação, execução de comandos no servidor.',
                'vulnerable_code': '''# Python - VULNERÁVEL
import sqlite3

def get_user(username):
    conn = sqlite3.connect('database.db')
    cursor = conn.cursor()
    # Concatenação direta de SQL (PERIGOSO!)
    query = f"SELECT * FROM users WHERE username = '{username}'"
    cursor.execute(query)
    return cursor.fetchone()''',
                'secure_code': '''# Python - SEGURO
import sqlite3

def get_user(username):
    conn = sqlite3.connect('database.db')
    cursor = conn.cursor()
    # Usa parameterized queries
    query = "SELECT * FROM users WHERE username = ?"
    cursor.execute(query, (username,))
    return cursor.fetchone()
    
# Ou use ORM como SQLAlchemy:
# user = User.query.filter_by(username=username).first()''',
                'checklist': [
                    'Usar sempre prepared statements ou parameterized queries',
                    'Nunca concatenar strings para construir SQL',
                    'Usar ORMs (SQLAlchemy, Django ORM, etc.)',
                    'Validar e sanitizar entradas no servidor',
                    'Aplicar princípio do menor privilégio no banco',
                    'Usar stored procedures quando apropriado',
                    'Implementar WAF (Web Application Firewall)'
                ],
                'references': [
                    {'title': 'OWASP SQL Injection Prevention', 'url': 'https://cheatsheetseries.owasp.org/cheatsheets/SQL_Injection_Prevention_Cheat_Sheet.html'},
                    {'title': 'SQLAlchemy Documentation', 'url': 'https://docs.sqlalchemy.org/'}
                ]
            },
            'Command Injection': {
                'description': 'Command Injection permite que atacantes executem comandos arbitrários no sistema operacional do servidor.',
                'impact': 'Execução remota de código, comprometimento total do servidor, acesso a dados sensíveis, instalação de malware.',
                'vulnerable_code': """# Python - VULNERÁVEL
# import os

def ping_host(host):
    # Executa comando com entrada do usuário (PERIGOSO!)
    result = os.system(f'ping -c 4 {host}')
    return result""",
                'secure_code': """# Python - SEGURO
# import subprocess
# import shlex

def ping_host(host):
    # Valida entrada
    if not host.replace('.', '').replace('-', '').isalnum():
        raise ValueError('Host inválido')
    
    # Usa subprocess com lista de argumentos
    try:
        result = subprocess.run(
            ['ping', '-c', '4', host],
            capture_output=True,
            text=True,
            timeout=10
        )
        return result.stdout
    except subprocess.TimeoutExpired:
        return 'Timeout'""",
                'checklist': [
                    'Evitar execução de comandos shell quando possível',
                    'Usar subprocess.run() com lista de argumentos',
                    'Nunca passar entrada do usuário diretamente para shell',
                    'Validar e sanitizar todas as entradas',
                    'Usar bibliotecas Python nativas ao invés de comandos',
                    'Implementar whitelist de comandos permitidos',
                    'Executar processos com usuário de baixo privilégio'
                ],
                'references': [
                    {'title': 'OWASP Command Injection', 'url': 'https://owasp.org/www-community/attacks/Command_Injection'},
                    {'title': 'Python subprocess Security', 'url': 'https://docs.python.org/3/library/subprocess.html#security-considerations'}
                ]
            },
            'Broken Authentication': {
                'description': 'Falhas de autenticação permitem que atacantes comprometam senhas, chaves ou tokens de sessão.',
                'impact': 'Roubo de identidade, acesso não autorizado, comprometimento de contas.',
                'vulnerable_code': """# Python/Flask - VULNERÁVEL
# Importa sessão do Flask
# from flask import session

@app.route('/login', methods=['POST'])
def login():
    username = request.form['username']
    password = request.form['password']
    
    # Senha em texto puro (PERIGOSO!)
    if username == 'admin' and password == 'admin123':
        session['user'] = username
        return 'Login OK'
    return 'Login falhou'
    
# Sessão sem timeout
# Sem proteção contra brute force""",
                'secure_code': """# Python/Flask - SEGURO
# from flask import session
# from werkzeug.security import check_password_hash
# from datetime import timedelta

# app.config['PERMANENT_SESSION_LIFETIME'] = timedelta(hours=1)

@app.route('/login', methods=['POST'])
def login():
    username = request.form['username']
    password = request.form['password']
    
    # Busca usuário do banco
    user = User.query.filter_by(username=username).first()
    
    if user and check_password_hash(user.password_hash, password):
        session.permanent = True
        session['user_id'] = user.id
        # Log de acesso
        log_login_attempt(username, success=True)
        return 'Login OK'
    
    # Rate limiting
    log_login_attempt(username, success=False)
    return 'Login falhou', 401""",
                'checklist': [
                    'Usar hash forte para senhas (bcrypt, Argon2)',
                    'Implementar rate limiting e bloqueio após tentativas',
                    'Usar sessões seguras com timeout',
                    'Implementar autenticação multifator (MFA)',
                    'Usar HTTPS para todas as comunicações',
                    'Implementar política de senha forte',
                    'Fazer logout seguro e invalidação de sessão',
                    'Proteger contra ataques de força bruta'
                ],
                'references': [
                    {'title': 'OWASP Authentication Cheat Sheet', 'url': 'https://cheatsheetseries.owasp.org/cheatsheets/Authentication_Cheat_Sheet.html'},
                    {'title': 'Flask Security Best Practices', 'url': 'https://flask.palletsprojects.com/en/2.3.x/security/'}
                ]
            },
            'Cryptographic Failures': {
                'description': 'Falhas criptográficas expõem dados sensíveis devido a criptografia fraca ou mal implementada.',
                'impact': 'Exposição de dados sensíveis, comprometimento de comunicações, violação de privacidade.',
                'vulnerable_code': """# Python - VULNERÁVEL
# import hashlib

def hash_password(password):
    # MD5 é fraco e inseguro (PERIGOSO!)
    return hashlib.md5(password.encode()).hexdigest()

def encrypt_data(data, key):
    # XOR simples não é seguro
    return ''.join(chr(ord(c) ^ key) for c in data)""",
                'secure_code': """# Python - SEGURO
# from werkzeug.security import generate_password_hash, check_password_hash
# from cryptography.fernet import Fernet

def hash_password(password):
    # Usa bcrypt através do Werkzeug
    return generate_password_hash(password, method='pbkdf2:sha256')

def encrypt_data(data, key):
    # Usa Fernet (AES-128 em modo CBC)
    f = Fernet(key)
    return f.encrypt(data.encode())

def decrypt_data(encrypted_data, key):
    f = Fernet(key)
    return f.decrypt(encrypted_data).decode()

# Gerar chave segura:
# key = Fernet.generate_key()""",
                'checklist': [
                    'Usar algoritmos aprovados (AES-256, RSA-2048+)',
                    'Nunca usar MD5 ou SHA1 para senhas',
                    'Usar bcrypt, scrypt ou Argon2 para hash de senhas',
                    'Implementar TLS/SSL para dados em trânsito',
                    'Usar bibliotecas criptográficas confiáveis',
                    'Gerenciar chaves de forma segura (não hardcode)',
                    'Criptografar dados sensíveis em repouso',
                    'Implementar Perfect Forward Secrecy'
                ],
                'references': [
                    {'title': 'OWASP Cryptographic Storage', 'url': 'https://cheatsheetseries.owasp.org/cheatsheets/Cryptographic_Storage_Cheat_Sheet.html'},
                    {'title': 'Python Cryptography Library', 'url': 'https://cryptography.io/en/latest/'}
                ]
            }
        }
        
        # Retorna guia específico ou genérico
        return guides.get(vuln_type, {
            'description': f'Vulnerabilidade do tipo {vuln_type} detectada.',
            'impact': 'Impacto varia dependendo do contexto e severidade.',
            'vulnerable_code': '# Exemplo específico não disponível',
            'secure_code': '# Consulte documentação específica para este tipo de vulnerabilidade',
            'checklist': [
                'Validar todas as entradas do usuário',
                'Implementar princípio do menor privilégio',
                'Manter bibliotecas e frameworks atualizados',
                'Realizar code review e testes de segurança',
                'Consultar documentação OWASP'
            ],
            'references': [
                {'title': 'OWASP Top 10', 'url': 'https://owasp.org/www-project-top-ten/'},
                {'title': 'OWASP Cheat Sheet Series', 'url': 'https://cheatsheetseries.owasp.org/'}
            ]
        })
    
    def _generate_chart_scripts(self):
        """Gera scripts JavaScript para os gráficos"""
        
        # Prepara dados para os gráficos
        severity_dist = self.risk_summary.get('severity_distribution', {})
        
        # Agrupa vulnerabilidades por tipo
        type_counts = {}
        risk_scores_data = []
        
        for vuln in self.vulnerabilities:
            vtype = vuln.get('type', 'Unknown')
            type_counts[vtype] = type_counts.get(vtype, 0) + 1
        
        # Top 10 por risk score
        sorted_vulns = sorted(self.vulnerabilities, key=lambda v: v.get('risk_score', 0), reverse=True)[:10]
        for i, vuln in enumerate(sorted_vulns, 1):
            risk_scores_data.append({
                'label': f"#{i} {vuln.get('type', 'N/A')}",
                'score': vuln.get('risk_score', 0)
            })
        
        return f"""
        // Dados dos gráficos
        const severityData = {json.dumps(severity_dist)};
        const typeData = {json.dumps(type_counts)};
        const riskScoresData = {json.dumps(risk_scores_data)};
        
        // Gráfico de Severidade (Pizza)
        const severityCtx = document.getElementById('severityChart');
        if (severityCtx) {{
            new Chart(severityCtx, {{
                type: 'doughnut',
                data: {{
                    labels: Object.keys(severityData),
                    datasets: [{{
                        data: Object.values(severityData),
                        backgroundColor: [
                            '#dc3545', // Critical
                            '#fd7e14', // High
                            '#ffc107', // Medium
                            '#0dcaf0', // Low
                            '#6c757d'  // Info
                        ]
                    }}]
                }},
                options: {{
                    responsive: true,
                    maintainAspectRatio: false,
                    plugins: {{
                        legend: {{
                            position: 'bottom'
                        }}
                    }}
                }}
            }});
        }}
        
        // Gráfico de Tipos (Barras)
        const typeCtx = document.getElementById('typeChart');
        if (typeCtx) {{
            new Chart(typeCtx, {{
                type: 'bar',
                data: {{
                    labels: Object.keys(typeData),
                    datasets: [{{
                        label: 'Quantidade',
                        data: Object.values(typeData),
                        backgroundColor: '#0d6efd'
                    }}]
                }},
                options: {{
                    responsive: true,
                    maintainAspectRatio: false,
                    plugins: {{
                        legend: {{
                            display: false
                        }}
                    }},
                    scales: {{
                        y: {{
                            beginAtZero: true,
                            ticks: {{
                                stepSize: 1
                            }}
                        }}
                    }}
                }}
            }});
        }}
        
        // Gráfico de Risk Scores (Barras Horizontais)
        const riskScoreCtx = document.getElementById('riskScoreChart');
        if (riskScoreCtx) {{
            const labels = riskScoresData.map(item => item.label);
            const scores = riskScoresData.map(item => item.score);
            const colors = scores.map(score => {{
                if (score >= 9) return '#dc3545';
                if (score >= 7) return '#fd7e14';
                if (score >= 4) return '#ffc107';
                return '#0dcaf0';
            }});
            
            new Chart(riskScoreCtx, {{
                type: 'bar',
                data: {{
                    labels: labels,
                    datasets: [{{
                        label: 'Risk Score',
                        data: scores,
                        backgroundColor: colors
                    }}]
                }},
                options: {{
                    indexAxis: 'y',
                    responsive: true,
                    maintainAspectRatio: false,
                    plugins: {{
                        legend: {{
                            display: false
                        }}
                    }},
                    scales: {{
                        x: {{
                            beginAtZero: true,
                            max: 10
                        }}
                    }}
                }}
            }});
        }}
        """

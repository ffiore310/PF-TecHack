"""
Motor de recomendações de remediação para vulnerabilidades.
Fornece soluções práticas e priorizadas.
"""

from typing import Dict, List, Tuple


class RecommendationEngine:
    """
    Gera recomendações de remediação personalizadas baseadas em
    tipo de vulnerabilidade, contexto e prioridade.
    """
    
    # Recomendações detalhadas por tipo de vulnerabilidade
    REMEDIATION_GUIDES = {
        'XSS': {
            'title': 'Cross-Site Scripting (XSS)',
            'priority': 'HIGH',
            'quick_fix': 'Escapar todos os inputs do usuário antes de exibi-los',
            'detailed_steps': [
                'Implementar Content Security Policy (CSP) headers',
                'Usar funções de escape de HTML (ex: htmlspecialchars em PHP)',
                'Validar e sanitizar todos os inputs do usuário',
                'Usar frameworks que fazem escape automático (React, Angular)',
                'Implementar HTTPOnly e Secure flags em cookies'
            ],
            'code_examples': {
                'python': '''
# Escape de HTML em Python (Flask)
from markupsafe import escape

@app.route('/user/<username>')
def show_user(username):
    return f'User: {escape(username)}'
    
# Ou use templates com auto-escape
return render_template('user.html', username=username)
''',
                'javascript': '''
// Escape de HTML em JavaScript
function escapeHtml(unsafe) {
    return unsafe
        .replace(/&/g, "&amp;")
        .replace(/</g, "&lt;")
        .replace(/>/g, "&gt;")
        .replace(/"/g, "&quot;")
        .replace(/'/g, "&#039;");
}

// Ou use textContent em vez de innerHTML
element.textContent = userInput;
''',
                'headers': '''
# CSP Header
Content-Security-Policy: default-src 'self'; script-src 'self' 'unsafe-inline'
'''
            },
            'prevention_checklist': [
                '☐ Implementar CSP headers',
                '☐ Escapar output em templates',
                '☐ Validar inputs no servidor',
                '☐ Usar HTTPOnly em cookies',
                '☐ Testar com payloads XSS'
            ],
            'testing_tools': ['Burp Suite', 'OWASP ZAP', 'XSS Strike'],
            'references': [
                'OWASP XSS Prevention Cheat Sheet',
                'Content Security Policy Guide',
                'OWASP Testing Guide - XSS'
            ]
        },
        
        'SQL Injection': {
            'title': 'SQL Injection',
            'priority': 'CRITICAL',
            'quick_fix': 'Usar prepared statements/parameterized queries',
            'detailed_steps': [
                'Substituir concatenação de SQL por prepared statements',
                'Usar ORMs que previnem SQL injection (SQLAlchemy, Hibernate)',
                'Implementar validação rigorosa de inputs',
                'Aplicar princípio do menor privilégio no banco de dados',
                'Usar stored procedures quando apropriado',
                'Nunca confiar em inputs do cliente'
            ],
            'code_examples': {
                'python': '''
# VULNERÁVEL - NÃO FAÇA ISSO
cursor.execute(f"SELECT * FROM users WHERE username = '{username}'")

# SEGURO - Use parameterized queries
cursor.execute("SELECT * FROM users WHERE username = %s", (username,))

# Ou use ORM (SQLAlchemy)
user = db.session.query(User).filter_by(username=username).first()
''',
                'php': '''
# VULNERÁVEL
$query = "SELECT * FROM users WHERE id = " . $_GET['id'];

# SEGURO - PDO com prepared statements
$stmt = $pdo->prepare("SELECT * FROM users WHERE id = ?");
$stmt->execute([$_GET['id']]);
''',
                'java': '''
// VULNERÁVEL
String query = "SELECT * FROM users WHERE id = " + userId;

// SEGURO - PreparedStatement
PreparedStatement stmt = conn.prepareStatement(
    "SELECT * FROM users WHERE id = ?"
);
stmt.setInt(1, userId);
'''
            },
            'prevention_checklist': [
                '☐ Usar prepared statements em todas as queries',
                '☐ Validar tipos de dados de inputs',
                '☐ Implementar whitelist de caracteres permitidos',
                '☐ Usar ORM quando possível',
                '☐ Aplicar least privilege no DB',
                '☐ Testar com SQLMap'
            ],
            'testing_tools': ['SQLMap', 'Burp Suite', 'jSQL Injection'],
            'references': [
                'OWASP SQL Injection Prevention Cheat Sheet',
                'SQL Injection Attacks and Defense',
                'Database Security Best Practices'
            ]
        },
        
        'Command Injection': {
            'title': 'Command Injection',
            'priority': 'CRITICAL',
            'quick_fix': 'Evitar chamadas ao shell com input do usuário',
            'detailed_steps': [
                'Usar bibliotecas nativas em vez de comandos shell',
                'Se necessário usar shell, validar rigorosamente inputs',
                'Usar whitelist de comandos e parâmetros permitidos',
                'Escapar caracteres especiais do shell',
                'Executar comandos com privilégios mínimos',
                'Considerar containerização/sandboxing'
            ],
            'code_examples': {
                'python': '''
# VULNERÁVEL
import os
filename = request.args.get('file')
os.system(f'cat {filename}')

# SEGURO - Use biblioteca nativa
import pathlib
filepath = pathlib.Path(filename)
if filepath.is_file():
    content = filepath.read_text()

# Se precisar de shell, use subprocess com lista
import subprocess
subprocess.run(['cat', filename], check=True)
''',
                'php': '''
# VULNERÁVEL
system("ping -c 4 " . $_GET['host']);

# SEGURO - Escape e validação
$host = escapeshellarg($_GET['host']);
if (preg_match('/^[a-zA-Z0-9.-]+$/', $_GET['host'])) {
    system("ping -c 4 " . $host);
}
'''
            },
            'prevention_checklist': [
                '☐ Evitar execução de comandos shell',
                '☐ Usar APIs nativas quando possível',
                '☐ Implementar whitelist de comandos',
                '☐ Validar e escapar todos inputs',
                '☐ Executar com privilégios mínimos',
                '☐ Auditar logs de execução'
            ],
            'testing_tools': ['Commix', 'Burp Suite', 'Manual Testing'],
            'references': [
                'OWASP Command Injection',
                'Secure Coding Guidelines',
                'OS Command Injection Defense'
            ]
        },
        
        'Path Traversal': {
            'title': 'Path Traversal',
            'priority': 'HIGH',
            'quick_fix': 'Validar e normalizar todos caminhos de arquivo',
            'detailed_steps': [
                'Usar whitelist de arquivos/diretórios permitidos',
                'Normalizar caminhos para resolver ../ e ./',
                'Validar que o caminho resolvido está dentro do diretório base',
                'Evitar concatenação direta de caminhos',
                'Usar funções seguras de manipulação de arquivos',
                'Implementar controle de acesso granular'
            ],
            'code_examples': {
                'python': '''
# VULNERÁVEL
filename = request.args.get('file')
with open(f'/var/www/files/{filename}') as f:
    content = f.read()

# SEGURO
import os
from pathlib import Path

base_dir = Path('/var/www/files')
filename = request.args.get('file')
filepath = (base_dir / filename).resolve()

# Verifica se está dentro do diretório base
if base_dir in filepath.parents:
    content = filepath.read_text()
else:
    raise ValueError("Invalid path")
''',
                'java': '''
// VULNERÁVEL
File file = new File("uploads/" + filename);

// SEGURO
Path basePath = Paths.get("uploads").toAbsolutePath().normalize();
Path filePath = basePath.resolve(filename).normalize();

if (!filePath.startsWith(basePath)) {
    throw new SecurityException("Invalid path");
}
'''
            },
            'prevention_checklist': [
                '☐ Implementar validação de caminhos',
                '☐ Usar whitelist de arquivos',
                '☐ Normalizar todos os paths',
                '☐ Verificar paths resolvidos',
                '☐ Implementar controle de acesso',
                '☐ Testar com ../../../etc/passwd'
            ],
            'testing_tools': ['Burp Suite', 'DotDotPwn', 'Manual Testing'],
            'references': [
                'OWASP Path Traversal',
                'File Upload Security',
                'Secure File Handling'
            ]
        },
        
        'CSRF': {
            'title': 'Cross-Site Request Forgery (CSRF)',
            'priority': 'MEDIUM',
            'quick_fix': 'Implementar tokens CSRF em formulários',
            'detailed_steps': [
                'Gerar tokens CSRF únicos por sessão',
                'Incluir tokens em todos formulários e requests de mudança de estado',
                'Validar tokens no servidor antes de processar',
                'Usar SameSite cookie attribute',
                'Verificar cabeçalho Origin/Referer',
                'Implementar re-autenticação para ações sensíveis'
            ],
            'code_examples': {
                'python': '''
# Flask com Flask-WTF
from flask_wtf.csrf import CSRFProtect

app = Flask(__name__)
app.config['SECRET_KEY'] = 'your-secret-key'
csrf = CSRFProtect(app)

# No template
<form method="POST">
    {{ csrf_token() }}
    <!-- form fields -->
</form>

# Para AJAX
<script>
var csrf_token = "{{ csrf_token() }}";
$.ajax({
    headers: {"X-CSRFToken": csrf_token},
    // ...
});
</script>
''',
                'php': '''
// Gerar token
session_start();
if (empty($_SESSION['csrf_token'])) {
    $_SESSION['csrf_token'] = bin2hex(random_bytes(32));
}

// No formulário
<input type="hidden" name="csrf_token" 
       value="<?= $_SESSION['csrf_token'] ?>">

// Validar
if ($_POST['csrf_token'] !== $_SESSION['csrf_token']) {
    die('CSRF token validation failed');
}
'''
            },
            'prevention_checklist': [
                '☐ Implementar tokens CSRF',
                '☐ Validar tokens no servidor',
                '☐ Usar SameSite cookies',
                '☐ Verificar Origin header',
                '☐ Re-autenticar ações críticas',
                '☐ Testar com CSRF PoCs'
            ],
            'testing_tools': ['Burp Suite', 'OWASP ZAP', 'CSRF PoC Generator'],
            'references': [
                'OWASP CSRF Prevention Cheat Sheet',
                'SameSite Cookie Explained',
                'CSRF Defense in Depth'
            ]
        },
        
        'Authentication Failure': {
            'title': 'Authentication Failure',
            'priority': 'CRITICAL',
            'quick_fix': 'Implementar autenticação robusta e MFA',
            'detailed_steps': [
                'Usar bibliotecas de autenticação bem estabelecidas',
                'Implementar autenticação multi-fator (MFA)',
                'Aplicar rate limiting em tentativas de login',
                'Usar hashing forte para senhas (bcrypt, Argon2)',
                'Implementar lockout após tentativas falhas',
                'Usar sessões seguras com timeout adequado'
            ],
            'code_examples': {
                'python': '''
# Flask-Login com bcrypt
from flask_login import LoginManager, login_user
from werkzeug.security import generate_password_hash, check_password_hash

# Hash de senha
hashed = generate_password_hash(password, method='pbkdf2:sha256')

# Verificação
if check_password_hash(user.password_hash, password):
    login_user(user)
    
# Rate limiting
from flask_limiter import Limiter

limiter = Limiter(app, key_func=lambda: request.remote_addr)

@app.route('/login', methods=['POST'])
@limiter.limit("5 per minute")
def login():
    # login logic
'''
            },
            'prevention_checklist': [
                '☐ Implementar MFA',
                '☐ Usar hashing forte',
                '☐ Implementar rate limiting',
                '☐ Configurar session timeout',
                '☐ Lockout após falhas',
                '☐ Auditar tentativas de login'
            ],
            'testing_tools': ['Burp Suite', 'Hydra', 'Manual Testing'],
            'references': [
                'OWASP Authentication Cheat Sheet',
                'Password Storage Guidelines',
                'Multi-Factor Authentication Guide'
            ]
        }
    }
    
    def __init__(self):
        self.custom_recommendations = {}
    
    def get_remediation_guide(self, vuln_type: str) -> Dict:
        """
        Retorna guia de remediação para tipo de vulnerabilidade.
        
        Args:
            vuln_type: Tipo da vulnerabilidade
            
        Returns:
            Guia completo de remediação
        """
        return self.REMEDIATION_GUIDES.get(
            vuln_type,
            {
                'title': vuln_type,
                'priority': 'MEDIUM',
                'quick_fix': 'Validar e sanitizar inputs do usuário',
                'detailed_steps': [
                    'Analisar o código vulnerável',
                    'Identificar vetor de ataque',
                    'Implementar validação apropriada',
                    'Testar a correção'
                ],
                'prevention_checklist': [
                    '☐ Revisar código',
                    '☐ Implementar validação',
                    '☐ Testar correção'
                ],
                'testing_tools': ['Burp Suite', 'Manual Testing'],
                'references': ['OWASP Testing Guide']
            }
        )
    
    def prioritize_vulnerabilities(self, vulnerabilities: List[Dict]) -> List[Dict]:
        """
        Prioriza vulnerabilidades para remediação.
        
        Args:
            vulnerabilities: Lista de vulnerabilidades com scores
            
        Returns:
            Lista priorizada de vulnerabilidades
        """
        # Critérios de priorização:
        # 1. Risk score (peso 40%)
        # 2. Facilidade de exploração (peso 30%)
        # 3. Impacto (peso 30%)
        
        def priority_score(vuln):
            risk = vuln.get('risk_score', 0)
            metrics = vuln.get('metrics', {})
            exploit = metrics.get('exploitability', 1.0)
            impact = metrics.get('impact_score', 5.0)
            
            # Calcula score de priorização
            return (risk * 0.4) + (exploit * 10 * 0.3) + (impact * 0.3)
        
        # Ordena por prioridade
        prioritized = sorted(
            vulnerabilities,
            key=priority_score,
            reverse=True
        )
        
        # Adiciona rank
        for i, vuln in enumerate(prioritized, 1):
            vuln['remediation_priority'] = i
            vuln['priority_score'] = round(priority_score(vuln), 2)
        
        return prioritized
    
    def generate_remediation_plan(self, vulnerabilities: List[Dict]) -> Dict:
        """
        Gera plano completo de remediação.
        
        Args:
            vulnerabilities: Lista de vulnerabilidades
            
        Returns:
            Plano de remediação estruturado
        """
        prioritized = self.prioritize_vulnerabilities(vulnerabilities)
        
        # Agrupa por severidade
        by_severity = {
            'Critical': [],
            'High': [],
            'Medium': [],
            'Low': []
        }
        
        for vuln in prioritized:
            severity = vuln.get('severity', 'Medium')
            by_severity[severity].append(vuln)
        
        # Gera timeline estimado
        timeline = self._estimate_remediation_timeline(by_severity)
        
        # Gera recomendações por fase
        phases = self._create_remediation_phases(by_severity)
        
        return {
            'total_vulnerabilities': len(vulnerabilities),
            'prioritized_list': prioritized[:10],  # Top 10
            'by_severity': {k: len(v) for k, v in by_severity.items()},
            'estimated_timeline': timeline,
            'remediation_phases': phases,
            'quick_wins': self._identify_quick_wins(prioritized),
            'long_term_improvements': self._identify_long_term_improvements(prioritized)
        }
    
    def _estimate_remediation_timeline(self, by_severity: Dict) -> Dict:
        """Estima timeline de remediação."""
        # Estimativas em horas
        time_estimates = {
            'Critical': 2,   # 2h cada
            'High': 4,       # 4h cada
            'Medium': 2,     # 2h cada
            'Low': 1         # 1h cada
        }
        
        total_hours = 0
        breakdown = {}
        
        for severity, vulns in by_severity.items():
            hours = len(vulns) * time_estimates.get(severity, 2)
            total_hours += hours
            breakdown[severity] = f"{hours}h ({len(vulns)} vulns)"
        
        return {
            'total_hours': total_hours,
            'total_days': round(total_hours / 8, 1),
            'breakdown': breakdown,
            'recommendation': self._get_timeline_recommendation(total_hours)
        }
    
    def _get_timeline_recommendation(self, hours: int) -> str:
        """Recomendação baseada no tempo estimado."""
        if hours <= 8:
            return "Pode ser concluído em 1 dia de trabalho"
        elif hours <= 40:
            return f"Aproximadamente 1 semana de trabalho ({round(hours/8, 1)} dias)"
        else:
            weeks = round(hours / 40, 1)
            return f"Projeto de {weeks} semanas - considere priorizar vulnerabilidades críticas"
    
    def _create_remediation_phases(self, by_severity: Dict) -> List[Dict]:
        """Cria fases de remediação."""
        phases = []
        
        # Fase 1: Critical (imediato)
        if by_severity['Critical']:
            phases.append({
                'phase': 1,
                'name': 'Remediação Imediata',
                'priority': 'CRITICAL',
                'timeframe': '24-48 horas',
                'vulnerabilities': len(by_severity['Critical']),
                'focus': 'Vulnerabilidades críticas que podem levar a comprometimento total'
            })
        
        # Fase 2: High (curto prazo)
        if by_severity['High']:
            phases.append({
                'phase': 2,
                'name': 'Remediação de Curto Prazo',
                'priority': 'HIGH',
                'timeframe': '1 semana',
                'vulnerabilities': len(by_severity['High']),
                'focus': 'Vulnerabilidades de alto impacto'
            })
        
        # Fase 3: Medium/Low (médio prazo)
        if by_severity['Medium'] or by_severity['Low']:
            phases.append({
                'phase': 3,
                'name': 'Melhorias Contínuas',
                'priority': 'MEDIUM',
                'timeframe': '2-4 semanas',
                'vulnerabilities': len(by_severity['Medium']) + len(by_severity['Low']),
                'focus': 'Hardening geral e melhorias de segurança'
            })
        
        return phases
    
    def _identify_quick_wins(self, vulnerabilities: List[Dict]) -> List[Dict]:
        """Identifica correções rápidas."""
        quick_wins = []
        
        for vuln in vulnerabilities[:5]:
            vuln_type = vuln.get('type', '')
            guide = self.get_remediation_guide(vuln_type)
            
            quick_wins.append({
                'vulnerability': vuln_type,
                'location': vuln.get('url', ''),
                'quick_fix': guide.get('quick_fix', ''),
                'estimated_time': '1-2 horas'
            })
        
        return quick_wins
    
    def _identify_long_term_improvements(self, vulnerabilities: List[Dict]) -> List[str]:
        """Identifica melhorias de longo prazo."""
        improvements = set()
        
        vuln_types = [v.get('type', '') for v in vulnerabilities]
        
        if 'XSS' in vuln_types:
            improvements.add('Implementar Content Security Policy (CSP) global')
        
        if 'SQL Injection' in vuln_types:
            improvements.add('Migrar para ORM em toda aplicação')
        
        if 'CSRF' in vuln_types:
            improvements.add('Implementar proteção CSRF automática framework-wide')
        
        if 'Authentication Failure' in vuln_types:
            improvements.add('Implementar autenticação multi-fator (MFA)')
        
        improvements.add('Implementar programa de Security Code Review')
        improvements.add('Estabelecer pipeline de segurança em CI/CD')
        improvements.add('Realizar testes de penetração periódicos')
        
        return list(improvements)

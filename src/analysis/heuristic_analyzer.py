"""
Analisador heurístico de vulnerabilidades.
Fornece análise contextual e identificação de padrões de ataque.
"""

import re
from typing import Dict, List, Set
from urllib.parse import urlparse


class HeuristicAnalyzer:
    """
    Análise heurística de vulnerabilidades para detecção de padrões
    e correlação entre vulnerabilidades.
    """
    
    # Padrões de endpoints sensíveis
    SENSITIVE_ENDPOINTS = [
        r'/admin',
        r'/login',
        r'/auth',
        r'/payment',
        r'/checkout',
        r'/user',
        r'/profile',
        r'/settings',
        r'/api',
        r'/dashboard'
    ]
    
    # Padrões de dados sensíveis
    SENSITIVE_DATA_PATTERNS = {
        'credit_card': r'\b\d{4}[-\s]?\d{4}[-\s]?\d{4}[-\s]?\d{4}\b',
        'ssn': r'\b\d{3}-\d{2}-\d{4}\b',
        'email': r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b',
        'password': r'password["\']?\s*[:=]\s*["\'][^"\']+["\']',
        'api_key': r'api[_-]?key["\']?\s*[:=]\s*["\'][^"\']+["\']',
        'token': r'token["\']?\s*[:=]\s*["\'][^"\']+["\']'
    }
    
    # Chains de ataque comuns
    ATTACK_CHAINS = {
        'XSS + Session Hijacking': ['XSS', 'Session'],
        'SQLi + Data Exfiltration': ['SQL Injection', 'Sensitive Data'],
        'Auth Bypass + Privilege Escalation': ['Authentication', 'Access Control'],
        'CSRF + State Changing': ['CSRF', 'POST', 'PUT', 'DELETE']
    }
    
    def __init__(self):
        self.analyzed_urls = set()
        self.patterns_found = {}
    
    def is_sensitive_endpoint(self, url: str) -> bool:
        """
        Verifica se a URL é um endpoint sensível.
        
        Args:
            url: URL a ser verificada
            
        Returns:
            True se for endpoint sensível
        """
        url_lower = url.lower()
        return any(re.search(pattern, url_lower) for pattern in self.SENSITIVE_ENDPOINTS)
    
    def detect_sensitive_data(self, text: str) -> Dict[str, List[str]]:
        """
        Detecta dados sensíveis no texto.
        
        Args:
            text: Texto a ser analisado
            
        Returns:
            Dicionário com tipos de dados sensíveis encontrados
        """
        findings = {}
        
        for data_type, pattern in self.SENSITIVE_DATA_PATTERNS.items():
            matches = re.findall(pattern, text, re.IGNORECASE)
            if matches:
                findings[data_type] = matches
        
        return findings
    
    def analyze_attack_surface(self, vulnerabilities: List[Dict]) -> Dict:
        """
        Analisa a superfície de ataque baseada nas vulnerabilidades.
        
        Args:
            vulnerabilities: Lista de vulnerabilidades
            
        Returns:
            Análise da superfície de ataque
        """
        # Agrupa por URL
        urls_affected = {}
        for vuln in vulnerabilities:
            url = vuln.get('url', '')
            if url not in urls_affected:
                urls_affected[url] = []
            urls_affected[url].append(vuln)
        
        # Identifica URLs críticas (múltiplas vulnerabilidades)
        critical_urls = {
            url: vulns for url, vulns in urls_affected.items() 
            if len(vulns) > 1
        }
        
        # Identifica endpoints sensíveis vulneráveis
        sensitive_vulnerable = {
            url: vulns for url, vulns in urls_affected.items()
            if self.is_sensitive_endpoint(url)
        }
        
        return {
            'total_urls_affected': len(urls_affected),
            'urls_with_multiple_vulns': len(critical_urls),
            'sensitive_endpoints_vulnerable': len(sensitive_vulnerable),
            'critical_urls': list(critical_urls.keys()),
            'sensitive_urls': list(sensitive_vulnerable.keys()),
            'average_vulns_per_url': round(
                sum(len(v) for v in urls_affected.values()) / len(urls_affected), 2
            ) if urls_affected else 0
        }
    
    def detect_attack_chains(self, vulnerabilities: List[Dict]) -> List[Dict]:
        """
        Detecta possíveis chains de ataque.
        
        Args:
            vulnerabilities: Lista de vulnerabilidades
            
        Returns:
            Lista de chains de ataque detectadas
        """
        detected_chains = []
        vuln_types = set(v.get('type', '') for v in vulnerabilities)
        
        for chain_name, required_types in self.ATTACK_CHAINS.items():
            # Verifica se todos os tipos necessários estão presentes
            if all(any(req in vtype for vtype in vuln_types) for req in required_types):
                # Encontra vulnerabilidades relacionadas
                related_vulns = [
                    v for v in vulnerabilities
                    if any(req in v.get('type', '') for req in required_types)
                ]
                
                detected_chains.append({
                    'chain_name': chain_name,
                    'severity': 'High',
                    'components': required_types,
                    'vulnerabilities_involved': len(related_vulns),
                    'description': self._get_chain_description(chain_name)
                })
        
        return detected_chains
    
    def _get_chain_description(self, chain_name: str) -> str:
        """Retorna descrição da chain de ataque."""
        descriptions = {
            'XSS + Session Hijacking': 
                'XSS pode ser usado para roubar tokens de sessão, permitindo sequestro de conta.',
            'SQLi + Data Exfiltration':
                'SQL Injection pode ser explorado para extrair dados sensíveis do banco de dados.',
            'Auth Bypass + Privilege Escalation':
                'Bypass de autenticação combinado com falhas de controle de acesso pode levar à escalação de privilégios.',
            'CSRF + State Changing':
                'CSRF em operações que mudam estado pode permitir ações não autorizadas.'
        }
        return descriptions.get(chain_name, 'Chain de ataque detectada.')
    
    def identify_exploitation_path(self, vulnerabilities: List[Dict]) -> List[Dict]:
        """
        Identifica possíveis caminhos de exploração.
        
        Args:
            vulnerabilities: Lista de vulnerabilidades
            
        Returns:
            Lista de caminhos de exploração sugeridos
        """
        paths = []
        
        # Ordena por severidade
        sorted_vulns = sorted(
            vulnerabilities,
            key=lambda v: v.get('risk_score', 0),
            reverse=True
        )
        
        # Cria caminho de exploração para as mais críticas
        for i, vuln in enumerate(sorted_vulns[:5], 1):  # Top 5
            vuln_type = vuln.get('type', 'Unknown')
            url = vuln.get('url', '')
            score = vuln.get('risk_score', 0)
            
            path = {
                'step': i,
                'vulnerability': vuln_type,
                'target': url,
                'risk_score': score,
                'exploitation_steps': self._get_exploitation_steps(vuln_type),
                'required_tools': self._get_required_tools(vuln_type),
                'expected_impact': self._get_expected_impact(vuln_type)
            }
            
            paths.append(path)
        
        return paths
    
    def _get_exploitation_steps(self, vuln_type: str) -> List[str]:
        """Retorna passos de exploração por tipo."""
        steps_map = {
            'XSS': [
                '1. Identificar ponto de injeção',
                '2. Criar payload XSS',
                '3. Bypassar filtros se necessário',
                '4. Executar script malicioso',
                '5. Roubar cookies/sessões'
            ],
            'SQL Injection': [
                '1. Identificar parâmetro vulnerável',
                '2. Testar com payloads básicos',
                '3. Mapear estrutura do banco',
                '4. Extrair dados sensíveis',
                '5. Escalar privilégios se possível'
            ],
            'Command Injection': [
                '1. Identificar comando vulnerável',
                '2. Testar injeção básica',
                '3. Bypassar sanitização',
                '4. Executar comandos arbitrários',
                '5. Obter shell reverso'
            ],
            'Authentication Failure': [
                '1. Identificar mecanismo falho',
                '2. Testar bypass de autenticação',
                '3. Enumerar usuários',
                '4. Explorar credenciais fracas',
                '5. Acessar recursos protegidos'
            ]
        }
        return steps_map.get(vuln_type, ['Análise manual necessária'])
    
    def _get_required_tools(self, vuln_type: str) -> List[str]:
        """Retorna ferramentas necessárias por tipo."""
        tools_map = {
            'XSS': ['Burp Suite', 'Browser DevTools', 'XSS Hunter'],
            'SQL Injection': ['SQLMap', 'Burp Suite', 'Manual Testing'],
            'Command Injection': ['Netcat', 'Burp Suite', 'Reverse Shell Generator'],
            'Authentication Failure': ['Burp Suite', 'Hydra', 'Custom Scripts'],
            'Path Traversal': ['Burp Suite', 'Manual Testing'],
            'CSRF': ['Burp Suite', 'CSRF PoC Generator']
        }
        return tools_map.get(vuln_type, ['Burp Suite', 'Manual Testing'])
    
    def _get_expected_impact(self, vuln_type: str) -> str:
        """Retorna impacto esperado por tipo."""
        impact_map = {
            'XSS': 'Roubo de sessão, defacement, redirecionamento malicioso',
            'SQL Injection': 'Exfiltração de dados, modificação de dados, bypass de autenticação',
            'Command Injection': 'Execução remota de código, controle total do servidor',
            'Authentication Failure': 'Acesso não autorizado, escalação de privilégios',
            'Path Traversal': 'Leitura de arquivos sensíveis, exposição de código-fonte',
            'CSRF': 'Ações não autorizadas, modificação de dados do usuário',
            'Cryptographic Failure': 'Exposição de dados sensíveis, quebra de confidencialidade'
        }
        return impact_map.get(vuln_type, 'Impacto varia conforme contexto')
    
    def generate_heuristic_insights(self, vulnerabilities: List[Dict]) -> Dict:
        """
        Gera insights heurísticos completos.
        
        Args:
            vulnerabilities: Lista de vulnerabilidades com scores
            
        Returns:
            Análise heurística completa
        """
        return {
            'attack_surface': self.analyze_attack_surface(vulnerabilities),
            'attack_chains': self.detect_attack_chains(vulnerabilities),
            'exploitation_paths': self.identify_exploitation_path(vulnerabilities),
            'insights_count': len(self.detect_attack_chains(vulnerabilities)) + 
                            len(self.identify_exploitation_path(vulnerabilities))
        }
    
    def correlate_vulnerabilities(self, vulnerabilities: List[Dict]) -> Dict:
        """
        Correlaciona vulnerabilidades para identificar padrões.
        
        Args:
            vulnerabilities: Lista de vulnerabilidades
            
        Returns:
            Análise de correlação
        """
        # Agrupa por tipo
        by_type = {}
        for vuln in vulnerabilities:
            vtype = vuln.get('type', 'Unknown')
            if vtype not in by_type:
                by_type[vtype] = []
            by_type[vtype].append(vuln)
        
        # Agrupa por método HTTP
        by_method = {}
        for vuln in vulnerabilities:
            method = vuln.get('method', 'Unknown')
            if method not in by_method:
                by_method[method] = []
            by_method[method].append(vuln)
        
        # Identifica padrões
        patterns = []
        
        # Padrão: Mesmo tipo em múltiplos endpoints
        for vtype, vulns in by_type.items():
            if len(vulns) > 2:
                patterns.append({
                    'type': 'Repeated Vulnerability Type',
                    'vulnerability': vtype,
                    'occurrences': len(vulns),
                    'recommendation': f'Implementar validação global contra {vtype}'
                })
        
        # Padrão: Múltiplas vulnerabilidades em GET
        if 'GET' in by_method and len(by_method['GET']) > 3:
            patterns.append({
                'type': 'GET Parameter Vulnerabilities',
                'count': len(by_method['GET']),
                'recommendation': 'Revisar validação de parâmetros GET'
            })
        
        return {
            'vulnerability_types': len(by_type),
            'http_methods_affected': len(by_method),
            'patterns_detected': patterns,
            'correlation_summary': {
                'by_type': {k: len(v) for k, v in by_type.items()},
                'by_method': {k: len(v) for k, v in by_method.items()}
            }
        }

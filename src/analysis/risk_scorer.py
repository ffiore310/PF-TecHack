"""
Sistema de pontuação e classificação de risco de vulnerabilidades.
Baseado em CVSS (Common Vulnerability Scoring System) adaptado.
"""

from typing import Dict, List
from enum import Enum


class Severity(Enum):
    """Níveis de severidade"""
    CRITICAL = "Critical"
    HIGH = "High"
    MEDIUM = "Medium"
    LOW = "Low"
    INFO = "Info"


class RiskScorer:
    """
    Calcula scores de risco para vulnerabilidades encontradas.
    """
    
    # Pesos base por tipo de vulnerabilidade (0-10)
    BASE_SCORES = {
        'XSS': 7.0,
        'SQL Injection': 9.0,
        'Command Injection': 9.5,
        'Path Traversal': 7.5,
        'CSRF': 6.0,
        'XXE': 8.0,
        'SSRF': 8.5,
        'Authentication Failure': 8.0,
        'Cryptographic Failure': 7.0,
        'Security Misconfiguration': 5.0,
        'Sensitive Data Exposure': 7.5,
        'Broken Access Control': 8.5,
        'Default': 5.0
    }
    
    # Multiplicadores por contexto
    CONTEXT_MULTIPLIERS = {
        'authentication': 1.3,      # Afeta autenticação
        'payment': 1.5,             # Afeta pagamentos
        'admin': 1.4,               # Área administrativa
        'user_data': 1.2,           # Dados de usuário
        'public': 0.9,              # Área pública
        'api': 1.1                  # Endpoint de API
    }
    
    # Multiplicadores por facilidade de exploração
    EXPLOITABILITY_MULTIPLIERS = {
        'trivial': 1.3,      # Muito fácil de explorar
        'easy': 1.2,         # Fácil de explorar
        'moderate': 1.0,     # Moderado
        'difficult': 0.8,    # Difícil
        'very_difficult': 0.6  # Muito difícil
    }
    
    def __init__(self):
        self.vulnerability_scores = {}
    
    def calculate_base_score(self, vuln_type: str) -> float:
        """
        Calcula o score base da vulnerabilidade.
        
        Args:
            vuln_type: Tipo da vulnerabilidade
            
        Returns:
            Score base (0-10)
        """
        return self.BASE_SCORES.get(vuln_type, self.BASE_SCORES['Default'])
    
    def calculate_context_score(self, url: str, evidence: str = "") -> float:
        """
        Calcula multiplicador baseado no contexto da vulnerabilidade.
        
        Args:
            url: URL onde a vulnerabilidade foi encontrada
            evidence: Evidências adicionais
            
        Returns:
            Multiplicador de contexto
        """
        multiplier = 1.0
        url_lower = url.lower()
        evidence_lower = evidence.lower()
        
        # Verifica contextos na URL e evidências
        for context, mult in self.CONTEXT_MULTIPLIERS.items():
            if context in url_lower or context in evidence_lower:
                multiplier = max(multiplier, mult)
        
        return multiplier
    
    def calculate_exploitability(self, vuln: Dict) -> float:
        """
        Calcula a facilidade de exploração da vulnerabilidade.
        
        Args:
            vuln: Dicionário com dados da vulnerabilidade
            
        Returns:
            Multiplicador de exploitabilidade
        """
        vuln_type = vuln.get('type', '')
        method = vuln.get('method', 'GET')
        
        # XSS e SQLi são geralmente fáceis de explorar
        if vuln_type in ['XSS', 'SQL Injection']:
            if method == 'GET':
                return self.EXPLOITABILITY_MULTIPLIERS['easy']
            else:
                return self.EXPLOITABILITY_MULTIPLIERS['moderate']
        
        # Falhas de autenticação são triviais
        if 'Authentication' in vuln_type:
            return self.EXPLOITABILITY_MULTIPLIERS['trivial']
        
        # Padrão
        return self.EXPLOITABILITY_MULTIPLIERS['moderate']
    
    def calculate_impact_score(self, vuln: Dict) -> float:
        """
        Calcula o impacto potencial da vulnerabilidade.
        
        Args:
            vuln: Dicionário com dados da vulnerabilidade
            
        Returns:
            Score de impacto (0-10)
        """
        vuln_type = vuln.get('type', '')
        
        # Impactos específicos por tipo
        impact_scores = {
            'SQL Injection': 10.0,        # Máximo - pode comprometer todo o DB
            'Command Injection': 10.0,     # Máximo - execução de código
            'XSS': 6.5,                   # Médio-alto - roubo de sessão
            'Authentication Failure': 9.0, # Alto - bypass de autenticação
            'Cryptographic Failure': 8.0,  # Alto - exposição de dados
            'Broken Access Control': 8.5,  # Alto - acesso não autorizado
        }
        
        return impact_scores.get(vuln_type, 5.0)
    
    def calculate_overall_score(self, vuln: Dict) -> float:
        """
        Calcula o score geral da vulnerabilidade (CVSS adaptado).
        
        Fórmula: (Base Score * Context * Exploitability + Impact) / 2
        
        Args:
            vuln: Dicionário com dados da vulnerabilidade
            
        Returns:
            Score final (0-10)
        """
        vuln_type = vuln.get('type', 'Default')
        url = vuln.get('url', '')
        evidence = vuln.get('evidence', '')
        
        # Componentes do score
        base_score = self.calculate_base_score(vuln_type)
        context_mult = self.calculate_context_score(url, evidence)
        exploit_mult = self.calculate_exploitability(vuln)
        impact = self.calculate_impact_score(vuln)
        
        # Cálculo final (média ponderada)
        exploitability_score = base_score * context_mult * exploit_mult
        final_score = (exploitability_score + impact) / 2
        
        # Limita entre 0 e 10
        return min(max(final_score, 0.0), 10.0)
    
    def get_severity_from_score(self, score: float) -> Severity:
        """
        Converte score numérico em nível de severidade.
        
        Args:
            score: Score da vulnerabilidade (0-10)
            
        Returns:
            Nível de severidade
        """
        if score >= 9.0:
            return Severity.CRITICAL
        elif score >= 7.0:
            return Severity.HIGH
        elif score >= 4.0:
            return Severity.MEDIUM
        elif score >= 0.1:
            return Severity.LOW
        else:
            return Severity.INFO
    
    def score_vulnerability(self, vuln: Dict) -> Dict:
        """
        Adiciona informações de score e severidade à vulnerabilidade.
        
        Args:
            vuln: Dicionário com dados da vulnerabilidade
            
        Returns:
            Vulnerabilidade enriquecida com score e severidade
        """
        score = self.calculate_overall_score(vuln)
        severity = self.get_severity_from_score(score)
        
        # Enriquece a vulnerabilidade
        enriched_vuln = vuln.copy()
        enriched_vuln['risk_score'] = round(score, 2)
        enriched_vuln['severity'] = severity.value
        enriched_vuln['severity_level'] = severity.name
        
        # Adiciona métricas detalhadas
        enriched_vuln['metrics'] = {
            'base_score': round(self.calculate_base_score(vuln.get('type', '')), 2),
            'impact_score': round(self.calculate_impact_score(vuln), 2),
            'exploitability': round(self.calculate_exploitability(vuln), 2),
            'context_multiplier': round(self.calculate_context_score(
                vuln.get('url', ''), 
                vuln.get('evidence', '')
            ), 2)
        }
        
        return enriched_vuln
    
    def score_vulnerabilities(self, vulnerabilities: List[Dict]) -> List[Dict]:
        """
        Calcula scores para uma lista de vulnerabilidades.
        
        Args:
            vulnerabilities: Lista de vulnerabilidades
            
        Returns:
            Lista de vulnerabilidades com scores
        """
        return [self.score_vulnerability(vuln) for vuln in vulnerabilities]
    
    def get_risk_summary(self, vulnerabilities: List[Dict]) -> Dict:
        """
        Gera resumo de risco do conjunto de vulnerabilidades.
        
        Args:
            vulnerabilities: Lista de vulnerabilidades com scores
            
        Returns:
            Resumo com estatísticas de risco
        """
        if not vulnerabilities:
            return {
                'total_vulnerabilities': 0,
                'average_score': 0.0,
                'max_score': 0.0,
                'severity_distribution': {},
                'overall_risk_level': 'LOW'
            }
        
        scores = [v.get('risk_score', 0) for v in vulnerabilities]
        severities = [v.get('severity', 'Low') for v in vulnerabilities]
        
        # Distribuição por severidade
        severity_dist = {}
        for sev in severities:
            severity_dist[sev] = severity_dist.get(sev, 0) + 1
        
        avg_score = sum(scores) / len(scores)
        
        # Nível de risco geral baseado na média e máximo
        max_score = max(scores)
        if max_score >= 9.0 or avg_score >= 7.0:
            overall_risk = 'CRITICAL'
        elif max_score >= 7.0 or avg_score >= 5.0:
            overall_risk = 'HIGH'
        elif avg_score >= 3.0:
            overall_risk = 'MEDIUM'
        else:
            overall_risk = 'LOW'
        
        return {
            'total_vulnerabilities': len(vulnerabilities),
            'average_score': round(avg_score, 2),
            'max_score': round(max_score, 2),
            'min_score': round(min(scores), 2),
            'severity_distribution': severity_dist,
            'overall_risk_level': overall_risk,
            'critical_count': severity_dist.get('Critical', 0),
            'high_count': severity_dist.get('High', 0),
            'medium_count': severity_dist.get('Medium', 0),
            'low_count': severity_dist.get('Low', 0)
        }

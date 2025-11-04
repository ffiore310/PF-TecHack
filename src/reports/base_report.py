"""
Classe base para todos os formatos de relatório.
"""

from abc import ABC, abstractmethod
from typing import Dict, Any
from datetime import datetime

class BaseReport(ABC):
    def __init__(self, scan_results: Dict[str, Any]):
        """
        Inicializa o relatório base.
        
        Args:
            scan_results: Resultados do scan em formato dict
        """
        self.scan_results = scan_results
        self.timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        self.target_url = scan_results.get('url')
        self.vulnerabilities = scan_results.get('vulnerabilities', [])
        self.scan_time = scan_results.get('scan_time')
        self.scan_types = scan_results.get('scan_types', [])
        self.performance = scan_results.get('performance', {})

    def get_summary(self) -> Dict[str, int]:
        """
        Gera um resumo com a contagem de vulnerabilidades por tipo.
        
        Returns:
            Dict com contagem de vulnerabilidades por tipo
        """
        summary = {}
        for vuln in self.vulnerabilities:
            vuln_type = vuln.get('type', 'unknown')
            summary[vuln_type] = summary.get(vuln_type, 0) + 1
        return summary
    
    def get_severity_counts(self) -> Dict[str, int]:
        """
        Conta vulnerabilidades por nível de severidade.
        
        Returns:
            Dict com contagem por severidade
        """
        counts = {
            'Critical': 0,
            'High': 0,
            'Medium': 0,
            'Low': 0
        }
        for vuln in self.vulnerabilities:
            severity = vuln.get('severity', 'Low')
            counts[severity] = counts.get(severity, 0) + 1
        return counts

    @abstractmethod
    def generate(self) -> str:
        """
        Gera o relatório no formato específico.
        Deve ser implementado pelas classes filhas.
        
        Returns:
            String com o relatório formatado
        """
        pass

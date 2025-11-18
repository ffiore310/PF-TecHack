"""
Gerador de relatórios em formato JSON.
"""

import json
from typing import Dict, Any
from .base_report import BaseReport

class JsonReport(BaseReport):
    def generate(self) -> str:
        """
        Gera o relatório em formato JSON.
        
        Returns:
            String com o relatório em JSON
        """
        report_dict = {
            'scan_info': {
                'timestamp': self.timestamp,
                'target_url': self.target_url,
                'scan_time': self.scan_time,
                'scan_types': list(self.scan_types)
            },
            'summary': {
                'by_type': self.get_summary(),
                'by_severity': self.get_severity_counts()
            },
            'vulnerabilities': self.vulnerabilities,
            'performance': {
                'total_time': self.scan_time,
                'module_stats': self.performance.get('modules_performance', {})
            }
        }
        
        # Adiciona análise avançada (FASE 1) se disponível
        if hasattr(self, 'risk_summary') and self.risk_summary:
            report_dict['risk_analysis'] = {
                'risk_summary': self.risk_summary,
                'heuristic_insights': getattr(self, 'heuristic_insights', {}),
                'correlation_analysis': getattr(self, 'correlation_analysis', {}),
                'remediation_plan': getattr(self, 'remediation_plan', {})
            }
        
        return json.dumps(report_dict, indent=2)

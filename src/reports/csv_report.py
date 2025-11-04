"""
Gerador de relatórios em formato CSV.
"""

import csv
import io
from typing import Dict, Any
from .base_report import BaseReport

class CsvReport(BaseReport):
    def generate(self) -> str:
        """
        Gera o relatório em formato CSV.
        
        Returns:
            String com o relatório em CSV
        """
        output = io.StringIO()
        writer = csv.writer(output)
        
        # Cabeçalho do relatório
        writer.writerow(['Scan Report'])
        writer.writerow(['Target URL', self.target_url])
        writer.writerow(['Timestamp', self.timestamp])
        writer.writerow(['Scan Duration', f"{self.scan_time:.2f}s"])
        writer.writerow([])
        
        # Resumo por tipo
        writer.writerow(['Vulnerability Summary'])
        writer.writerow(['Type', 'Count'])
        for vuln_type, count in self.get_summary().items():
            writer.writerow([vuln_type, count])
        writer.writerow([])
        
        # Resumo por severidade
        writer.writerow(['Severity Summary'])
        writer.writerow(['Severity', 'Count'])
        for severity, count in self.get_severity_counts().items():
            writer.writerow([severity, count])
        writer.writerow([])
        
        # Detalhes das vulnerabilidades
        writer.writerow(['Detailed Findings'])
        writer.writerow(['Type', 'Subtype', 'Severity', 'Description', 'Evidence', 'Recommendation'])
        
        for vuln in self.vulnerabilities:
            writer.writerow([
                vuln.get('type', ''),
                vuln.get('subtype', ''),
                vuln.get('severity', ''),
                vuln.get('description', ''),
                vuln.get('evidence', ''),
                vuln.get('recommendation', '')
            ])
        writer.writerow([])
        
        # Performance
        writer.writerow(['Performance Metrics'])
        writer.writerow(['Module', 'Time (s)', 'Percentage'])
        for module, stats in self.performance.get('modules_performance', {}).items():
            writer.writerow([
                module,
                f"{stats.get('duration', 0):.2f}",
                f"{stats.get('percentage', 0):.1f}%"
            ])
        
        return output.getvalue()

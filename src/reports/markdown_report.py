"""
Gerador de relatórios em formato Markdown.
"""

from typing import Dict, Any
from .base_report import BaseReport

class MarkdownReport(BaseReport):
    def generate(self) -> str:
        """
        Gera o relatório em formato Markdown.
        
        Returns:
            String com o relatório em Markdown
        """
        md_lines = [
            "# Relatório de Scan de Segurança",
            "",
            "## Informações do Scan",
            f"- **URL Alvo:** {self.target_url}",
            f"- **Data/Hora:** {self.timestamp}",
            f"- **Duração:** {self.scan_time:.2f} segundos",
            f"- **Tipos de Scan:** {', '.join(self.scan_types)}",
            "",
            "## Resumo de Vulnerabilidades",
            ""
        ]
        
        # Adiciona resumo por tipo
        summary = self.get_summary()
        for vuln_type, count in summary.items():
            md_lines.append(f"- **{vuln_type}:** {count} vulnerabilidade(s)")
        
        # Adiciona resumo por severidade
        md_lines.extend([
            "",
            "### Por Severidade",
            ""
        ])
        severity_counts = self.get_severity_counts()
        for severity, count in severity_counts.items():
            if count > 0:
                md_lines.append(f"- **{severity}:** {count}")
        
        # Adiciona vulnerabilidades detalhadas
        md_lines.extend([
            "",
            "## Vulnerabilidades Encontradas",
            ""
        ])
        
        # Ordena por severidade
        severity_order = {'Critical': 0, 'High': 1, 'Medium': 2, 'Low': 3}
        sorted_vulns = sorted(
            self.vulnerabilities,
            key=lambda x: severity_order.get(x.get('severity', 'Low'), 99)
        )
        
        for vuln in sorted_vulns:
            md_lines.extend([
                f"### {vuln.get('type')} ({vuln.get('severity')})",
                f"- **Subtipo:** {vuln.get('subtype', 'N/A')}",
                f"- **Descrição:** {vuln.get('description', 'N/A')}",
                "",
                "**Evidência:**",
                "```",
                vuln.get('evidence', 'N/A'),
                "```",
                "",
                "**Recomendação:**",
                vuln.get('recommendation', 'N/A'),
                ""
            ])
        
        # Adiciona métricas de performance
        md_lines.extend([
            "## Métricas de Performance",
            ""
        ])
        
        for module, stats in self.performance.get('modules_performance', {}).items():
            md_lines.append(
                f"- **{module}:** {stats.get('duration', 0):.2f}s "
                f"({stats.get('percentage', 0):.1f}% do tempo total)"
            )
        
        return "\n".join(md_lines)

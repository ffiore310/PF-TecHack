"""
Classes base para diferentes formatos de relatório.
"""

from abc import ABC, abstractmethod
from typing import Dict, Any, List
import json
import csv
import markdown
import datetime
from pathlib import Path

class BaseReportFormatter(ABC):
    """Classe base para formatadores de relatório."""
    
    @abstractmethod
    def format(self, scan_results: Dict[str, Any]) -> str:
        """
        Formata os resultados do scan.
        
        Args:
            scan_results: Dicionário com resultados do scan
            
        Returns:
            String formatada com o relatório
        """
        pass
        
    def _get_timestamp(self) -> str:
        """Retorna timestamp formatado."""
        return datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        
    def _format_duration(self, seconds: float) -> str:
        """Formata duração em segundos."""
        return f"{seconds:.2f} segundos"
        
    def _get_severity_order(self) -> Dict[str, int]:
        """Retorna ordem de severidade para ordenação."""
        return {
            'Critical': 0,
            'High': 1,
            'Medium': 2,
            'Low': 3,
            'Info': 4
        }
        
class TextReportFormatter(BaseReportFormatter):
    """Formatador para relatórios em texto plano."""
    
    def format(self, scan_results: Dict[str, Any]) -> str:
        lines = [
            "=====================================",
            "RELATÓRIO DE SCAN DE VULNERABILIDADES",
            "=====================================",
            "",
            f"Data/Hora: {self._get_timestamp()}",
            f"URL Analisada: {scan_results['url']}",
            f"Tempo de Scan: {self._format_duration(scan_results['scan_time'])}",
            "Parâmetros do Scan:",
            f"- Tipos de Scan: {scan_results['scan_types']}",
            f"- Modo: {scan_results['scan_mode']}",
            "",
            "RESUMO",
            "------"
        ]
        
        # Agrupa vulnerabilidades por tipo
        vuln_types = {}
        for vuln in scan_results['vulnerabilities']:
            if vuln['type'] not in vuln_types:
                vuln_types[vuln['type']] = []
            vuln_types[vuln['type']].append(vuln)
            
        for vuln_type, vulns in vuln_types.items():
            lines.extend([
                f"- {vuln_type}: {len(vulns)} vulnerabilidade(s) encontrada(s)",
                f"  Descrição: {vuln['description']}",
                ""
            ])
            
        # Detalhes por severidade
        lines.extend([
            "",
            "DETALHES DAS VULNERABILIDADES",
            "============================="
        ])
        
        # Ordena por severidade
        severity_order = self._get_severity_order()
        sorted_vulns = sorted(
            scan_results['vulnerabilities'],
            key=lambda x: (severity_order.get(x['severity'], 99), x['type'])
        )
        
        current_type = None
        current_severity = None
        
        for vuln in sorted_vulns:
            if (vuln['type'], vuln['severity']) != (current_type, current_severity):
                current_type = vuln['type']
                current_severity = vuln['severity']
                lines.extend([
                    "",
                    f"{current_type} - Severidade {current_severity}",
                    "=" * (len(current_type) + len(current_severity) + 13)
                ])
                
            lines.extend([
                "",
                "Descrição:",
                f"  {vuln['description']}",
                "",
                "Evidências:",
                f"  {vuln.get('evidence', 'N/A')}",
                "",
                "Recomendação:",
                f"  {vuln.get('recommendation', 'N/A')}",
                ""
            ])
            
        # Adiciona estatísticas de performance
        if 'performance' in scan_results:
            lines.extend([
                "",
                "ESTATÍSTICAS DE PERFORMANCE",
                "=========================",
                f"Tempo total de scan: {self._format_duration(scan_results['scan_time'])}",
                ""
            ])
            
            if 'modules_performance' in scan_results['performance']:
                lines.append("Performance por módulo:")
                for module, stats in scan_results['performance']['modules_performance'].items():
                    lines.append(
                        f"- {module}: {stats['duration']:.2f}s "
                        f"({stats['percentage']:.1f}% do tempo total)"
                    )
                    
        return "\n".join(lines)
        
class JsonReportFormatter(BaseReportFormatter):
    """Formatador para relatórios em JSON."""
    
    def format(self, scan_results: Dict[str, Any]) -> str:
        report_data = {
            'metadata': {
                'timestamp': self._get_timestamp(),
                'url': scan_results['url'],
                'scan_time': scan_results['scan_time'],
                'scan_types': list(scan_results['scan_types']),
                'scan_mode': scan_results['scan_mode']
            },
            'summary': {
                'total_vulnerabilities': len(scan_results['vulnerabilities']),
                'vulnerabilities_by_type': {},
                'vulnerabilities_by_severity': {}
            },
            'vulnerabilities': scan_results['vulnerabilities'],
            'performance': scan_results.get('performance', {})
        }
        
        # Conta vulnerabilidades por tipo e severidade
        for vuln in scan_results['vulnerabilities']:
            # Por tipo
            vuln_type = vuln['type']
            if vuln_type not in report_data['summary']['vulnerabilities_by_type']:
                report_data['summary']['vulnerabilities_by_type'][vuln_type] = 0
            report_data['summary']['vulnerabilities_by_type'][vuln_type] += 1
            
            # Por severidade
            severity = vuln['severity']
            if severity not in report_data['summary']['vulnerabilities_by_severity']:
                report_data['summary']['vulnerabilities_by_severity'][severity] = 0
            report_data['summary']['vulnerabilities_by_severity'][severity] += 1
            
        return json.dumps(report_data, indent=2)
        
class CsvReportFormatter(BaseReportFormatter):
    """Formatador para relatórios em CSV."""
    
    def format(self, scan_results: Dict[str, Any]) -> str:
        output = []
        fieldnames = [
            'type', 'subtype', 'severity', 'description',
            'evidence', 'recommendation'
        ]
        
        # Usa StringIO para simular arquivo
        from io import StringIO
        output_file = StringIO()
        writer = csv.DictWriter(output_file, fieldnames=fieldnames)
        writer.writeheader()
        
        for vuln in scan_results['vulnerabilities']:
            row = {
                field: str(vuln.get(field, '')) for field in fieldnames
            }
            writer.writerow(row)
            
        return output_file.getvalue()
        
class MarkdownReportFormatter(BaseReportFormatter):
    """Formatador para relatórios em Markdown."""
    
    def format(self, scan_results: Dict[str, Any]) -> str:
        lines = [
            "# Relatório de Scan de Vulnerabilidades",
            "",
            "## Informações Gerais",
            "",
            f"- **Data/Hora**: {self._get_timestamp()}",
            f"- **URL Analisada**: {scan_results['url']}",
            f"- **Tempo de Scan**: {self._format_duration(scan_results['scan_time'])}",
            f"- **Tipos de Scan**: {', '.join(scan_results['scan_types'])}",
            f"- **Modo**: {scan_results['scan_mode']}",
            "",
            "## Resumo",
            ""
        ]
        
        # Agrupa vulnerabilidades por tipo
        vuln_types = {}
        for vuln in scan_results['vulnerabilities']:
            if vuln['type'] not in vuln_types:
                vuln_types[vuln['type']] = []
            vuln_types[vuln['type']].append(vuln)
            
        for vuln_type, vulns in vuln_types.items():
            lines.extend([
                f"### {vuln_type}",
                f"- **Total**: {len(vulns)} vulnerabilidade(s)",
                f"- **Descrição**: {vulns[0]['description']}",
                ""
            ])
            
        # Detalhes das vulnerabilidades
        lines.extend([
            "## Detalhes das Vulnerabilidades",
            ""
        ])
        
        # Ordena por severidade
        severity_order = self._get_severity_order()
        sorted_vulns = sorted(
            scan_results['vulnerabilities'],
            key=lambda x: (severity_order.get(x['severity'], 99), x['type'])
        )
        
        current_type = None
        current_severity = None
        
        for vuln in sorted_vulns:
            if (vuln['type'], vuln['severity']) != (current_type, current_severity):
                current_type = vuln['type']
                current_severity = vuln['severity']
                lines.extend([
                    f"### {current_type} - Severidade {current_severity}",
                    ""
                ])
                
            lines.extend([
                "#### Detalhes",
                f"- **Descrição**: {vuln['description']}",
                f"- **Evidências**: {vuln.get('evidence', 'N/A')}",
                f"- **Recomendação**: {vuln.get('recommendation', 'N/A')}",
                ""
            ])
            
        # Performance
        if 'performance' in scan_results:
            lines.extend([
                "## Estatísticas de Performance",
                "",
                f"**Tempo Total**: {self._format_duration(scan_results['scan_time'])}",
                ""
            ])
            
            if 'modules_performance' in scan_results['performance']:
                lines.append("### Performance por Módulo")
                for module, stats in scan_results['performance']['modules_performance'].items():
                    lines.append(
                        f"- **{module}**: {stats['duration']:.2f}s "
                        f"({stats['percentage']:.1f}% do tempo total)"
                    )
                    
        return "\n".join(lines)

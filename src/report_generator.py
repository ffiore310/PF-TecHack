#!/usr/bin/env python3

"""
Módulo para geração de relatórios de vulnerabilidades.
"""

import datetime
from typing import Dict, List

class ReportGenerator:
    def __init__(self):
        self.vulnerability_descriptions = {
            'XSS': 'Cross-Site Scripting (XSS) permite que atacantes injetem scripts maliciosos em páginas web',
            'SQL Injection': 'SQL Injection permite que atacantes manipulem queries SQL através de inputs não sanitizados'
        }
    
    def _get_vulnerability_count(self, vulnerabilities: List[Dict]) -> Dict[str, int]:
        """
        Conta o número de vulnerabilidades por tipo.
        
        Args:
            vulnerabilities: Lista de vulnerabilidades encontradas
            
        Returns:
            Dict com contagem de vulnerabilidades por tipo
        """
        counts = {}
        for vuln in vulnerabilities:
            vuln_type = vuln['type']
            counts[vuln_type] = counts.get(vuln_type, 0) + 1
        return counts
    
    def _format_vulnerability(self, vuln: Dict) -> str:
        """
        Formata uma única vulnerabilidade para o relatório.
        
        Args:
            vuln: Dicionário com dados da vulnerabilidade
            
        Returns:
            String formatada com detalhes da vulnerabilidade
        """
        output = [
            f"Tipo: {vuln['type']}",
            f"Método: {vuln['method']}",
            f"Parâmetro: {vuln['param']}",
            f"Payload: {vuln['payload']}",
            f"Severidade: {vuln['severity']}"
        ]
        
        if 'pattern_matched' in vuln:
            output.append(f"Padrão encontrado: {vuln['pattern_matched']}")
            
        return "\n".join(output)
    
    def generate(self, results: Dict, output_file: str):
        """
        Gera um relatório baseado nos resultados do scan.
        
        Args:
            results: Dicionário com resultados do scan
            output_file: Caminho do arquivo de saída
        """
        # Data e hora do relatório
        timestamp = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        
        # Contagem de vulnerabilidades
        vuln_counts = self._get_vulnerability_count(results['vulnerabilities'])
        
        # Gera o relatório
        report_lines = [
            "=====================================",
            "RELATÓRIO DE SCAN DE VULNERABILIDADES",
            "=====================================",
            "",
            f"Data/Hora: {timestamp}",
            f"URL Analisada: {results['url']}",
            f"Tempo de Scan: {results['scan_time']:.2f} segundos",
            f"Parâmetros do Scan:",
            f"- Tipos de Scan: {results.get('scan_types', 'all')}",
            f"- Modo: {results.get('scan_mode', 'normal')}",
            "",
            "RESUMO",
            "------",
        ]
        
        # Adiciona resumo
        if not results['vulnerabilities']:
            report_lines.append("Nenhuma vulnerabilidade encontrada.")
        else:
            for vuln_type, count in vuln_counts.items():
                report_lines.extend([
                    f"- {vuln_type}: {count} vulnerabilidade(s) encontrada(s)",
                    f"  Descrição: {self.vulnerability_descriptions.get(vuln_type, 'Sem descrição disponível')}",
                    ""
                ])
        
        # Adiciona detalhes das vulnerabilidades
        if results['vulnerabilities']:
            report_lines.extend([
                "",
                "DETALHES DAS VULNERABILIDADES",
                "--------------------------"
            ])
            
            for i, vuln in enumerate(results['vulnerabilities'], 1):
                report_lines.extend([
                    f"\nVulnerabilidade #{i}:",
                    "-" * 20,
                    self._format_vulnerability(vuln),
                    ""
                ])
        
        # Adiciona recomendações básicas
        report_lines.extend([
            "",
            "RECOMENDAÇÕES GERAIS",
            "-------------------",
            "1. Sanitize todos os inputs do usuário",
            "2. Use prepared statements para consultas SQL",
            "3. Implemente validação tanto no cliente quanto no servidor",
            "4. Mantenha as bibliotecas e frameworks atualizados",
            "",
            "FIM DO RELATÓRIO"
        ])
        
        # Escreve o relatório no arquivo
        with open(output_file, 'w') as f:
            f.write("\n".join(report_lines))

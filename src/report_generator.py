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
            'SQL Injection': 'SQL Injection permite que atacantes manipulem queries SQL através de inputs não sanitizados',
            'Authentication Failure': 'Falhas de autenticação podem permitir acesso não autorizado a contas de usuário',
            'Cryptographic Failure': 'Falhas criptográficas podem comprometer a segurança das comunicações e dados'
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
            f"Subtipo: {vuln.get('subtype', 'N/A')}",
            f"Severidade: {vuln['severity']}",
            f"Descrição: {vuln['description']}"
        ]
        
        # Adiciona recomendação se existir
        if 'recommendation' in vuln:
            output.append(f"Recomendação: {vuln['recommendation']}")
            
        # Adiciona evidências se existirem
        if 'evidence' in vuln:
            output.append(f"Evidência: {vuln['evidence']}")
        
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
                "============================="
            ])
            
            # Agrupa vulnerabilidades por tipo e severidade
            vuln_groups = {}
            for vuln in results['vulnerabilities']:
                key = (vuln['type'], vuln['severity'])
                if key not in vuln_groups:
                    vuln_groups[key] = []
                vuln_groups[key].append(vuln)
            
            # Ordena grupos por severidade (Critical > High > Medium > Low)
            severity_order = {'Critical': 0, 'High': 1, 'Medium': 2, 'Low': 3}
            sorted_groups = sorted(
                vuln_groups.items(),
                key=lambda x: (severity_order.get(x[0][1], 99), x[0][0])
            )
            
            for (vuln_type, severity), vulns in sorted_groups:
                report_lines.extend([
                    f"\n{vuln_type} - Severidade {severity}",
                    "=" * (len(vuln_type) + len(severity) + 13)
                ])
                
                for i, vuln in enumerate(vulns, 1):
                    report_lines.extend([
                        f"\nInstância #{i}:",
                        "-" * 12
                    ])
                    report_lines.extend(self._format_vulnerability(vuln).split('\n'))
                    report_lines.append("")
        
        # Adiciona estatísticas de performance
        if 'performance' in results:
            report_lines.extend([
                "",
                "ESTATÍSTICAS DE PERFORMANCE",
                "=========================",
                f"Tempo total de scan: {results['scan_time']:.2f} segundos",
                ""
            ])
            
            if 'modules_performance' in results['performance']:
                report_lines.append("Performance por módulo:")
                for module, stats in results['performance']['modules_performance'].items():
                    report_lines.append(
                        f"- {module}: {stats['duration']:.2f}s "
                        f"({stats['percentage']:.1f}% do tempo total)"
                    )
        
        # Adiciona recomendações específicas por tipo de vulnerabilidade
        report_lines.extend([
            "",
            "RECOMENDAÇÕES DE SEGURANÇA",
            "========================="
        ])
        
        for vuln_type in set(v['type'] for v in results['vulnerabilities']):
            if vuln_type == 'Authentication Failure':
                report_lines.extend([
                    "\nPara Falhas de Autenticação:",
                    "- Implemente rate limiting para prevenir força bruta",
                    "- Use senhas fortes e política de senhas robusta",
                    "- Implemente autenticação de dois fatores (2FA)",
                    "- Use tokens de sessão seguros e cookies com flags apropriadas"
                ])
            elif vuln_type == 'Cryptographic Failure':
                report_lines.extend([
                    "\nPara Falhas Criptográficas:",
                    "- Use HTTPS em toda a aplicação",
                    "- Configure corretamente os certificados SSL/TLS",
                    "- Implemente HSTS e CSP",
                    "- Use algoritmos de criptografia fortes e atualizados"
                ])
            elif vuln_type == 'XSS':
                report_lines.extend([
                    "\nPara Cross-Site Scripting (XSS):",
                    "- Sanitize todos os inputs do usuário",
                    "- Use Content Security Policy (CSP)",
                    "- Escape output em contextos HTML, JavaScript, e URLs",
                    "- Valide e filtre todos os dados do usuário"
                ])
            elif vuln_type == 'SQL Injection':
                report_lines.extend([
                    "\nPara SQL Injection:",
                    "- Use prepared statements ou ORM",
                    "- Implemente o princípio do menor privilégio",
                    "- Sanitize e valide todos os inputs",
                    "- Evite concatenação direta de strings em queries"
                ])
        
        report_lines.extend([
            "",
            "FIM DO RELATÓRIO",
            "==============="
        ])
        
        # Escreve o relatório no arquivo
        with open(output_file, 'w') as f:
            f.write("\n".join(report_lines))

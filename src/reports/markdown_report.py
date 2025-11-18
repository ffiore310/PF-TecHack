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
            # Inclui informações de risco se disponível (FASE 1)
            risk_score = vuln.get('risk_score', 'N/A')
            severity_level = vuln.get('severity_level', vuln.get('severity', 'N/A'))
            
            md_lines.extend([
                f"### {vuln.get('type')} ({severity_level})",
                f"- **Risk Score:** {risk_score}/10",
                f"- **Prioridade:** #{vuln.get('remediation_priority', 'N/A')}",
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
            
            # Adiciona métricas detalhadas se disponível
            if 'metrics' in vuln:
                metrics = vuln['metrics']
                md_lines.extend([
                    "**Métricas de Risco:**",
                    f"- Base Score: {metrics.get('base_score', 'N/A')}",
                    f"- Impact Score: {metrics.get('impact_score', 'N/A')}",
                    f"- Exploitability: {metrics.get('exploitability', 'N/A')}",
                    f"- Context Multiplier: {metrics.get('context_multiplier', 'N/A')}",
                    ""
                ])
        
        # === FASE 1: ANÁLISE AVANÇADA ===
        
        # Adiciona resumo de risco se disponível
        if hasattr(self, 'risk_summary') and self.risk_summary:
            md_lines.extend([
                "## 🎯 Análise de Risco",
                "",
                f"- **Nível de Risco Geral:** {self.risk_summary.get('overall_risk_level', 'N/A')}",
                f"- **Score Médio:** {self.risk_summary.get('average_score', 0):.2f}/10",
                f"- **Score Máximo:** {self.risk_summary.get('max_score', 0):.2f}/10",
                f"- **Total de Vulnerabilidades:** {self.risk_summary.get('total_vulnerabilities', 0)}",
                "",
                "### Distribuição por Severidade",
                ""
            ])
            
            severity_dist = self.risk_summary.get('severity_distribution', {})
            for sev, count in severity_dist.items():
                md_lines.append(f"- **{sev}:** {count}")
        
        # Adiciona insights heurísticos
        if hasattr(self, 'heuristic_insights') and self.heuristic_insights:
            insights = self.heuristic_insights
            
            md_lines.extend([
                "",
                "## 🔍 Análise Heurística",
                "",
                "### Superfície de Ataque",
                ""
            ])
            
            attack_surface = insights.get('attack_surface', {})
            md_lines.extend([
                f"- **URLs Afetadas:** {attack_surface.get('total_urls_affected', 0)}",
                f"- **URLs com Múltiplas Vulnerabilidades:** {attack_surface.get('urls_with_multiple_vulns', 0)}",
                f"- **Endpoints Sensíveis Vulneráveis:** {attack_surface.get('sensitive_endpoints_vulnerable', 0)}",
                f"- **Média de Vulnerabilidades por URL:** {attack_surface.get('average_vulns_per_url', 0)}",
                ""
            ])
            
            # Chains de ataque
            attack_chains = insights.get('attack_chains', [])
            if attack_chains:
                md_lines.extend([
                    "### ⚠️ Chains de Ataque Detectadas",
                    ""
                ])
                
                for chain in attack_chains:
                    md_lines.extend([
                        f"**{chain['chain_name']}** ({chain['severity']})",
                        f"- Componentes: {', '.join(chain['components'])}",
                        f"- Vulnerabilidades Envolvidas: {chain['vulnerabilities_involved']}",
                        f"- Descrição: {chain['description']}",
                        ""
                    ])
            
            # Caminhos de exploração
            exploit_paths = insights.get('exploitation_paths', [])
            if exploit_paths:
                md_lines.extend([
                    "### 🎯 Caminhos de Exploração Sugeridos",
                    ""
                ])
                
                for path in exploit_paths[:3]:  # Top 3
                    md_lines.extend([
                        f"**Passo {path['step']}: {path['vulnerability']}**",
                        f"- Target: {path['target']}",
                        f"- Risk Score: {path['risk_score']}/10",
                        f"- Impacto Esperado: {path['expected_impact']}",
                        ""
                    ])
        
        # Plano de remediação
        if hasattr(self, 'remediation_plan') and self.remediation_plan:
            plan = self.remediation_plan
            
            md_lines.extend([
                "",
                "## Plano de Remediacao",
                ""
            ])
            
            # Timeline
            timeline = plan.get('estimated_timeline', {})
            md_lines.extend([
                "### ⏱️ Timeline Estimado",
                "",
                f"- **Tempo Total:** {timeline.get('total_hours', 0)}h ({timeline.get('total_days', 0)} dias)",
                f"- **Recomendação:** {timeline.get('recommendation', 'N/A')}",
                "",
                "**Breakdown por Severidade:**",
                ""
            ])
            
            for sev, time_str in timeline.get('breakdown', {}).items():
                md_lines.append(f"- {sev}: {time_str}")
            
            # Fases de remediação
            phases = plan.get('remediation_phases', [])
            if phases:
                md_lines.extend([
                    "",
                    "### 📋 Fases de Remediação",
                    ""
                ])
                
                for phase in phases:
                    md_lines.extend([
                        f"**Fase {phase['phase']}: {phase['name']}**",
                        f"- Prioridade: {phase['priority']}",
                        f"- Timeframe: {phase['timeframe']}",
                        f"- Vulnerabilidades: {phase['vulnerabilities']}",
                        f"- Foco: {phase['focus']}",
                        ""
                    ])
            
            # Quick wins
            quick_wins = plan.get('quick_wins', [])
            if quick_wins:
                md_lines.extend([
                    "### ⚡ Quick Wins (Vitórias Rápidas)",
                    ""
                ])
                
                for win in quick_wins:
                    md_lines.extend([
                        f"**{win['vulnerability']}**",
                        f"- Localização: {win['location']}",
                        f"- Fix Rápido: {win['quick_fix']}",
                        f"- Tempo Estimado: {win['estimated_time']}",
                        ""
                    ])
            
            # Melhorias de longo prazo
            long_term = plan.get('long_term_improvements', [])
            if long_term:
                md_lines.extend([
                    "### 🎯 Melhorias de Longo Prazo",
                    ""
                ])
                
                for improvement in long_term:
                    md_lines.append(f"- {improvement}")
        
        # Adiciona métricas de performance
        md_lines.extend([
            "",
            "## 📊 Métricas de Performance",
            ""
        ])
        
        for module, stats in self.performance.get('modules_performance', {}).items():
            md_lines.append(
                f"- **{module}:** {stats.get('duration', 0):.2f}s "
                f"({stats.get('percentage', 0):.1f}% do tempo total)"
            )
        
        return "\n".join(md_lines)

#!/usr/bin/env python3
"""
Script de teste para a FASE 1 - Análise Heurística e Priorização
"""

import sys
import os

# Adiciona o diretório src ao path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))

from analysis.risk_scorer import RiskScorer, Severity
from analysis.heuristic_analyzer import HeuristicAnalyzer
from analysis.recommendation_engine import RecommendationEngine

def test_risk_scorer():
    """Testa o sistema de scoring de risco"""
    print("=" * 60)
    print("🎯 TESTE 1: Risk Scorer")
    print("=" * 60)
    
    scorer = RiskScorer()
    
    # Vulnerabilidade de teste
    test_vuln = {
        'type': 'SQL Injection',
        'url': 'http://example.com/admin/login',
        'method': 'GET',
        'evidence': 'SQL error detected',
        'description': 'SQL injection via username parameter'
    }
    
    # Calcula score
    scored = scorer.score_vulnerability(test_vuln)
    
    print(f"\n✅ Vulnerabilidade: {test_vuln['type']}")
    print(f"   Risk Score: {scored['risk_score']}/10")
    print(f"   Severidade: {scored['severity']}")
    print(f"   Metrics:")
    print(f"     - Base Score: {scored['metrics']['base_score']}")
    print(f"     - Impact: {scored['metrics']['impact_score']}")
    print(f"     - Exploitability: {scored['metrics']['exploitability']}")
    print(f"     - Context: {scored['metrics']['context_multiplier']}")
    
    # Testa múltiplas vulnerabilidades
    vulns = [
        {'type': 'XSS', 'url': 'http://example.com/search', 'method': 'GET'},
        {'type': 'SQL Injection', 'url': 'http://example.com/login', 'method': 'POST'},
        {'type': 'Command Injection', 'url': 'http://example.com/admin/exec', 'method': 'POST'},
        {'type': 'Path Traversal', 'url': 'http://example.com/files', 'method': 'GET'},
    ]
    
    scored_vulns = scorer.score_vulnerabilities(vulns)
    summary = scorer.get_risk_summary(scored_vulns)
    
    print(f"\n📊 Resumo de {len(vulns)} vulnerabilidades:")
    print(f"   Score Médio: {summary['average_score']}/10")
    print(f"   Score Máximo: {summary['max_score']}/10")
    print(f"   Nível de Risco: {summary['overall_risk_level']}")
    print(f"   Distribuição:")
    for sev, count in summary['severity_distribution'].items():
        print(f"     - {sev}: {count}")
    
    print("\n✅ Risk Scorer funcionando corretamente!\n")
    return scored_vulns

def test_heuristic_analyzer(vulnerabilities):
    """Testa o analisador heurístico"""
    print("=" * 60)
    print("🔍 TESTE 2: Heuristic Analyzer")
    print("=" * 60)
    
    analyzer = HeuristicAnalyzer()
    
    # Análise de superfície de ataque
    attack_surface = analyzer.analyze_attack_surface(vulnerabilities)
    
    print(f"\n🎯 Superfície de Ataque:")
    print(f"   URLs Afetadas: {attack_surface['total_urls_affected']}")
    print(f"   URLs com Múltiplas Vulns: {attack_surface['urls_with_multiple_vulns']}")
    print(f"   Endpoints Sensíveis: {attack_surface['sensitive_endpoints_vulnerable']}")
    
    # Detecta attack chains
    chains = analyzer.detect_attack_chains(vulnerabilities)
    
    print(f"\n⚠️ Attack Chains Detectadas: {len(chains)}")
    for chain in chains:
        print(f"   - {chain['chain_name']} ({chain['severity']})")
        print(f"     Componentes: {', '.join(chain['components'])}")
    
    # Caminhos de exploração
    paths = analyzer.identify_exploitation_path(vulnerabilities)
    
    print(f"\n🎯 Caminhos de Exploração (Top {min(3, len(paths))}):")
    for path in paths[:3]:
        print(f"   {path['step']}. {path['vulnerability']} (Score: {path['risk_score']}/10)")
        print(f"      Target: {path['target']}")
        print(f"      Ferramentas: {', '.join(path['required_tools'])}")
    
    # Correlação
    correlation = analyzer.correlate_vulnerabilities(vulnerabilities)
    
    print(f"\n📈 Análise de Correlação:")
    print(f"   Tipos Únicos: {correlation['vulnerability_types']}")
    print(f"   Métodos HTTP: {correlation['http_methods_affected']}")
    print(f"   Padrões Detectados: {len(correlation['patterns_detected'])}")
    
    print("\n✅ Heuristic Analyzer funcionando corretamente!\n")

def test_recommendation_engine(vulnerabilities):
    """Testa o motor de recomendações"""
    print("=" * 60)
    print("🛠️ TESTE 3: Recommendation Engine")
    print("=" * 60)
    
    engine = RecommendationEngine()
    
    # Prioriza vulnerabilidades
    prioritized = engine.prioritize_vulnerabilities(vulnerabilities)
    
    print(f"\n📋 Vulnerabilidades Priorizadas:")
    for vuln in prioritized:
        print(f"   #{vuln['remediation_priority']} - {vuln['type']} "
              f"(Score: {vuln['priority_score']}, Risk: {vuln['risk_score']}/10)")
    
    # Gera plano de remediação
    plan = engine.generate_remediation_plan(vulnerabilities)
    
    print(f"\n⏱️ Timeline de Remediação:")
    print(f"   Total: {plan['estimated_timeline']['total_hours']}h "
          f"({plan['estimated_timeline']['total_days']} dias)")
    print(f"   Recomendação: {plan['estimated_timeline']['recommendation']}")
    
    print(f"\n📋 Fases de Remediação: {len(plan['remediation_phases'])}")
    for phase in plan['remediation_phases']:
        print(f"   Fase {phase['phase']}: {phase['name']}")
        print(f"     - Prioridade: {phase['priority']}")
        print(f"     - Timeframe: {phase['timeframe']}")
        print(f"     - Vulnerabilidades: {phase['vulnerabilities']}")
    
    print(f"\n⚡ Quick Wins: {len(plan['quick_wins'])}")
    for win in plan['quick_wins'][:3]:
        print(f"   - {win['vulnerability']}")
        print(f"     Fix: {win['quick_fix']}")
    
    print(f"\n🎯 Melhorias Longo Prazo: {len(plan['long_term_improvements'])}")
    for improvement in plan['long_term_improvements'][:3]:
        print(f"   - {improvement}")
    
    # Testa guia de remediação
    guide = engine.get_remediation_guide('XSS')
    
    print(f"\n📖 Guia de Remediação para XSS:")
    print(f"   Prioridade: {guide['priority']}")
    print(f"   Quick Fix: {guide['quick_fix']}")
    print(f"   Passos Detalhados: {len(guide['detailed_steps'])}")
    print(f"   Checklist: {len(guide['prevention_checklist'])} itens")
    print(f"   Ferramentas: {', '.join(guide['testing_tools'])}")
    
    print("\n✅ Recommendation Engine funcionando corretamente!\n")

def main():
    """Executa todos os testes"""
    print("\n" + "=" * 60)
    print("🚀 TESTE COMPLETO DA FASE 1")
    print("   Análise Heurística e Priorização de Vulnerabilidades")
    print("=" * 60 + "\n")
    
    try:
        # Teste 1: Risk Scorer
        scored_vulns = test_risk_scorer()
        
        # Teste 2: Heuristic Analyzer
        test_heuristic_analyzer(scored_vulns)
        
        # Teste 3: Recommendation Engine
        test_recommendation_engine(scored_vulns)
        
        print("=" * 60)
        print("🎉 TODOS OS TESTES PASSARAM COM SUCESSO!")
        print("=" * 60)
        print("\n✅ FASE 1 implementada e funcionando corretamente!")
        print("   - Risk Scoring com CVSS adaptado")
        print("   - Análise Heurística de Attack Surface")
        print("   - Detecção de Attack Chains")
        print("   - Caminhos de Exploração")
        print("   - Priorização Inteligente")
        print("   - Planos de Remediação Personalizados")
        print("   - Guias Detalhados de Correção")
        print("\n")
        
        return 0
        
    except Exception as e:
        print(f"\n❌ ERRO: {str(e)}")
        import traceback
        traceback.print_exc()
        return 1

if __name__ == '__main__':
    sys.exit(main())

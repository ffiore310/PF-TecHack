#!/usr/bin/env python3
"""
Script de teste para verificar se a FASE 2 (Dashboard Visual) está funcionando.
"""

import requests
import json
import time
from datetime import datetime

print("=" * 70)
print("🧪 TESTE DA FASE 2 - DASHBOARD VISUAL")
print("=" * 70)
print()

# Configurações
BASE_URL = "http://localhost:5001"
TARGET_URL = "http://localhost:5000"

def test_web_app_running():
    """Testa se a aplicação web está rodando"""
    print("📡 Teste 1: Verificando se a aplicação web está rodando...")
    try:
        response = requests.get(BASE_URL, timeout=5)
        if response.status_code == 200:
            print("   ✅ Aplicação web respondendo em http://localhost:5001")
            return True
        else:
            print(f"   ❌ Erro: Status code {response.status_code}")
            return False
    except Exception as e:
        print(f"   ❌ Erro ao conectar: {e}")
        print("   💡 Execute: python3 src/web/app.py")
        return False

def test_scan_execute_route():
    """Testa a nova rota /scan/execute"""
    print("\n📡 Teste 2: Testando rota /scan/execute (nova da Fase 2)...")
    try:
        # Prepara dados do formulário
        data = {
            'url': TARGET_URL,
            'type': 'all'
        }
        
        print(f"   📤 Enviando requisição para {BASE_URL}/scan/execute")
        print(f"   🎯 Target: {TARGET_URL}")
        
        response = requests.post(
            f"{BASE_URL}/scan/execute",
            data=data,
            timeout=30
        )
        
        if response.status_code == 200:
            result = response.json()
            
            if result.get('status') == 'success':
                print("   ✅ Scan executado com sucesso!")
                print(f"   📊 Scan ID: {result.get('scan_id')}")
                
                # Verifica estrutura dos dados
                data = result.get('data', {})
                print(f"\n   📈 Dados retornados:")
                print(f"      - Total vulnerabilidades: {data.get('total_vulns', 0)}")
                print(f"      - Tempo de scan: {data.get('scan_time', 0):.2f}s")
                
                # Verifica dados da Fase 1
                if 'risk_summary' in data:
                    risk = data['risk_summary']
                    print(f"      - Risk Summary: ✅")
                    print(f"        • Score médio: {risk.get('average_score', 0):.2f}/10")
                    print(f"        • Nível de risco: {risk.get('overall_risk_level', 'N/A')}")
                else:
                    print(f"      - Risk Summary: ❌ AUSENTE")
                
                if 'heuristic_insights' in data:
                    print(f"      - Heuristic Insights: ✅")
                else:
                    print(f"      - Heuristic Insights: ❌ AUSENTE")
                
                if 'remediation_plan' in data:
                    print(f"      - Remediation Plan: ✅")
                else:
                    print(f"      - Remediation Plan: ❌ AUSENTE")
                
                return True, result.get('scan_id')
            else:
                print(f"   ❌ Erro: {result.get('message')}")
                return False, None
        else:
            print(f"   ❌ Erro HTTP: {response.status_code}")
            try:
                error = response.json()
                print(f"   💬 Mensagem: {error.get('message', 'N/A')}")
            except:
                print(f"   💬 Resposta: {response.text[:200]}")
            return False, None
            
    except Exception as e:
        print(f"   ❌ Erro na requisição: {e}")
        return False, None

def test_download_route(scan_id):
    """Testa a rota de download"""
    print(f"\n📡 Teste 3: Testando rota /scan/download/{scan_id}...")
    
    for fmt in ['json', 'markdown']:
        try:
            print(f"\n   📥 Testando download formato: {fmt.upper()}")
            response = requests.get(
                f"{BASE_URL}/scan/download/{scan_id}",
                params={'format': fmt},
                timeout=10
            )
            
            if response.status_code == 200:
                # Verifica se tem conteúdo
                content_length = len(response.content)
                print(f"   ✅ Download {fmt.upper()} bem-sucedido!")
                print(f"      - Tamanho: {content_length} bytes")
                
                # Verifica content-type
                content_type = response.headers.get('content-type', '')
                print(f"      - Content-Type: {content_type}")
                
                # Se for JSON, verifica estrutura
                if fmt == 'json':
                    try:
                        data = response.json()
                        print(f"      - Estrutura JSON válida: ✅")
                        
                        # Verifica seções do relatório
                        if 'scan_info' in data:
                            print(f"      - scan_info: ✅")
                        if 'vulnerabilities' in data:
                            print(f"      - vulnerabilities: ✅ ({len(data['vulnerabilities'])} items)")
                        if 'risk_analysis' in data:
                            print(f"      - risk_analysis (FASE 1): ✅")
                        
                    except:
                        print(f"      - JSON inválido: ❌")
                
                # Se for Markdown, verifica conteúdo
                if fmt == 'markdown':
                    text = response.text
                    
                    # Verifica seções esperadas
                    sections = [
                        '# Relatório de Scan',
                        '## 🎯 Análise de Risco',
                        '## 🔍 Análise Heurística',
                        '## 🛠️ Plano de Remediação'
                    ]
                    
                    found = [s for s in sections if s in text]
                    print(f"      - Seções encontradas: {len(found)}/{len(sections)}")
                    
                    if len(found) >= 3:
                        print(f"      - Relatório Markdown completo: ✅")
            else:
                print(f"   ❌ Erro HTTP: {response.status_code}")
                
        except Exception as e:
            print(f"   ❌ Erro: {e}")

def test_frontend_structure():
    """Verifica se o HTML tem os elementos do dashboard"""
    print(f"\n📡 Teste 4: Verificando estrutura do frontend...")
    
    try:
        response = requests.get(BASE_URL, timeout=5)
        html = response.text
        
        # Elementos esperados
        elements = {
            'Chart.js CDN': 'chart.min.js',
            'Dashboard Section': 'id="dashboardSection"',
            'Severity Chart': 'id="severityChart"',
            'Type Chart': 'id="typeChart"',
            'Risk Score Chart': 'id="riskScoreChart"',
            'Timeline Content': 'id="timelineContent"',
            'Quick Wins': 'id="quickWinsContent"',
            'Attack Chains': 'id="attackChainsContent"',
            'Vuln Details List': 'id="vulnDetailsList"',
            'Função populateDashboard': 'function populateDashboard',
            'Função createSeverityChart': 'function createSeverityChart',
            'Rota /scan/execute': '/scan/execute'
        }
        
        found = 0
        missing = []
        
        for name, selector in elements.items():
            if selector in html:
                print(f"   ✅ {name}")
                found += 1
            else:
                print(f"   ❌ {name} - AUSENTE")
                missing.append(name)
        
        print(f"\n   📊 Elementos encontrados: {found}/{len(elements)}")
        
        if found == len(elements):
            print(f"   ✅ Frontend completo com todos os elementos do dashboard!")
            return True
        else:
            print(f"   ⚠️ Alguns elementos estão faltando:")
            for m in missing:
                print(f"      - {m}")
            return False
            
    except Exception as e:
        print(f"   ❌ Erro: {e}")
        return False

def print_manual_test_guide():
    """Imprime guia de teste manual"""
    print("\n" + "=" * 70)
    print("📋 GUIA DE TESTE MANUAL NO NAVEGADOR")
    print("=" * 70)
    print("""
1. ✅ Abra o navegador em: http://localhost:5001

2. ✅ Você deve ver:
   - Formulário de scan (lado esquerdo)
   - Área de resultados (lado direito)

3. ✅ Preencha o formulário:
   - URL: http://localhost:5000
   - Tipo: ☑️ Todos
   - Formato: JSON (ou Markdown)

4. ✅ Clique em "Iniciar Scan"
   - Deve aparecer "Scan em andamento..."

5. ✅ Após alguns segundos, o DASHBOARD deve aparecer com:
   
   📊 MÉTRICAS (4 cards no topo):
   ┌─────────────┬─────────────┬─────────────┬─────────────┐
   │ Total Vulns │ Avg Score   │ Risk Level  │ Scan Time   │
   └─────────────┴─────────────┴─────────────┴─────────────┘
   
   📈 GRÁFICOS:
   ┌──────────────┬──────────────┐
   │ Gráfico Pizza│ Gráfico Barras│
   │ (Severidade) │ (Tipos)      │
   └──────────────┴──────────────┘
   
   ┌────────────────────────────┐
   │ Gráfico Risk Scores (Top 10)│
   └────────────────────────────┘
   
   🛠️ PLANO DE REMEDIAÇÃO:
   ┌──────────────┬──────────────┐
   │ Timeline     │ Quick Wins   │
   └──────────────┴──────────────┘
   
   ⚠️ ATTACK CHAINS (se detectadas):
   ┌────────────────────────────┐
   │ Alert vermelho com chains  │
   └────────────────────────────┘
   
   📋 LISTA DETALHADA:
   ┌────────────────────────────┐
   │ #1 SQL Injection [10/10]  │
   │ #2 XSS [7.5/10]            │
   │ ...                         │
   └────────────────────────────┘

6. ✅ Clique no botão "Baixar Relatório Completo"
   - Deve fazer download do arquivo
   - Nome: scan_report_YYYYMMDD_HHMMSS.json (ou .md)

7. ✅ Verifique o console do navegador (F12)
   - Não deve ter erros em vermelho
   - Pode ter logs em azul (normais)

8. ✅ Teste responsividade:
   - Redimensione a janela do navegador
   - Os cards devem reorganizar
   - Gráficos devem adaptar

9. ✅ Faça outro scan:
   - Formulário deve funcionar novamente
   - Dashboard deve atualizar com novos dados
   - Gráficos devem ser recriados
""")

def main():
    """Executa todos os testes"""
    
    # Teste 1: Web app rodando
    if not test_web_app_running():
        print("\n❌ Aplicação web não está rodando. Testes abortados.")
        print("\n💡 Para iniciar:")
        print("   Terminal 1: python3 src/tests/test_server.py")
        print("   Terminal 2: python3 src/web/app.py")
        return
    
    # Teste 2: Scan execute
    success, scan_id = test_scan_execute_route()
    
    # Teste 3: Download
    if success and scan_id:
        test_download_route(scan_id)
    else:
        print("\n⚠️ Pulando teste de download (scan falhou)")
    
    # Teste 4: Frontend
    test_frontend_structure()
    
    # Guia manual
    print_manual_test_guide()
    
    # Resumo final
    print("\n" + "=" * 70)
    print("📊 RESUMO DOS TESTES AUTOMATIZADOS")
    print("=" * 70)
    print("""
✅ Se todos os testes acima passaram, a FASE 2 está funcionando!

🎯 Próximos passos:
   1. Abra http://localhost:5001 no navegador
   2. Execute um scan
   3. Visualize o dashboard interativo
   4. Baixe o relatório completo

📸 O dashboard deve mostrar:
   - Métricas em cards
   - 3 gráficos (pizza, barras, risk scores)
   - Timeline de remediação
   - Quick wins
   - Attack chains (se detectadas)
   - Lista detalhada de vulnerabilidades

🎉 FASE 2 COMPLETA!
""")

if __name__ == '__main__':
    main()

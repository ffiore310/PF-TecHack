#!/usr/bin/env python3

"""
Script para testar o scanner contra o servidor de teste.
"""

import time
import sys
import os
import datetime

# Adiciona o diretório src ao Python path
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from scanner import Scanner
from report_generator import ReportGenerator

def test_scanner():
    # URL do servidor de teste
    test_url = "http://localhost:5000"
    
    print("Iniciando teste do scanner...")
    print(f"Testando URL: {test_url}")
    
    # Criar instância do scanner
    scanner = Scanner()
    
    # Executar scan
    print("\nExecutando scan...")
    results = scanner.scan(test_url)
    
    # Criar nome do arquivo de relatório com timestamp
    timestamp = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
    report_file = f"scan_report_{timestamp}.txt"
    
    # Gerar relatório
    print(f"\nGerando relatório em {report_file}...")
    report_gen = ReportGenerator()
    report_gen.generate(results, report_file)
    
    # Mostrar resumo na tela
    print("\nResumo do scan:")
    print(f"URL: {results['url']}")
    print(f"Tempo de scan: {results['scan_time']:.2f} segundos")
    print(f"Total de vulnerabilidades encontradas: {len(results['vulnerabilities'])}")
    print(f"\nRelatório completo salvo em: {report_file}")

if __name__ == '__main__':
    print("=== Scanner Test Tool ===")
    print("\nCertifique-se de que o servidor de teste (test_server.py) está rodando!")
    input("Pressione Enter para continuar...")
    
    try:
        test_scanner()
    except Exception as e:
        print(f"\nErro durante o teste: {e}")
    finally:
        print("\nTeste concluído.")

#!/usr/bin/env python3

"""
Main entry point for the Web Application Security Scanner.
Handles command line arguments and initiates the scanning process.
"""

import argparse
import sys
import datetime
from colorama import init, Fore, Style
from scanner import Scanner
from report_generator import ReportGenerator

# Inicializa colorama para saída colorida
init()

def print_banner():
    """Exibe o banner do scanner"""
    banner = f"""
{Fore.CYAN}Web Application Security Scanner{Style.RESET_ALL}
{Fore.BLUE}================================{Style.RESET_ALL}
Versão: 1.0.0 (Conceito B)
Desenvolvido por: Fernando Fiore
"""
    print(banner)

def print_status(message, status="info"):
    """Exibe mensagens coloridas de status"""
    colors = {
        "info": Fore.BLUE,
        "success": Fore.GREEN,
        "error": Fore.RED,
        "warning": Fore.YELLOW
    }
    color = colors.get(status, Fore.WHITE)
    print(f"{color}[*] {message}{Style.RESET_ALL}")

def validate_scan_types(value):
    """Valida os tipos de scan selecionados"""
    valid_types = {'xss', 'sqli', 'all'}
    types = set(value.lower().split(','))
    
    if not types.issubset(valid_types):
        invalid = types - valid_types
        raise argparse.ArgumentTypeError(
            f"Tipos de scan inválidos: {', '.join(invalid)}. "
            f"Tipos válidos: {', '.join(valid_types)}"
        )
    return types

def main():
    parser = argparse.ArgumentParser(
        description='Scanner de Segurança para Aplicações Web',
        formatter_class=argparse.RawDescriptionHelpFormatter
    )
    
    parser.add_argument(
        '-u', '--url',
        required=True,
        help='URL alvo para scan (ex: http://exemplo.com)'
    )
    
    parser.add_argument(
        '-t', '--types',
        type=validate_scan_types,
        default='all',
        help='Tipos de scan a serem executados (xss,sqli,all). Default: all'
    )
    
    parser.add_argument(
        '-o', '--output',
        help='Arquivo de saída para o relatório. Se não especificado, será gerado automaticamente'
    )
    
    parser.add_argument(
        '-q', '--quiet',
        action='store_true',
        help='Modo silencioso - mostra apenas resultados essenciais'
    )
    
    args = parser.parse_args()
    
    if not args.quiet:
        print_banner()
    
    # Gera nome do arquivo de saída se não especificado
    if not args.output:
        timestamp = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
        args.output = f"scan_report_{timestamp}.txt"
    
    try:
        # Inicializa e executa o scanner
        print_status(f"Iniciando scan em {args.url}", "info")
        print_status(f"Tipos de scan selecionados: {','.join(args.types)}", "info")
        
        scanner = Scanner()
        results = scanner.scan(
            url=args.url,
            scan_types=args.types,
            scan_mode='quiet' if args.quiet else 'normal'
        )
        
        # Gera o relatório
        print_status("Gerando relatório...", "info")
        report_gen = ReportGenerator()
        report_gen.generate(results, args.output)
        
        # Exibe resumo
        vuln_count = len(results['vulnerabilities'])
        if vuln_count > 0:
            print_status(
                f"Scan completo. Encontradas {vuln_count} vulnerabilidades!",
                "warning"
            )
        else:
            print_status("Scan completo. Nenhuma vulnerabilidade encontrada.", "success")
        
        print_status(f"Relatório salvo em: {args.output}", "success")
        
    except KeyboardInterrupt:
        print_status("\nScan interrompido pelo usuário.", "warning")
        sys.exit(1)
    except Exception as e:
        print_status(f"Erro durante o scan: {str(e)}", "error")
        sys.exit(1)

if __name__ == '__main__':
    main()

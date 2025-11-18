"""
Interface web do scanner.
"""

from flask import Flask, render_template, request, jsonify, send_file
import sys
import os
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from scanner import Scanner
from reports.json_report import JsonReport
from reports.markdown_report import MarkdownReport
from reports.html_report import HtmlReport
from datetime import datetime
import io

app = Flask(__name__)
scanner = Scanner()

# Desabilita proteção XSS do navegador (já que é uma ferramenta de segurança)
@app.after_request
def add_security_headers(response):
    """Adiciona headers de segurança para evitar alertas do navegador"""
    response.headers['X-XSS-Protection'] = '0'  # Desabilita filtro XSS do navegador
    response.headers['X-Content-Type-Options'] = 'nosniff'
    response.headers['Content-Security-Policy'] = "default-src 'self' 'unsafe-inline' 'unsafe-eval' https://cdn.jsdelivr.net https://code.jquery.com; img-src 'self' data:;"
    return response

# Armazena resultados do último scan (em produção, use Redis ou banco de dados)
last_scan_results = {}

@app.route('/')
def index():
    """Página principal"""
    return render_template('index.html')

@app.route('/scan/execute', methods=['POST'])
def execute_scan():
    """Executa scan e retorna dados JSON para o dashboard"""
    try:
        url = request.form.get('url')
        scan_type = request.form.get('type', 'all').split(',')
        
        # Valida URL
        if not url:
            return jsonify({
                'status': 'error',
                'message': 'URL não fornecida'
            }), 400
        
        app.logger.info(f"Iniciando scan para URL: {url}")
        
        # Executa scan
        results = scanner.scan(url, scan_types=scan_type)
        
        app.logger.info(f"Scan concluído")
        
        # Verifica se há erro no resultado
        if 'error' in results:
            return jsonify({
                'status': 'error',
                'message': results['error']
            }), 400
        
        # Armazena resultados para download posterior
        scan_id = datetime.now().strftime("%Y%m%d_%H%M%S")
        last_scan_results[scan_id] = results
        
        # Retorna dados para o dashboard
        return jsonify({
            'status': 'success',
            'scan_id': scan_id,
            'data': results
        })
            
    except Exception as e:
        app.logger.error(f"Erro interno: {str(e)}")
        return jsonify({
            'status': 'error',
            'message': f'Erro interno: {str(e)}'
        }), 500

@app.route('/scan', methods=['POST'])
def start_scan():
    """DEPRECATED: Mantido para compatibilidade. Use /scan/execute"""
    return execute_scan()

@app.route('/scan/download/<scan_id>', methods=['GET'])
def download_report(scan_id):
    """Baixa relatório de um scan específico"""
    try:
        report_format = request.args.get('format', 'json')
        
        # Recupera resultados do scan
        if scan_id not in last_scan_results:
            return jsonify({
                'status': 'error',
                'message': 'Scan não encontrado'
            }), 404
        
        results = last_scan_results[scan_id]
        
        # Gera relatório no formato escolhido
        if report_format == 'json':
            report = JsonReport(results)
            mimetype = 'application/json'
            extension = 'json'
        elif report_format == 'html':
            report = HtmlReport(results)
            mimetype = 'text/html'
            extension = 'html'
        else:  # markdown
            report = MarkdownReport(results)
            mimetype = 'text/markdown'
            extension = 'md'
        
        report_content = report.generate()
        
        # Determina o nome do arquivo
        filename = f'scan_report_{scan_id}.{extension}'
            
        app.logger.info(f"Relatório gerado com sucesso no formato {report_format}")
        
        # Retorna o relatório como download
        buffer = io.BytesIO()
        buffer.write(report_content.encode('utf-8'))
        buffer.seek(0)
        
        response = send_file(
            buffer,
            mimetype=mimetype,
            as_attachment=True,
            download_name=filename
        )
        
        # Adiciona cabeçalhos explícitos
        response.headers['Content-Disposition'] = f'attachment; filename="{filename}"'
        response.headers['Access-Control-Expose-Headers'] = 'Content-Disposition'
        
        return response
        
    except Exception as e:
        app.logger.error(f"Erro ao gerar relatório: {str(e)}")
        return jsonify({
            'status': 'error',
            'message': f'Erro ao gerar relatório: {str(e)}'
        }), 500

if __name__ == '__main__':
    # Inicia servidor web
    app.run(host='0.0.0.0', port=5001)

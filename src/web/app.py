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
from datetime import datetime
import io

app = Flask(__name__)
scanner = Scanner()

@app.route('/')
def index():
    """Página principal"""
    return render_template('index.html')

@app.route('/scan', methods=['POST'])
def start_scan():
    """Inicia um scan imediato"""
    try:
        url = request.form.get('url')
        scan_type = request.form.get('type', 'all').split(',')
        report_format = request.form.get('format', 'json')
        
        # Valida URL
        if not url:
            return jsonify({
                'status': 'error',
                'message': 'URL não fornecida'
            }), 400
        
        app.logger.info(f"Iniciando scan para URL: {url}")
        
        # Executa scan
        results = scanner.scan(url, scan_types=scan_type)
        
        app.logger.info(f"Scan concluído. Resultados: {results}")
        
        # Verifica se há erro no resultado
        if 'error' in results:
            return jsonify({
                'status': 'error',
                'message': results['error']
            }), 400
            
        # Gera relatório no formato escolhido
        try:
            if report_format == 'json':
                report = JsonReport(results)
                mimetype = 'application/json'
                extension = 'json'
            else:  # markdown
                report = MarkdownReport(results)
                mimetype = 'text/markdown'
                extension = 'md'
            
            report_content = report.generate()
            
            # Determina o nome do arquivo
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            filename = f'scan_report_{timestamp}.{extension}'
                
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
            
    except Exception as e:
        app.logger.error(f"Erro interno: {str(e)}")
        return jsonify({
            'status': 'error',
            'message': f'Erro interno: {str(e)}'
        }), 500

if __name__ == '__main__':
    # Inicia servidor web
    app.run(host='0.0.0.0', port=5001)

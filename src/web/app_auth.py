"""
Interface web do scanner com sistema de autenticação.
FASE 4: Sistema multi-usuário completo
"""

from flask import Flask, render_template, request, jsonify, send_file, redirect, url_for, flash
from flask_login import LoginManager, login_user, logout_user, login_required, current_user
import sys
import os
import secrets
import threading
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from scanner import Scanner
from reports.json_report import JsonReport
from reports.markdown_report import MarkdownReport
from reports.html_report import HtmlReport
from datetime import datetime
import io

# Importa modelos e formulários
from models import db, User, Scan, Report, init_db
from forms import LoginForm, RegistrationForm, ScanForm, EditProfileForm, ChangePasswordForm

app = Flask(__name__)

# Configurações
# SECRET_KEY muda a cada reinício em modo dev - invalida sessões antigas automaticamente
app.config['SECRET_KEY'] = os.environ.get('SECRET_KEY') or secrets.token_hex(32)
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///scanner.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

# Configurações de Sessão - Invalidar ao fechar navegador/reiniciar servidor
app.config['SESSION_COOKIE_HTTPONLY'] = True  # Segurança: cookie não acessível via JS
app.config['SESSION_COOKIE_SAMESITE'] = 'Lax'  # Proteção CSRF
app.config['PERMANENT_SESSION_LIFETIME'] = 3600  # Sessão expira em 1 hora (3600 segundos)
app.config['SESSION_REFRESH_EACH_REQUEST'] = True  # Renova tempo a cada requisição

# Inicializa extensões
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'
login_manager.login_message = 'Por favor, faça login para acessar esta página.'
login_manager.login_message_category = 'warning'
login_manager.session_protection = 'strong'  # Proteção forte contra session hijacking

# Inicializa banco de dados
init_db(app)

# Scanner global
scanner = Scanner()

# User loader para Flask-Login
@login_manager.user_loader
def load_user(user_id):
    """Carrega usuário pelo ID"""
    return User.query.get(user_id)

# Headers de segurança
@app.after_request
def add_security_headers(response):
    """Adiciona headers de segurança para evitar alertas do navegador"""
    response.headers['X-XSS-Protection'] = '0'
    response.headers['X-Content-Type-Options'] = 'nosniff'
    response.headers['Content-Security-Policy'] = "default-src 'self' 'unsafe-inline' 'unsafe-eval' https://cdn.jsdelivr.net https://code.jquery.com; img-src 'self' data:;"
    return response


# ==================== ROTAS DE AUTENTICAÇÃO ====================

@app.route('/')
def index():
    """Página inicial - redireciona conforme autenticação"""
    if current_user.is_authenticated:
        return redirect(url_for('dashboard'))
    return redirect(url_for('login'))


@app.route('/login', methods=['GET', 'POST'])
def login():
    """Página de login"""
    if current_user.is_authenticated:
        return redirect(url_for('dashboard'))
    
    form = LoginForm()
    if form.validate_on_submit():
        user = User.query.filter_by(email=form.email.data.lower()).first()
        
        if user and user.check_password(form.password.data):
            login_user(user, remember=False)  # Sempre sessão temporária
            user.update_last_login()
            flash(f'Bem-vindo de volta, {user.name}!', 'success')
            
            # Redireciona para próxima página ou dashboard
            next_page = request.args.get('next')
            return redirect(next_page) if next_page else redirect(url_for('dashboard'))
        else:
            flash('Email ou senha incorretos. Tente novamente.', 'danger')
    
    return render_template('login.html', form=form)


@app.route('/register', methods=['GET', 'POST'])
def register():
    """Página de cadastro"""
    if current_user.is_authenticated:
        return redirect(url_for('dashboard'))
    
    form = RegistrationForm()
    if form.validate_on_submit():
        user = User(
            name=form.name.data,
            email=form.email.data.lower(),
            company=form.company.data if form.company.data else None
        )
        user.set_password(form.password.data)
        
        db.session.add(user)
        db.session.commit()
        
        flash(f'Conta criada com sucesso! Faça login para continuar.', 'success')
        return redirect(url_for('login'))
    
    return render_template('register.html', form=form)


@app.route('/logout')
@login_required
def logout():
    """Logout do usuário"""
    logout_user()
    flash('Você saiu da sua conta. Até logo!', 'info')
    return redirect(url_for('login'))


# ==================== DASHBOARD E PERFIL ====================

@app.route('/dashboard')
@login_required
def dashboard():
    """Dashboard do usuário"""
    # Busca scans do usuário (ordenados por mais recente)
    scans = current_user.scans.order_by(Scan.created_at.desc()).limit(20).all()
    
    # Verifica se há scans em andamento (para auto-refresh)
    has_running_scans = current_user.scans.filter(
        (Scan.status == 'running') | (Scan.status == 'pending')
    ).count() > 0
    
    # Estatísticas
    scan_count = current_user.get_scan_count()
    total_vulnerabilities = current_user.get_total_vulnerabilities()
    
    # Conta vulnerabilidades críticas
    critical_count = 0
    for scan in current_user.scans:
        if scan.status == 'completed':
            critical_count += scan.critical_count
    
    return render_template('dashboard.html',
                         scans=scans,
                         scan_count=scan_count,
                         total_vulnerabilities=total_vulnerabilities,
                         critical_count=critical_count,
                         has_running_scans=has_running_scans)


@app.route('/profile')
@login_required
def profile():
    """Perfil do usuário"""
    return render_template('profile.html')


@app.route('/profile/edit', methods=['GET', 'POST'])
@login_required
def edit_profile():
    """Editar perfil"""
    form = EditProfileForm()
    
    if form.validate_on_submit():
        current_user.name = form.name.data
        current_user.company = form.company.data if form.company.data else None
        db.session.commit()
        flash('Perfil atualizado com sucesso!', 'success')
        return redirect(url_for('profile'))
    
    # Preenche formulário com dados atuais
    form.name.data = current_user.name
    form.company.data = current_user.company
    
    return render_template('edit_profile.html', form=form)


@app.route('/profile/change-password', methods=['GET', 'POST'])
@login_required
def change_password():
    """Alterar senha"""
    form = ChangePasswordForm()
    
    if form.validate_on_submit():
        if current_user.check_password(form.current_password.data):
            current_user.set_password(form.new_password.data)
            db.session.commit()
            flash('Senha alterada com sucesso!', 'success')
            return redirect(url_for('profile'))
        else:
            flash('Senha atual incorreta.', 'danger')
    
    return render_template('change_password.html', form=form)


# ==================== SCANS ====================

def run_scan_background(scan_id, url, scan_type):
    """Executa scan em background"""
    with app.app_context():
        try:
            scan = Scan.query.get(scan_id)
            if not scan:
                return
            
            # Atualiza status
            scan.status = 'running'
            db.session.commit()
            
            app.logger.info(f"Executando scan {scan_id} para URL: {url}")
            
            # Determina tipos de scan
            if scan_type == 'all':
                scan_types = ['xss', 'sqli', 'auth', 'crypto']
            else:
                scan_types = [scan_type]
            
            # Executa scanner
            results = scanner.scan(url, scan_types)
            
            # Marca como completo
            scan.mark_completed(results)
            app.logger.info(f"Scan {scan_id} concluído com sucesso")
            
        except Exception as e:
            app.logger.error(f"Erro no scan {scan_id}: {str(e)}")
            scan = Scan.query.get(scan_id)
            if scan:
                scan.mark_failed(str(e))


@app.route('/scan/new', methods=['GET', 'POST'])
@login_required
def new_scan():
    """Criar novo scan"""
    form = ScanForm()
    
    if form.validate_on_submit():
        # Cria registro do scan
        scan = Scan(
            user_id=current_user.id,
            url=form.url.data,
            scan_type=form.scan_type.data,
            status='pending'
        )
        db.session.add(scan)
        db.session.commit()
        
        # Inicia scan em background
        thread = threading.Thread(
            target=run_scan_background,
            args=(scan.id, scan.url, scan.scan_type)
        )
        thread.daemon = True
        thread.start()
        
        flash('Scan iniciado com sucesso! Aguarde alguns instantes para os resultados.', 'success')
        return redirect(url_for('dashboard'))
    
    return render_template('new_scan.html', form=form)


@app.route('/scan/<scan_id>')
@login_required
def scan_detail(scan_id):
    """Detalhes de um scan"""
    scan = Scan.query.get_or_404(scan_id)
    
    # Verifica se o scan pertence ao usuário
    if scan.user_id != current_user.id:
        flash('Você não tem permissão para ver este scan.', 'danger')
        return redirect(url_for('dashboard'))
    
    return render_template('scan_detail.html', scan=scan)


@app.route('/scan/<scan_id>/download/<format>')
@login_required
def download_scan_report(scan_id, format):
    """Baixa relatório de um scan"""
    scan = Scan.query.get_or_404(scan_id)
    
    # Verifica permissão
    if scan.user_id != current_user.id:
        flash('Você não tem permissão para baixar este relatório.', 'danger')
        return redirect(url_for('dashboard'))
    
    if scan.status != 'completed':
        flash('Este scan ainda não foi concluído.', 'warning')
        return redirect(url_for('scan_detail', scan_id=scan_id))
    
    try:
        # Gera relatório no formato escolhido
        if format == 'json':
            report = JsonReport(scan.results)
            mimetype = 'application/json'
            extension = 'json'
        elif format == 'html':
            report = HtmlReport(scan.results)
            mimetype = 'text/html'
            extension = 'html'
        else:  # markdown
            report = MarkdownReport(scan.results)
            mimetype = 'text/markdown'
            extension = 'md'
        
        report_content = report.generate()
        
        # Nome do arquivo
        timestamp = scan.created_at.strftime('%Y%m%d_%H%M%S')
        filename = f'scan_report_{timestamp}.{extension}'
        
        # Cria buffer
        buffer = io.BytesIO()
        buffer.write(report_content.encode('utf-8'))
        buffer.seek(0)
        
        return send_file(
            buffer,
            mimetype=mimetype,
            as_attachment=True,
            download_name=filename
        )
        
    except Exception as e:
        app.logger.error(f"Erro ao gerar relatório: {str(e)}")
        flash(f'Erro ao gerar relatório: {str(e)}', 'danger')
        return redirect(url_for('scan_detail', scan_id=scan_id))


@app.route('/scan/<scan_id>/delete')
@login_required
def delete_scan(scan_id):
    """Exclui um scan"""
    scan = Scan.query.get_or_404(scan_id)
    
    # Verifica permissão
    if scan.user_id != current_user.id:
        flash('Você não tem permissão para excluir este scan.', 'danger')
        return redirect(url_for('dashboard'))
    
    db.session.delete(scan)
    db.session.commit()
    
    flash('Scan excluído com sucesso.', 'success')
    return redirect(url_for('dashboard'))


# ==================== EXECUTAR APLICAÇÃO ====================

if __name__ == '__main__':
    print("\n" + "="*60)
    print("🔐 SISTEMA DE AUTENTICAÇÃO INICIADO")
    print("="*60)
    print("⚠️  Sessões antigas foram invalidadas (nova SECRET_KEY)")
    print("📝 Login necessário: http://localhost:5001")
    print("👤 Admin padrão: admin@webscanner.com / admin123")
    print("="*60 + "\n")
    
    app.run(host='0.0.0.0', port=5001, debug=True)

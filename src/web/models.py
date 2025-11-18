"""
Modelos de banco de dados para sistema de autenticação e histórico de scans.
"""

from flask_sqlalchemy import SQLAlchemy
from flask_login import UserMixin
from werkzeug.security import generate_password_hash, check_password_hash
from datetime import datetime
import uuid

db = SQLAlchemy()


class User(UserMixin, db.Model):
    """Modelo de usuário para autenticação"""
    __tablename__ = 'users'
    
    id = db.Column(db.String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    name = db.Column(db.String(100), nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False, index=True)
    password_hash = db.Column(db.String(200), nullable=False)
    company = db.Column(db.String(100), nullable=True)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    last_login = db.Column(db.DateTime, nullable=True)
    
    # Relacionamento com scans
    scans = db.relationship('Scan', backref='user', lazy='dynamic', cascade='all, delete-orphan')
    
    def set_password(self, password):
        """Criptografa e salva a senha"""
        self.password_hash = generate_password_hash(password, method='pbkdf2:sha256')
    
    def check_password(self, password):
        """Verifica se a senha está correta"""
        return check_password_hash(self.password_hash, password)
    
    def update_last_login(self):
        """Atualiza timestamp do último login"""
        self.last_login = datetime.utcnow()
        db.session.commit()
    
    def get_scan_count(self):
        """Retorna total de scans do usuário"""
        return self.scans.count()
    
    def get_total_vulnerabilities(self):
        """Retorna total de vulnerabilidades encontradas em todos os scans"""
        total = 0
        for scan in self.scans:
            if scan.results:
                total += len(scan.results.get('vulnerabilities', []))
        return total
    
    def __repr__(self):
        return f'<User {self.email}>'


class Scan(db.Model):
    """Modelo de scan armazenado"""
    __tablename__ = 'scans'
    
    id = db.Column(db.String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    user_id = db.Column(db.String(36), db.ForeignKey('users.id'), nullable=False, index=True)
    url = db.Column(db.String(500), nullable=False)
    scan_type = db.Column(db.String(50), nullable=False)  # all, xss, sqli, etc.
    status = db.Column(db.String(20), default='pending')  # pending, completed, failed
    created_at = db.Column(db.DateTime, default=datetime.utcnow, index=True)
    completed_at = db.Column(db.DateTime, nullable=True)
    
    # Resultados em JSON
    results = db.Column(db.JSON, nullable=True)
    
    # Estatísticas rápidas (para não precisar processar JSON toda vez)
    total_vulnerabilities = db.Column(db.Integer, default=0)
    critical_count = db.Column(db.Integer, default=0)
    high_count = db.Column(db.Integer, default=0)
    risk_score = db.Column(db.Float, default=0.0)
    risk_level = db.Column(db.String(20), default='LOW')  # LOW, MEDIUM, HIGH, CRITICAL
    
    # Relacionamento com relatórios
    reports = db.relationship('Report', backref='scan', lazy='dynamic', cascade='all, delete-orphan')
    
    def mark_completed(self, results_data):
        """Marca scan como completo e salva resultados"""
        self.status = 'completed'
        self.completed_at = datetime.utcnow()
        self.results = results_data
        
        # Extrai estatísticas
        if results_data:
            vulns = results_data.get('vulnerabilities', [])
            self.total_vulnerabilities = len(vulns)
            
            # Conta severidades diretamente das vulnerabilidades
            critical_count = 0
            high_count = 0
            for vuln in vulns:
                severity = vuln.get('severity', '').upper()
                if severity == 'CRITICAL':
                    critical_count += 1
                elif severity == 'HIGH':
                    high_count += 1
            
            self.critical_count = critical_count
            self.high_count = high_count
            
            # Pega risk_summary se disponível
            risk_summary = results_data.get('risk_summary', {})
            self.risk_score = risk_summary.get('average_score', 0.0)
            self.risk_level = risk_summary.get('overall_risk_level', 'LOW')
        
        db.session.commit()
    
    def mark_failed(self, error_message=None):
        """Marca scan como falho"""
        self.status = 'failed'
        self.completed_at = datetime.utcnow()
        if error_message:
            self.results = {'error': error_message}
        db.session.commit()
    
    def get_duration(self):
        """Retorna duração do scan em segundos"""
        if self.completed_at:
            delta = self.completed_at - self.created_at
            return round(delta.total_seconds(), 2)
        return None
    
    def __repr__(self):
        return f'<Scan {self.id} - {self.url}>'


class Report(db.Model):
    """Modelo de relatório gerado"""
    __tablename__ = 'reports'
    
    id = db.Column(db.String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    scan_id = db.Column(db.String(36), db.ForeignKey('scans.id'), nullable=False, index=True)
    format = db.Column(db.String(20), nullable=False)  # json, html, markdown
    file_path = db.Column(db.String(500), nullable=True)  # Caminho do arquivo salvo
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    
    # Conteúdo do relatório (se não salvo em arquivo)
    content = db.Column(db.Text, nullable=True)
    
    def __repr__(self):
        return f'<Report {self.id} - {self.format}>'


def init_db(app):
    """Inicializa o banco de dados"""
    db.init_app(app)
    
    with app.app_context():
        # Cria todas as tabelas
        db.create_all()
        
        # Cria usuário admin padrão se não existir
        admin = User.query.filter_by(email='admin@webscanner.com').first()
        if not admin:
            admin = User(
                name='Administrator',
                email='admin@webscanner.com',
                company='Web Security Scanner'
            )
            admin.set_password('admin123')  # MUDAR EM PRODUÇÃO!
            db.session.add(admin)
            db.session.commit()
            print("✅ Usuário admin criado: admin@webscanner.com / admin123")


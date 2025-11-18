"""
Formulários para autenticação e gerenciamento de usuários.
"""

from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, BooleanField, SubmitField, SelectField
from wtforms.validators import DataRequired, Email, EqualTo, Length, ValidationError
from models import User


class LoginForm(FlaskForm):
    """Formulário de login"""
    email = StringField('Email', validators=[
        DataRequired(message='Email é obrigatório'),
        Email(message='Email inválido', check_deliverability=False)
    ])
    password = PasswordField('Senha', validators=[
        DataRequired(message='Senha é obrigatória')
    ])
    submit = SubmitField('Entrar')


class RegistrationForm(FlaskForm):
    """Formulário de cadastro"""
    name = StringField('Nome Completo', validators=[
        DataRequired(message='Nome é obrigatório'),
        Length(min=3, max=100, message='Nome deve ter entre 3 e 100 caracteres')
    ])
    email = StringField('Email', validators=[
        DataRequired(message='Email é obrigatório'),
        Email(message='Email inválido', check_deliverability=False)
    ])
    company = StringField('Empresa/Organização', validators=[
        Length(max=100, message='Nome da empresa muito longo')
    ])
    password = PasswordField('Senha', validators=[
        DataRequired(message='Senha é obrigatória'),
        Length(min=6, message='Senha deve ter no mínimo 6 caracteres')
    ])
    password_confirm = PasswordField('Confirmar Senha', validators=[
        DataRequired(message='Confirmação de senha é obrigatória'),
        EqualTo('password', message='As senhas devem ser iguais')
    ])
    submit = SubmitField('Criar Conta')
    
    def validate_email(self, email):
        """Valida se email já não está cadastrado"""
        user = User.query.filter_by(email=email.data.lower()).first()
        if user:
            raise ValidationError('Este email já está cadastrado. Faça login ou use outro email.')


class ChangePasswordForm(FlaskForm):
    """Formulário para alterar senha"""
    current_password = PasswordField('Senha Atual', validators=[
        DataRequired(message='Senha atual é obrigatória')
    ])
    new_password = PasswordField('Nova Senha', validators=[
        DataRequired(message='Nova senha é obrigatória'),
        Length(min=6, message='Senha deve ter no mínimo 6 caracteres')
    ])
    new_password_confirm = PasswordField('Confirmar Nova Senha', validators=[
        DataRequired(message='Confirmação de senha é obrigatória'),
        EqualTo('new_password', message='As senhas devem ser iguais')
    ])
    submit = SubmitField('Alterar Senha')


class EditProfileForm(FlaskForm):
    """Formulário para editar perfil"""
    name = StringField('Nome Completo', validators=[
        DataRequired(message='Nome é obrigatório'),
        Length(min=3, max=100, message='Nome deve ter entre 3 e 100 caracteres')
    ])
    company = StringField('Empresa/Organização', validators=[
        Length(max=100, message='Nome da empresa muito longo')
    ])
    submit = SubmitField('Salvar Alterações')


class ScanForm(FlaskForm):
    """Formulário para criar novo scan"""
    url = StringField('URL Alvo', validators=[
        DataRequired(message='URL é obrigatória')
    ])
    scan_type = SelectField('Tipo de Scan', choices=[
        ('all', 'Todos os Tipos'),
        ('xss', 'Cross-Site Scripting (XSS)'),
        ('sqli', 'SQL Injection'),
        ('auth', 'Falhas de Autenticação'),
        ('crypto', 'Falhas Criptográficas')
    ])
    submit = SubmitField('Iniciar Scan')

"""
Scanner para detecção de falhas de autenticação (A7:2021).
"""

import re
from typing import List, Dict, Any
from .base_scanner import BaseScanner
from utils.http_utils import make_request

class AuthScanner(BaseScanner):
    def __init__(self):
        super().__init__()
        self.common_passwords = [
            'password', '123456', 'admin', 'admin123', 'root',
            'password123', 'qwerty', '12345', '123456789', 'test'
        ]
        
    def _check_login_rate_limit(self, url):
        """Verifica se existe limitação de tentativas de login."""
        vulnerabilities = []
        
        # Tenta fazer vários logins em sequência rápida
        failed_attempts = 0
        for _ in range(5):  # Tenta 5 vezes
            try:
                response = make_request(
                    f"{url}/login", 
                    method='POST',
                    data={'username': 'admin', 'password': 'wrong'}
                )
                
                if response and response.status_code == 200:
                    failed_attempts += 1
                elif response and response.status_code == 429:
                    # Rate limit detectado, site está protegido
                    return []
            except Exception as e:
                print(f"Erro ao testar rate limit: {str(e)}")
                continue
        
        if failed_attempts >= 5:
            vulnerabilities.append({
                'type': 'Authentication Failure',
                'subtype': 'No Rate Limiting',
                'url': url,
                'severity': 'High',
                'description': 'Não foi detectada limitação de tentativas de login.',
                'recommendation': 'Implementar rate limiting e proteção contra força bruta.'
            })
            
        return vulnerabilities
    
    def _check_weak_passwords(self, url):
        """Verifica se o sistema aceita senhas fracas."""
        vulnerabilities = []
        
        # Tenta registrar conta com senha fraca
        response = make_request(
            f"{url}/register",
            method='POST',
            data={'username': 'test_user', 'password': '123456'}
        )
        
        if response and response.status_code == 200:
            vulnerabilities.append({
                'type': 'Authentication Failure',
                'subtype': 'Weak Password Policy',
                'url': url,
                'severity': 'Medium',
                'description': 'O sistema aceita senhas fracas no registro.',
                'recommendation': 'Implementar política de senhas fortes.'
            })
            
        return vulnerabilities
    
    def _check_password_exposure(self, url):
        """Verifica exposição de senhas em respostas ou logs."""
        vulnerabilities = []
        
        # Tenta login com payload especial para verificar logs
        response = make_request(
            f"{url}/login",
            method='POST',
            data={'username': 'admin', 'password': "' OR '1'='1"}
        )
        
        if response and ('password' in response.text.lower() or 
                        'senha' in response.text.lower()):
            vulnerabilities.append({
                'type': 'Authentication Failure',
                'subtype': 'Password Exposure',
                'url': url,
                'severity': 'High',
                'description': 'Possível exposição de senhas em mensagens de erro ou logs.',
                'recommendation': 'Não incluir senhas em mensagens de erro ou logs.'
            })
            
        return vulnerabilities
    
    def _check_secure_session(self, url):
        """Verifica a segurança das sessões."""
        vulnerabilities = []
        
        response = make_request(url)
        if not response:
            return vulnerabilities
            
        cookies = response.cookies
        for cookie in cookies:
            if not cookie.secure:
                vulnerabilities.append({
                    'type': 'Authentication Failure',
                    'subtype': 'Insecure Session Cookie',
                    'url': url,
                    'severity': 'High',
                    'description': f'Cookie {cookie.name} não está marcado como secure.',
                    'recommendation': 'Marcar cookies de sessão como secure e httpOnly.'
                })
                
            if not cookie.has_nonstandard_attr('httponly'):
                vulnerabilities.append({
                    'type': 'Authentication Failure',
                    'subtype': 'Insecure Session Cookie',
                    'url': url,
                    'severity': 'Medium',
                    'description': f'Cookie {cookie.name} não está marcado como httpOnly.',
                    'recommendation': 'Marcar cookies de sessão como secure e httpOnly.'
                })
                
        return vulnerabilities
    
    def scan(self, url: str) -> List[Dict[str, Any]]:
        """
        Executa verificações de segurança de autenticação.
        
        Args:
            url: URL do alvo a ser escaneado
            
        Returns:
            Lista de vulnerabilidades encontradas
        """
        vulnerabilities = []
        
        try:
            # Verifica rate limiting
            rate_limit_vulns = self._check_login_rate_limit(url)
            if rate_limit_vulns:
                vulnerabilities.extend(rate_limit_vulns)
            
            # Verifica senhas fracas
            password_vulns = self._check_weak_passwords(url)
            if password_vulns:
                vulnerabilities.extend(password_vulns)
            
            # Verifica exposição de senhas
            exposure_vulns = self._check_password_exposure(url)
            if exposure_vulns:
                vulnerabilities.extend(exposure_vulns)
            
            # Verifica segurança das sessões
            session_vulns = self._check_secure_session(url)
            if session_vulns:
                vulnerabilities.extend(session_vulns)
            
            return vulnerabilities
            
        except Exception as e:
            print(f"Erro ao executar scan de autenticação: {str(e)}")
            return [{
                'type': 'Authentication Failure',
                'subtype': 'Scan Error',
                'url': url,
                'severity': 'Unknown',
                'description': f'Erro ao executar scan: {str(e)}',
                'recommendation': 'Verificar configuração do servidor e tentar novamente.'
            }]

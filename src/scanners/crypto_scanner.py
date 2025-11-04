"""
Scanner para detecção de falhas criptográficas (A2:2021).
"""

import ssl
import socket
from typing import List, Dict, Any
from urllib.parse import urlparse
from .base_scanner import BaseScanner
from utils.http_utils import make_request

class CryptoScanner(BaseScanner):
    def __init__(self):
        super().__init__()
        self.weak_ciphers = [
            'TLS_RSA_WITH_RC4_128_SHA',
            'TLS_RSA_WITH_RC4_128_MD5',
            'TLS_RSA_WITH_3DES_EDE_CBC_SHA',
        ]
        
    def _check_ssl_tls(self, url):
        """Verifica se o site usa HTTPS e valida o certificado SSL/TLS."""
        parsed = urlparse(url)
        if parsed.scheme != 'https':
            return {
                'type': 'Cryptographic Failure',
                'subtype': 'Missing HTTPS',
                'url': url,
                'severity': 'High',
                'description': 'O site não utiliza HTTPS, o que pode permitir interceptação de dados.',
                'recommendation': 'Implementar HTTPS em todo o site.'
            }
        
        try:
            hostname = parsed.hostname
            context = ssl.create_default_context()
            with socket.create_connection((hostname, 443)) as sock:
                with context.wrap_socket(sock, server_hostname=hostname) as ssock:
                    cert = ssock.getpeercert()
                    cipher = ssock.cipher()
                    
                    vulnerabilities = []
                    
                    # Verifica versão do protocolo
                    if ssl.PROTOCOL_TLSv1_2 > ssock.version():
                        vulnerabilities.append({
                            'type': 'Cryptographic Failure',
                            'subtype': 'Weak Protocol Version',
                            'url': url,
                            'severity': 'High',
                            'details': f'Versão TLS detectada: {ssock.version()}',
                            'recommendation': 'Atualizar para TLS 1.2 ou superior.'
                        })
                    
                    # Verifica cifras fracas
                    if cipher[0] in self.weak_ciphers:
                        vulnerabilities.append({
                            'type': 'Cryptographic Failure',
                            'subtype': 'Weak Cipher',
                            'url': url,
                            'severity': 'Medium',
                            'details': f'Cifra fraca detectada: {cipher[0]}',
                            'recommendation': 'Desabilitar cifras criptográficas antigas e fracas.'
                        })
                    
                    # Verifica validade do certificado
                    if not cert:
                        vulnerabilities.append({
                            'type': 'Cryptographic Failure',
                            'subtype': 'Invalid Certificate',
                            'url': url,
                            'severity': 'High',
                            'description': 'Certificado SSL/TLS inválido ou auto-assinado.',
                            'recommendation': 'Usar certificado SSL/TLS válido de uma CA confiável.'
                        })
                    
                    return vulnerabilities
                    
        except (socket.gaierror, socket.error, ssl.SSLError) as e:
            return [{
                'type': 'Cryptographic Failure',
                'subtype': 'SSL/TLS Error',
                'url': url,
                'severity': 'High',
                'description': f'Erro na verificação SSL/TLS: {str(e)}',
                'recommendation': 'Verificar configuração SSL/TLS do servidor.'
            }]
    
    def _check_security_headers(self, url):
        """Verifica headers de segurança relacionados à criptografia."""
        response = make_request(url)
        if not response:
            return []
        
        vulnerabilities = []
        headers = response.headers
        
        # Verifica HSTS
        if 'Strict-Transport-Security' not in headers:
            vulnerabilities.append({
                'type': 'Cryptographic Failure',
                'subtype': 'Missing HSTS',
                'url': url,
                'severity': 'Medium',
                'description': 'Header HSTS não encontrado.',
                'recommendation': 'Implementar Strict Transport Security (HSTS).'
            })
        
        # Verifica Content Security Policy
        if 'Content-Security-Policy' not in headers:
            vulnerabilities.append({
                'type': 'Cryptographic Failure',
                'subtype': 'Missing CSP',
                'url': url,
                'severity': 'Medium',
                'description': 'Content Security Policy não encontrada.',
                'recommendation': 'Implementar Content Security Policy.'
            })
        
        return vulnerabilities
    
    def scan(self, url: str) -> List[Dict[str, Any]]:
        """
        Executa verificações de segurança criptográfica.
        
        Args:
            url: URL do alvo a ser escaneado
            
        Returns:
            Lista de vulnerabilidades encontradas
        """
        vulnerabilities = []
        
        try:
            # Verifica SSL/TLS
            ssl_vulns = self._check_ssl_tls(url)
            if isinstance(ssl_vulns, dict):  # caso de falta de HTTPS
                vulnerabilities.append(ssl_vulns)
            elif isinstance(ssl_vulns, list):  # outros problemas SSL/TLS
                vulnerabilities.extend(ssl_vulns)
            
            # Verifica headers de segurança
            header_vulns = self._check_security_headers(url)
            if header_vulns:
                vulnerabilities.extend(header_vulns)
            
            return vulnerabilities
            
        except Exception as e:
            print(f"Erro ao executar scan criptográfico: {str(e)}")
            return [{
                'type': 'Cryptographic Failure',
                'subtype': 'Scan Error',
                'url': url,
                'severity': 'Unknown',
                'description': f'Erro ao executar scan: {str(e)}',
                'recommendation': 'Verificar configuração do servidor e tentar novamente.'
            }]

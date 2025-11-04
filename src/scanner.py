#!/usr/bin/env python3

"""
Scanner module for detecting web application vulnerabilities.
"""

import time
from typing import List, Dict, Any, Optional
from urllib.parse import parse_qs, urlencode, urlparse, urlunparse
from utils.http_utils import validate_url, make_request
from utils.payloads import XSS_PAYLOADS, SQLI_PAYLOADS, SQL_ERROR_PATTERNS
from utils.diagnostics import ScannerDiagnostics
from scanners.crypto_scanner import CryptoScanner
from scanners.auth_scanner import AuthScanner

class Scanner:
    def __init__(self):
        self.vulnerabilities = []
        self.crypto_scanner = CryptoScanner()
        self.auth_scanner = AuthScanner()
        self.diagnostics = ScannerDiagnostics()
        
    def scan(self, url: str, scan_types: List[str] = None, scan_mode: str = 'fast') -> dict:
        """
        Executa o scan de vulnerabilidades no alvo especificado.
        
        Args:
            url: URL do alvo a ser escaneado
            scan_types: Lista de tipos de scan a serem executados (xss, sqli, etc)
            scan_mode: Modo de scan (fast ou deep)
            
        Returns:
            Dicionário com os resultados do scan
        """
        
        if not scan_types:
            scan_types = ['all']
            
        vulnerabilities = []
        scan_id = self.diagnostics.start_scan(url, scan_types)
        start_time = time.time()
        success = True
        
        try:
            # Valida URL
            if not url.startswith(('http://', 'https://')):
                raise ValueError('URL inválida. Use http:// ou https://')
            
            # Executa os scans conforme configuração
            if 'all' in scan_types or 'xss' in scan_types:
                module_start = time.time()
                try:
                    xss_vulns = self._scan_xss(url)
                    if xss_vulns:
                        vulnerabilities.extend(xss_vulns)
                    self.diagnostics.log_module_result(
                        scan_id, 'xss', True, time.time() - module_start
                    )
                except Exception as e:
                    self.diagnostics.log_module_result(
                        scan_id, 'xss', False, time.time() - module_start, str(e)
                    )
                    success = False
            
            if 'all' in scan_types or 'sqli' in scan_types:
                module_start = time.time()
                try:
                    sqli_vulns = self._scan_sqli(url)
                    if sqli_vulns:
                        vulnerabilities.extend(sqli_vulns)
                    self.diagnostics.log_module_result(
                        scan_id, 'sqli', True, time.time() - module_start
                    )
                except Exception as e:
                    self.diagnostics.log_module_result(
                        scan_id, 'sqli', False, time.time() - module_start, str(e)
                    )
                    success = False
            
            if 'all' in scan_types or 'crypto' in scan_types:
                module_start = time.time()
                try:
                    crypto_vulns = self.crypto_scanner.scan(url)
                    if crypto_vulns:
                        if isinstance(crypto_vulns, list):
                            vulnerabilities.extend(crypto_vulns)
                        else:
                            vulnerabilities.append(crypto_vulns)
                    self.diagnostics.log_module_result(
                        scan_id, 'crypto', True, time.time() - module_start
                    )
                except Exception as e:
                    self.diagnostics.log_module_result(
                        scan_id, 'crypto', False, time.time() - module_start, str(e)
                    )
                    success = False
            
            if 'all' in scan_types or 'auth' in scan_types:
                module_start = time.time()
                try:
                    auth_vulns = self.auth_scanner.scan(url)
                    if auth_vulns:
                        vulnerabilities.extend(auth_vulns)
                    self.diagnostics.log_module_result(
                        scan_id, 'auth', True, time.time() - module_start
                    )
                except Exception as e:
                    self.diagnostics.log_module_result(
                        scan_id, 'auth', False, time.time() - module_start, str(e)
                    )
                    success = False
            
            end_time = time.time()
            scan_duration = end_time - start_time
            
            # Finaliza diagnóstico
            stats = self.diagnostics.finish_scan(scan_id, success, len(vulnerabilities))
            
            # Analisa performance
            performance = self.diagnostics.analyze_performance(stats)
            
            return {
                'url': url,
                'vulnerabilities': vulnerabilities,
                'scan_time': scan_duration,
                'scan_types': scan_types,
                'scan_mode': scan_mode,
                'total_vulns': len(vulnerabilities),
                'performance': performance,
                'success': success
            }
            
        except Exception as e:
            end_time = time.time()
            # Finaliza diagnóstico com erro
            self.diagnostics.finish_scan(scan_id, False, 0)
            
            return {
                'url': url,
                'error': str(e),
                'vulnerabilities': [],
                'scan_time': end_time - start_time,
                'scan_types': scan_types,
                'scan_mode': scan_mode,
                'total_vulns': 0,
                'success': False
            }
    
    def _get_injectable_urls(self, url):
        """
        Gera URLs com diferentes pontos de injeção baseados na URL original.
        
        Args:
            url (str): URL original
            
        Returns:
            list: Lista de tuplas (url, método, dados) para teste
        """
        parsed = urlparse(url)
        
        # Lista para armazenar pontos de injeção
        injectable_points = []
        
        # Verifica parâmetros GET
        if parsed.query:
            params = parse_qs(parsed.query)
            for param in params:
                # Cria uma cópia dos parâmetros para modificar
                new_params = params.copy()
                # Marca o parâmetro para injeção
                new_params[param] = ['{PAYLOAD}']
                # Reconstrói a query string
                new_query = urlencode(new_params, doseq=True)
                # Reconstrói a URL
                new_url = urlunparse((
                    parsed.scheme,
                    parsed.netloc,
                    parsed.path,
                    parsed.params,
                    new_query,
                    parsed.fragment
                ))
                injectable_points.append((new_url, 'GET', None))
        
        # Adiciona um teste POST básico
        injectable_points.append((url, 'POST', {'test': '{PAYLOAD}'}))
        
        return injectable_points
    
    def _scan_xss(self, url):
        """
        Executa scan de XSS na URL fornecida.
        
        Args:
            url (str): URL para verificar
            
        Returns:
            list: Lista de vulnerabilidades XSS encontradas
        """
        vulnerabilities = []
        
        # Teste via GET parameter
        for payload in XSS_PAYLOADS:
            test_url = f"{url}?message={payload}"
            response = make_request(test_url, method='GET')
            if response and payload in response.text:
                vulnerabilities.append({
                    'type': 'XSS',
                    'subtype': 'Reflected XSS',
                    'url': test_url,
                    'severity': 'High',
                    'description': f'Possível XSS refletido detectado via parâmetro GET "message"',
                    'evidence': f'URL: {test_url}\nPayload: {payload}',
                    'recommendation': 'Sanitize todos os inputs e aplique encoding apropriado no output'
                })
        
        # Teste via POST parameter
        for payload in XSS_PAYLOADS:
            response = make_request(url, method='POST', data={'message': payload})
            if response and payload in response.text:
                vulnerabilities.append({
                    'type': 'XSS',
                    'subtype': 'Stored XSS',
                    'url': url,
                    'severity': 'High',
                    'description': f'Possível XSS armazenado detectado via POST em "message"',
                    'evidence': f'URL: {url}\nPayload: {payload}\nMétodo: POST',
                    'recommendation': 'Sanitize todos os inputs e aplique encoding apropriado no output'
                })
        
        return vulnerabilities
    
    def _scan_sqli(self, url):
        """
        Executa scan de SQL Injection na URL fornecida.
        
        Args:
            url (str): URL para verificar
            
        Returns:
            list: Lista de vulnerabilidades SQL Injection encontradas
        """
        vulnerabilities = []
        login_url = f"{url}/login"
        
        # Teste de SQL Injection no formulário de login
        for payload in SQLI_PAYLOADS:
            # Teste no campo username
            response = make_request(
                login_url, 
                method='POST',
                data={'username': payload, 'password': 'test123'}
            )
            
            if response:
                for pattern in SQL_ERROR_PATTERNS:
                    if pattern in response.text:
                        vulnerabilities.append({
                            'type': 'SQL Injection',
                            'subtype': 'Error-based SQLi',
                            'url': login_url,
                            'severity': 'High',
                            'description': f'SQL Injection detectada no campo username do formulário de login',
                            'evidence': f'URL: {login_url}\nPayload: {payload}\nErro SQL encontrado: {pattern}',
                            'recommendation': 'Use prepared statements ou ORM e implemente validação adequada de input'
                        })
                        break
            
            # Teste no campo password
            response = make_request(
                login_url,
                method='POST',
                data={'username': 'test', 'password': payload}
            )
            
            if response:
                for pattern in SQL_ERROR_PATTERNS:
                    if pattern in response.text:
                        vulnerabilities.append({
                            'type': 'SQL Injection',
                            'subtype': 'Error-based SQLi',
                            'url': login_url,
                            'severity': 'High',
                            'description': f'SQL Injection detectada no campo password do formulário de login',
                            'evidence': f'URL: {login_url}\nPayload: {payload}\nErro SQL encontrado: {pattern}',
                            'recommendation': 'Use prepared statements ou ORM e implemente validação adequada de input'
                        })
                        break
        
        return vulnerabilities

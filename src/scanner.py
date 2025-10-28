#!/usr/bin/env python3

"""
Scanner module for detecting web application vulnerabilities.
"""

import time
from urllib.parse import parse_qs, urlencode, urlparse, urlunparse
from utils.http_utils import validate_url, make_request
from utils.payloads import XSS_PAYLOADS, SQLI_PAYLOADS, SQL_ERROR_PATTERNS

class Scanner:
    def __init__(self):
        self.vulnerabilities = []
        
    def scan(self, url, scan_types='all', scan_mode='normal'):
        """
        Executa o scan de segurança na URL fornecida.
        
        Args:
            url (str): URL alvo para scan
            scan_types (str/set): Tipos de scan a executar ('all', 'xss', 'sqli')
            scan_mode (str): Modo de execução ('normal', 'quiet')
            
        Returns:
            dict: Resultados do scan
        """
        if not validate_url(url):
            return {
                'url': url,
                'error': 'URL inválida',
                'vulnerabilities': [],
                'scan_time': None,
                'scan_types': scan_types,
                'scan_mode': scan_mode
            }
        
        start_time = time.time()
        
        # Lista para armazenar vulnerabilidades encontradas
        vulnerabilities = []
        
        # Converte scan_types para set se for string
        if isinstance(scan_types, str):
            scan_types = {scan_types}
        
        # Executa os scans conforme configuração
        if 'all' in scan_types or 'xss' in scan_types:
            xss_vulns = self._scan_xss(url)
            vulnerabilities.extend(xss_vulns)
            
        if 'all' in scan_types or 'sqli' in scan_types:
            sqli_vulns = self._scan_sqli(url)
            vulnerabilities.extend(sqli_vulns)
        
        end_time = time.time()
        
        return {
            'url': url,
            'vulnerabilities': vulnerabilities,
            'scan_time': end_time - start_time,
            'scan_types': scan_types,
            'scan_mode': scan_mode
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
                    'url': test_url,
                    'method': 'GET',
                    'payload': payload,
                    'param': 'message',
                    'severity': 'High'
                })
        
        # Teste via POST parameter
        for payload in XSS_PAYLOADS:
            response = make_request(url, method='POST', data={'message': payload})
            if response and payload in response.text:
                vulnerabilities.append({
                    'type': 'XSS',
                    'url': url,
                    'method': 'POST',
                    'payload': payload,
                    'param': 'message',
                    'severity': 'High'
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
                            'url': login_url,
                            'method': 'POST',
                            'payload': payload,
                            'param': 'username',
                            'pattern_matched': pattern,
                            'severity': 'High'
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
                            'url': login_url,
                            'method': 'POST',
                            'payload': payload,
                            'param': 'password',
                            'pattern_matched': pattern,
                            'severity': 'High'
                        })
                        break
        
        return vulnerabilities

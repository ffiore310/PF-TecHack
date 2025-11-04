"""
Testes para os scanners especializados.
"""

import unittest
from unittest.mock import patch, MagicMock
from scanners.auth_scanner import AuthScanner
from scanners.crypto_scanner import CryptoScanner

class TestAuthScanner(unittest.TestCase):
    def setUp(self):
        self.scanner = AuthScanner()
        
    @patch('scanners.auth_scanner.make_request')
    def test_check_login_rate_limit(self, mock_request):
        """Testa detecção de rate limiting."""
        # Simula resposta sem rate limit
        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_request.return_value = mock_response
        
        vulns = self.scanner._check_login_rate_limit("http://example.com")
        self.assertEqual(len(vulns), 1)
        self.assertEqual(vulns[0]['subtype'], 'No Rate Limiting')
        
        # Simula resposta com rate limit
        mock_response.status_code = 429
        vulns = self.scanner._check_login_rate_limit("http://example.com")
        self.assertEqual(len(vulns), 0)
        
    @patch('scanners.auth_scanner.make_request')
    def test_check_weak_passwords(self, mock_request):
        """Testa detecção de senhas fracas."""
        # Simula aceitação de senha fraca
        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_request.return_value = mock_response
        
        vulns = self.scanner._check_weak_passwords("http://example.com")
        self.assertEqual(len(vulns), 1)
        self.assertEqual(vulns[0]['subtype'], 'Weak Password Policy')
        
class TestCryptoScanner(unittest.TestCase):
    def setUp(self):
        self.scanner = CryptoScanner()
        
    def test_check_ssl_tls(self):
        """Testa verificação SSL/TLS."""
        # Testa URL sem HTTPS
        vulns = self.scanner._check_ssl_tls("http://example.com")
        self.assertEqual(vulns['subtype'], 'Missing HTTPS')
        
    @patch('scanners.crypto_scanner.make_request')
    def test_check_security_headers(self, mock_request):
        """Testa verificação de headers de segurança."""
        # Simula resposta sem headers de segurança
        mock_response = MagicMock()
        mock_response.headers = {}
        mock_request.return_value = mock_response
        
        vulns = self.scanner._check_security_headers("http://example.com")
        self.assertEqual(len(vulns), 2)  # HSTS e CSP ausentes
        self.assertTrue(
            any(v['subtype'] == 'Missing HSTS' for v in vulns)
        )
        self.assertTrue(
            any(v['subtype'] == 'Missing CSP' for v in vulns)
        )
        
        # Simula resposta com headers corretos
        mock_response.headers = {
            'Strict-Transport-Security': 'max-age=31536000',
            'Content-Security-Policy': "default-src 'self'"
        }
        vulns = self.scanner._check_security_headers("http://example.com")
        self.assertEqual(len(vulns), 0)
        
if __name__ == '__main__':
    unittest.main()

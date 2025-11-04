"""
Testes integrados do scanner principal.
"""

import unittest
from unittest.mock import patch, MagicMock
import time
from scanner import Scanner

class TestScanner(unittest.TestCase):
    def setUp(self):
        self.scanner = Scanner()
        
    def test_scanner_initialization(self):
        """Testa inicialização do scanner."""
        self.assertIsNotNone(self.scanner.crypto_scanner)
        self.assertIsNotNone(self.scanner.auth_scanner)
        self.assertIsNotNone(self.scanner.diagnostics)
        
    def test_invalid_url(self):
        """Testa validação de URL."""
        result = self.scanner.scan("invalid_url")
        self.assertFalse(result['success'])
        self.assertIn('error', result)
        self.assertEqual(result['total_vulns'], 0)
        
    @patch('scanner.Scanner._scan_xss')
    @patch('scanner.Scanner._scan_sqli')
    def test_scan_types(self, mock_sqli, mock_xss):
        """Testa execução seletiva de tipos de scan."""
        url = "http://example.com"
        
        # Configura mocks
        mock_xss.return_value = [{'type': 'XSS', 'severity': 'High'}]
        mock_sqli.return_value = [{'type': 'SQLi', 'severity': 'High'}]
        
        # Testa scan específico XSS
        result = self.scanner.scan(url, scan_types=['xss'])
        self.assertTrue(result['success'])
        mock_xss.assert_called_once()
        mock_sqli.assert_not_called()
        
        # Reset mocks
        mock_xss.reset_mock()
        mock_sqli.reset_mock()
        
        # Testa scan 'all'
        result = self.scanner.scan(url, scan_types=['all'])
        self.assertTrue(result['success'])
        mock_xss.assert_called_once()
        mock_sqli.assert_called_once()
        
    def test_performance_tracking(self):
        """Testa tracking de performance."""
        url = "http://example.com"
        
        # Patch de todos os métodos de scan para simular execução
        with patch.multiple(
            self.scanner,
            _scan_xss=MagicMock(return_value=[]),
            _scan_sqli=MagicMock(return_value=[])
        ):
            result = self.scanner.scan(url)
            
            # Verifica se informações de performance estão presentes
            self.assertIn('performance', result)
            self.assertIn('scan_time', result)
            self.assertTrue(isinstance(result['scan_time'], float))
            
    def test_error_handling(self):
        """Testa tratamento de erros durante scan."""
        url = "http://example.com"
        
        # Simula erro em um módulo
        with patch('scanner.Scanner._scan_xss') as mock_xss:
            mock_xss.side_effect = Exception("Erro simulado")
            
            result = self.scanner.scan(url, scan_types=['xss'])
            
            # Verifica resultado
            self.assertFalse(result['success'])
            self.assertEqual(result['total_vulns'], 0)
            self.assertGreater(result['scan_time'], 0)
            
    def test_scan_mode(self):
        """Testa diferentes modos de scan."""
        url = "http://example.com"
        
        # Testa modo rápido
        result_fast = self.scanner.scan(url, scan_mode='fast')
        time_fast = result_fast['scan_time']
        
        # Testa modo profundo
        result_deep = self.scanner.scan(url, scan_mode='deep')
        time_deep = result_deep['scan_time']
        
        # No modo deep, o scan deve levar mais tempo
        self.assertGreater(time_deep, time_fast)
        
if __name__ == '__main__':
    unittest.main()

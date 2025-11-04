"""
Testes para o módulo de diagnóstico do scanner.
"""

import unittest
import time
from utils.diagnostics import ScannerDiagnostics

class TestScannerDiagnostics(unittest.TestCase):
    def setUp(self):
        self.diagnostics = ScannerDiagnostics()
        
    def test_start_scan(self):
        """Testa o início do monitoramento de scan."""
        url = "http://example.com"
        scan_types = ['all']
        
        scan_id = self.diagnostics.start_scan(url, scan_types)
        self.assertIn(scan_id, self.diagnostics.scan_stats)
        self.assertEqual(self.diagnostics.scan_stats[scan_id]['url'], url)
        self.assertEqual(self.diagnostics.scan_stats[scan_id]['status'], 'running')
        
    def test_log_module_result(self):
        """Testa o registro de resultado de um módulo."""
        url = "http://example.com"
        scan_types = ['all']
        scan_id = self.diagnostics.start_scan(url, scan_types)
        
        # Testa módulo com sucesso
        self.diagnostics.log_module_result(
            scan_id, 'auth', True, 1.5
        )
        self.assertEqual(
            self.diagnostics.scan_stats[scan_id]['modules']['auth']['status'],
            'completed'
        )
        self.assertEqual(
            self.diagnostics.scan_stats[scan_id]['modules']['auth']['duration'],
            1.5
        )
        
        # Testa módulo com erro
        self.diagnostics.log_module_result(
            scan_id, 'crypto', False, 0.5, "Test error"
        )
        self.assertEqual(
            self.diagnostics.scan_stats[scan_id]['modules']['crypto']['status'],
            'error'
        )
        self.assertEqual(len(self.diagnostics.error_log), 1)
        
    def test_finish_scan(self):
        """Testa a finalização do monitoramento de scan."""
        url = "http://example.com"
        scan_types = ['all']
        scan_id = self.diagnostics.start_scan(url, scan_types)
        
        # Simula alguns módulos
        self.diagnostics.log_module_result(scan_id, 'auth', True, 1.0)
        self.diagnostics.log_module_result(scan_id, 'crypto', True, 2.0)
        
        # Finaliza scan
        stats = self.diagnostics.finish_scan(scan_id, True, 5)
        self.assertEqual(stats['status'], 'completed')
        self.assertEqual(stats['total_vulnerabilities'], 5)
        self.assertGreater(stats['duration'], 0)
        
    def test_analyze_performance(self):
        """Testa a análise de performance."""
        # Cria estatísticas simuladas
        stats = {
            'duration': 10.0,
            'modules': {
                'auth': {'duration': 2.0},
                'crypto': {'duration': 5.0},
                'xss': {'duration': 1.0},
                'sqli': {'duration': 2.0}
            }
        }
        
        analysis = self.diagnostics.analyze_performance(stats)
        
        # Verifica se identificou gargalo (crypto > 40%)
        self.assertIn('crypto', analysis['bottlenecks'])
        self.assertEqual(
            analysis['modules_performance']['crypto']['percentage'],
            50.0
        )
        
if __name__ == '__main__':
    unittest.main()

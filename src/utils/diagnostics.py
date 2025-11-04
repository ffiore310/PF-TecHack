"""
Utilitários para diagnóstico e debug do scanner.
"""

from typing import Dict, List, Any, Optional
import time
import json
import logging

# Configuração do logger
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)

logger = logging.getLogger('scanner_diagnostics')

class ScannerDiagnostics:
    """Classe para diagnóstico e monitoramento do scanner."""
    
    def __init__(self):
        self.scan_stats = {}
        self.error_log = []
        
    def start_scan(self, url: str, scan_types: List[str]) -> None:
        """
        Inicia o monitoramento de um scan.
        
        Args:
            url: URL sendo escaneada
            scan_types: Lista de tipos de scan ativos
        """
        scan_id = str(time.time())
        self.scan_stats[scan_id] = {
            'url': url,
            'scan_types': scan_types,
            'start_time': time.time(),
            'status': 'running',
            'modules': {
                'auth': {'status': 'pending', 'duration': None},
                'crypto': {'status': 'pending', 'duration': None},
                'xss': {'status': 'pending', 'duration': None},
                'sqli': {'status': 'pending', 'duration': None}
            }
        }
        logger.info(f"Iniciando scan {scan_id} para {url}")
        return scan_id
        
    def log_module_result(self, scan_id: str, module: str, success: bool,
                         duration: float, error: Optional[str] = None) -> None:
        """
        Registra o resultado de um módulo de scan.
        
        Args:
            scan_id: ID do scan
            module: Nome do módulo (auth, crypto, etc)
            success: Se o módulo completou com sucesso
            duration: Duração da execução em segundos
            error: Mensagem de erro se houver falha
        """
        if scan_id in self.scan_stats:
            self.scan_stats[scan_id]['modules'][module] = {
                'status': 'completed' if success else 'error',
                'duration': duration,
                'error': error
            }
            
            if not success:
                self.error_log.append({
                    'scan_id': scan_id,
                    'module': module,
                    'error': error,
                    'timestamp': time.time()
                })
                logger.error(f"Erro no módulo {module}: {error}")
                
    def finish_scan(self, scan_id: str, success: bool,
                   total_vulns: int) -> Dict[str, Any]:
        """
        Finaliza o monitoramento de um scan.
        
        Args:
            scan_id: ID do scan
            success: Se o scan completou com sucesso
            total_vulns: Número total de vulnerabilidades encontradas
            
        Returns:
            Estatísticas do scan
        """
        if scan_id in self.scan_stats:
            end_time = time.time()
            stats = self.scan_stats[scan_id]
            stats['end_time'] = end_time
            stats['duration'] = end_time - stats['start_time']
            stats['status'] = 'completed' if success else 'error'
            stats['total_vulnerabilities'] = total_vulns
            
            logger.info(
                f"Scan {scan_id} finalizado em {stats['duration']:.2f}s "
                f"com {total_vulns} vulnerabilidades"
            )
            
            return stats
            
    def get_error_summary(self) -> List[Dict[str, Any]]:
        """
        Retorna um resumo dos erros registrados.
        
        Returns:
            Lista de erros com detalhes
        """
        return self.error_log
        
    def export_stats(self, filepath: str) -> None:
        """
        Exporta as estatísticas para um arquivo JSON.
        
        Args:
            filepath: Caminho do arquivo de saída
        """
        with open(filepath, 'w') as f:
            json.dump({
                'scan_stats': self.scan_stats,
                'error_log': self.error_log
            }, f, indent=2)
            
    @staticmethod
    def analyze_performance(stats: Dict[str, Any]) -> Dict[str, Any]:
        """
        Analisa o desempenho do scan.
        
        Args:
            stats: Estatísticas de um scan
            
        Returns:
            Análise de performance
        """
        analysis = {
            'total_duration': stats['duration'],
            'modules_performance': {},
            'bottlenecks': []
        }
        
        # Analisa tempo de cada módulo
        for module, data in stats['modules'].items():
            if data['duration']:
                analysis['modules_performance'][module] = {
                    'duration': data['duration'],
                    'percentage': (data['duration'] / stats['duration']) * 100
                }
                
                # Identifica gargalos (módulos que levam mais de 40% do tempo)
                if (data['duration'] / stats['duration']) > 0.4:
                    analysis['bottlenecks'].append(module)
                    
        return analysis

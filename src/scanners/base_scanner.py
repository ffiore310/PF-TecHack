"""
Módulo base para implementação de scanners específicos.
Define a interface e funcionalidades comuns para todos os scanners.
"""

from typing import List, Dict, Any, Optional
import time
import logging

# Configuração do logger
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)

class BaseScanner:
    """
    Classe base para todos os scanners específicos.
    Implementa funcionalidades comuns e define a interface.
    """
    
    def __init__(self):
        self.vulnerabilities = []
        self.logger = logging.getLogger(self.__class__.__name__)
        self.start_time = None
        self.end_time = None
    
    def scan(self, url: str) -> List[Dict[str, Any]]:
        """
        Método base para scanning. Deve ser implementado pelas classes filhas.
        
        Args:
            url: URL do alvo a ser escaneado
            
        Returns:
            Lista de vulnerabilidades encontradas
        """
        raise NotImplementedError("Método scan deve ser implementado pela classe filha")
    
    def _start_scan(self) -> None:
        """Marca o início do scan e reseta o estado."""
        self.start_time = time.time()
        self.vulnerabilities = []
        self.logger.info("Iniciando scan...")
    
    def _end_scan(self) -> float:
        """
        Marca o fim do scan e calcula duração.
        
        Returns:
            Duração do scan em segundos
        """
        self.end_time = time.time()
        duration = self.end_time - self.start_time
        self.logger.info(f"Scan finalizado em {duration:.2f}s")
        return duration
    
    def _add_vulnerability(self, vulnerability: Dict[str, Any]) -> None:
        """
        Adiciona uma vulnerabilidade à lista.
        
        Args:
            vulnerability: Dicionário com detalhes da vulnerabilidade
        """
        self.vulnerabilities.append(vulnerability)
        self.logger.info(
            f"Vulnerabilidade encontrada: {vulnerability.get('type')} - "
            f"{vulnerability.get('subtype')} ({vulnerability.get('severity')})"
        )
    
    def _validate_url(self, url: str) -> bool:
        """
        Valida formato da URL.
        
        Args:
            url: URL a ser validada
            
        Returns:
            True se URL é válida, False caso contrário
        """
        return url.startswith(('http://', 'https://'))

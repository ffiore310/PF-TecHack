"""
Utilitários para requests HTTP e manipulação de URLs.
"""

import requests
from urllib.parse import urlparse, urljoin

def validate_url(url):
    """
    Valida se a URL fornecida é válida.
    
    Args:
        url (str): URL para validar
        
    Returns:
        bool: True se a URL é válida, False caso contrário
    """
    try:
        result = urlparse(url)
        return all([result.scheme, result.netloc])
    except:
        return False

def make_request(url, method='GET', data=None, headers=None):
    """
    Realiza uma requisição HTTP.
    
    Args:
        url (str): URL alvo
        method (str): Método HTTP (GET, POST, etc)
        data (dict): Dados para enviar (opcional)
        headers (dict): Headers HTTP (opcional)
        
    Returns:
        requests.Response: Objeto de resposta
    """
    try:
        return requests.request(method, url, data=data, headers=headers)
    except requests.exceptions.RequestException as e:
        print(f"Erro ao fazer requisição: {e}")
        return None

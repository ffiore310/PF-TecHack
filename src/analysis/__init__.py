"""
Módulo de análise heurística e priorização de vulnerabilidades.
Implementa CVSS-based scoring, análise de attack chains e recomendações.
"""

from .risk_scorer import RiskScorer, Severity
from .heuristic_analyzer import HeuristicAnalyzer
from .recommendation_engine import RecommendationEngine

__all__ = [
    'RiskScorer',
    'Severity',
    'HeuristicAnalyzer',
    'RecommendationEngine'
]

"""
Static checks — fully KB-driven via kb_driven_checker.
No hardcoded rules in this file.
"""
from analysis.static_checks.kb_driven_checker import run_all_checks

__all__ = ["run_all_checks"]

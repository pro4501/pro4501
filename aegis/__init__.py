"""AEGIS — AI-assisted, scope-gated authorized penetration testing.

AEGIS drives standard reconnaissance and vulnerability-identification tools
with Claude, under a signed, enforced engagement scope, and produces a
professional Markdown report. It is for authorized assessments and lab use
only.
"""

from .agent import AegisAgent, AssessmentResult, Finding
from .executor import ALLOWED_TOOLS, Executor
from .reporting import ReportContext, build_report
from .scope import Authorization, Scope, ScopeError

__version__ = "0.1.0"

__all__ = [
    "AegisAgent",
    "AssessmentResult",
    "Finding",
    "Executor",
    "ALLOWED_TOOLS",
    "ReportContext",
    "build_report",
    "Authorization",
    "Scope",
    "ScopeError",
]

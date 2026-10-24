"""Pure advisory routing; this package has no dispatch capability."""
from .evaluator import evaluate_local, recommend_target

__all__ = ["evaluate_local", "recommend_target"]

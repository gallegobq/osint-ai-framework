"""Compatibility module for the original case terminology.

The domain now uses Investigation consistently; external code can migrate from
CaseRepository to InvestigationRepository without a silent behavior change.
"""

from app.repositories.investigation_repository import InvestigationRepository


CaseRepository = InvestigationRepository

__all__ = ["CaseRepository"]

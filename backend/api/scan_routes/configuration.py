"""HTTP bindings for scan configuration."""

from fastapi import APIRouter, Depends
from backend.auth import get_current_user
from backend.models import (
    FpReviewMethodCatalog,
    MiningEngineCatalog,
    ThreatAnalysisMethodCatalog,
    User,
)
from backend.report_routes import HistoricalReportRoute
from backend.scans import configuration as service

router = APIRouter(route_class=HistoricalReportRoute)


@router.get("/api/mining-engines", response_model=MiningEngineCatalog)
async def get_mining_engine_catalog(
    current_user: User = Depends(get_current_user),
) -> MiningEngineCatalog:
    'Return the mining engines shipped by this repository.'
    return await service.get_mining_engine_catalog(current_user=current_user)


@router.get("/api/fp-review-methods", response_model=FpReviewMethodCatalog)
async def get_fp_review_method_catalog(
    current_user: User = Depends(get_current_user),
) -> FpReviewMethodCatalog:
    'Return repository-owned false-positive review methods.'
    return await service.get_fp_review_method_catalog(current_user=current_user)


@router.get(
    "/api/threat-analysis-methods",
    response_model=ThreatAnalysisMethodCatalog,
)
async def get_threat_analysis_method_catalog(
    current_user: User = Depends(get_current_user),
) -> ThreatAnalysisMethodCatalog:
    'Return repository-owned threat-analysis methods.'
    return await service.get_threat_analysis_method_catalog(current_user=current_user)

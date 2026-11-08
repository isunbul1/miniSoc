"""API v1 router aggregator.

Includes all v1 sub-routers under the /api/v1 prefix.
"""

from fastapi import APIRouter

from app.api.v1.alerts import router as alerts_router
from app.api.v1.detection import router as detection_router
from app.api.v1.health import router as health_router
from app.api.v1.logs import router as logs_router
from app.api.v1.mitre import router as mitre_router
from app.api.v1.stats import router as stats_router

router = APIRouter(prefix="/api/v1")

router.include_router(health_router)
router.include_router(logs_router)
router.include_router(alerts_router)
router.include_router(mitre_router)
router.include_router(detection_router)
router.include_router(stats_router)

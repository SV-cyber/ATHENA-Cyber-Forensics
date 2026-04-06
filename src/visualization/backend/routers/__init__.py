from .alerts import router as alerts_router
from .detections import router as detections_router
from .events import router as events_router

__all__ = ["alerts_router", "detections_router", "events_router"]

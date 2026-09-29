import os
from contextlib import asynccontextmanager
from fastapi import FastAPI
from api.routes import router
from api.state import state
from detection.orchestrator import DetectionOrchestrator
import logging

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# Determine model directory
# Use a relative path from the project root assuming `models/baseline_random` or similar.
# In a real environment, this might be loaded from an environment variable.
MODEL_DIR = os.getenv("SIH_MODEL_DIR", "models/baseline")

@asynccontextmanager
async def lifespan(app: FastAPI):
    """
    Lifecycle manager for the FastAPI application.
    Initializes the orchestrator on startup.
    """
    logger.info("Initializing Phase 10 Detection API...")

    try:
        effective_model_dir = MODEL_DIR if os.path.isdir(MODEL_DIR) else None
        state.orchestrator = DetectionOrchestrator(
            model_dir=effective_model_dir, model_name="RandomForest")
        if effective_model_dir:
            logger.info(f"Orchestrator initialized with model from {MODEL_DIR}")
        else:
            logger.warning(f"Orchestrator running behavioral-only (no model at {MODEL_DIR})")
    except Exception as e:
        logger.error(f"Failed to initialize orchestrator: {e}")
        state.orchestrator = None

    yield

    logger.info("Shutting down Phase 10 Detection API...")

from fastapi.middleware.cors import CORSMiddleware

app = FastAPI(
    title="SIH 145 - Detection API Prototype",
    description="Real-time Phase 10 inference API for unidirectional network traffic.",
    version="1.0.0",
    lifespan=lifespan
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

app.include_router(router)

"""
HTTP API for the Network Security AI Agent.

Runs on the sensor machine next to the agent (it needs the same access the
agent does: packet capture and, for blocking, root). The web dashboard talks
to this API.

Run:
    python -m src.api                      # uses SOC_API_HOST / SOC_API_PORT
    uvicorn src.api:app --host 127.0.0.1   # or directly with uvicorn
"""

import hmac
import logging
import os
import tempfile
import threading
from contextlib import asynccontextmanager, contextmanager
from typing import Any, Dict, Iterator, List, Optional

from fastapi import APIRouter, Depends, FastAPI, File, HTTPException, Query, Request, UploadFile
from fastapi.middleware.cors import CORSMiddleware
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from pydantic import BaseModel

from src import __version__
from src.config import Settings, load_settings
from src.orchestrator import SOCAgent
from src.packet_capture import PcapReadError
from src.threat import ThreatLevel

logger = logging.getLogger(__name__)

UPLOAD_CHUNK_BYTES = 1024 * 1024


class IPRequest(BaseModel):
    ip: str


class AgentService:
    """
    Owns the SOCAgent and serializes work on it.

    SOCAgent is not thread-safe, and analysis/training are long-running, so
    only one runs at a time; a second request gets 409 instead of queueing
    behind it or corrupting shared state.
    """

    def __init__(self, soc: SOCAgent, settings: Settings):
        self.soc = soc
        self.settings = settings
        self._job_lock = threading.Lock()
        self.current_job: Optional[str] = None

    @contextmanager
    def exclusive(self, job: str) -> Iterator[None]:
        if not self._job_lock.acquire(blocking=False):
            raise HTTPException(
                status_code=409,
                detail=f"Agent is busy ({self.current_job}); try again when it finishes",
            )
        self.current_job = job
        try:
            yield
        finally:
            self.current_job = None
            self._job_lock.release()


def _save_upload(upload: UploadFile, max_bytes: int) -> str:
    """
    Stream an upload to a private temp file, enforcing a size limit.

    Returns:
        Path of the temp file (caller deletes it)

    Raises:
        HTTPException 413: If the upload exceeds max_bytes
    """
    fd, path = tempfile.mkstemp(prefix="soc-upload-", suffix=".pcap")  # 0600
    written = 0
    try:
        with os.fdopen(fd, "wb") as out:
            while chunk := upload.file.read(UPLOAD_CHUNK_BYTES):
                written += len(chunk)
                if written > max_bytes:
                    raise HTTPException(
                        status_code=413,
                        detail=f"Upload exceeds {max_bytes // (1024 * 1024)} MB limit",
                    )
                out.write(chunk)
    except BaseException:
        os.unlink(path)
        raise
    return path


@contextmanager
def _uploaded_pcap(upload: UploadFile, settings: Settings) -> Iterator[str]:
    """Save an upload to a temp file for the duration of the block."""
    path = _save_upload(upload, settings.max_upload_mb * 1024 * 1024)
    try:
        yield path
    finally:
        os.unlink(path)


def _model_info(soc: SOCAgent) -> Dict[str, Any]:
    agent = soc.detection_agent
    model = agent.ml_model
    return {
        "trained": model.is_fitted,
        "trained_at": model.trained_at,
        "training_samples": model.n_samples,
        "thresholds": {level.value: value for level, value in agent.thresholds.items()},
    }


def create_app(
    settings: Optional[Settings] = None,
    soc: Optional[SOCAgent] = None
) -> FastAPI:
    """
    Build the API app.

    Args:
        settings: Settings to use (loaded from the environment if None)
        soc: Pre-built agent (mainly for tests); built from settings if None

    Returns:
        FastAPI application
    """
    settings = settings or load_settings()
    settings.validate_api_security()

    @asynccontextmanager
    async def lifespan(app: FastAPI):
        agent = soc or SOCAgent.from_settings(settings)
        app.state.service = AgentService(agent, settings)
        yield

    app = FastAPI(
        title="Network Security AI Agent",
        version=__version__,
        lifespan=lifespan,
    )

    if settings.cors_origins or settings.cors_origin_regex:
        app.add_middleware(
            CORSMiddleware,
            allow_origins=settings.cors_origins,
            allow_origin_regex=settings.cors_origin_regex,
            allow_methods=["GET", "POST", "DELETE"],
            allow_headers=["Authorization", "Content-Type"],
            allow_credentials=False,  # bearer token, no cookies
            max_age=600,
        )

    bearer = HTTPBearer(auto_error=False)

    def require_api_key(
        request: Request,
        credentials: Optional[HTTPAuthorizationCredentials] = Depends(bearer),
    ) -> None:
        """
        Check `Authorization: Bearer <SOC_API_KEY>`.

        Without a configured key, only loopback clients are accepted. This
        also covers `uvicorn src.api:app --host 0.0.0.0`, which bypasses the
        SOC_API_HOST startup check.
        """
        if settings.api_key is None:
            client = request.client.host if request.client else ""
            # "testclient" is the placeholder host FastAPI's TestClient uses;
            # it can't come from a real socket
            if client not in ("127.0.0.1", "::1", "localhost", "testclient"):
                raise HTTPException(
                    status_code=403,
                    detail="API key required for remote access (set SOC_API_KEY)",
                )
            return
        supplied = credentials.credentials if credentials else ""
        # Constant-time comparison: don't leak key prefixes through timing
        if not hmac.compare_digest(supplied.encode(), settings.api_key.encode()):
            raise HTTPException(
                status_code=401,
                detail="Invalid or missing API key",
                headers={"WWW-Authenticate": "Bearer"},
            )

    api = APIRouter(dependencies=[Depends(require_api_key)])

    if settings.api_key is None:
        logger.warning(
            "SOC_API_KEY is not set: the API accepts unauthenticated requests "
            "(allowed only because it is bound to loopback)"
        )

    def service(request: Request) -> AgentService:
        return request.app.state.service

    # ---------------------------------------------------------------- status

    @app.get("/health")
    def health() -> Dict[str, str]:
        """Liveness check."""
        return {"status": "ok"}

    @api.get("/status")
    def status(request: Request) -> Dict[str, Any]:
        """Agent statistics, model state and (non-secret) settings."""
        svc = service(request)
        return {
            "version": __version__,
            "busy": svc.current_job,
            "stats": dict(svc.soc.stats),
            "model": _model_info(svc.soc),
            "settings": svc.settings.describe(),
        }

    # -------------------------------------------------------- analysis/train

    @api.post("/analyze")
    def analyze(
        request: Request,
        file: UploadFile = File(..., description="pcap or pcapng capture"),
        auto_block: Optional[bool] = Query(
            None, description="Block CRITICAL sources (default: SOC_AUTO_BLOCK_CRITICAL)"
        ),
    ) -> Dict[str, Any]:
        """Analyze an uploaded capture and return detections and responses."""
        svc = service(request)
        with svc.exclusive(f"analyzing {file.filename}"):
            with _uploaded_pcap(file, svc.settings) as path:
                try:
                    result = svc.soc.analyze_pcap(path, auto_block_critical=auto_block)
                except (PcapReadError, FileNotFoundError) as e:
                    raise HTTPException(status_code=400, detail=str(e).replace(path, file.filename or "upload"))
        result["file"] = file.filename
        result["model_trained"] = svc.soc.detection_agent.ml_model.is_fitted
        return result

    @api.post("/train")
    def train(
        request: Request,
        file: UploadFile = File(..., description="Capture of known-benign traffic"),
        save: bool = Query(True, description="Save the model to SOC_MODEL_PATH if set"),
    ) -> Dict[str, Any]:
        """Train the detection model on an uploaded benign capture."""
        svc = service(request)
        with svc.exclusive(f"training on {file.filename}"):
            with _uploaded_pcap(file, svc.settings) as path:
                try:
                    svc.soc.train_on_benign_traffic(path)
                except (PcapReadError, FileNotFoundError) as e:
                    raise HTTPException(status_code=400, detail=str(e).replace(path, file.filename or "upload"))
                except ValueError as e:
                    raise HTTPException(status_code=400, detail=str(e))

            if not svc.soc.detection_agent.ml_model.is_fitted:
                raise HTTPException(status_code=400, detail="No flows found in the capture")

            saved_to = None
            if save and svc.settings.model_path:
                svc.soc.save_model(svc.settings.model_path)
                saved_to = svc.settings.model_path

        return {"model": _model_info(svc.soc), "saved_to": saved_to}

    # ------------------------------------------------------------- history

    @api.get("/detections")
    def detections(
        request: Request,
        limit: int = Query(100, ge=1, le=10_000),
        min_level: str = Query("LOW", description="LOW, MEDIUM, HIGH or CRITICAL"),
        include_features: bool = Query(False),
    ) -> List[Dict[str, Any]]:
        """Most recent detections first, filtered by minimum threat level."""
        try:
            threshold = ThreatLevel.parse(min_level)
        except ValueError as e:
            raise HTTPException(status_code=422, detail=str(e))
        history = service(request).soc.detection_agent.detection_history
        matching = [d for d in reversed(history) if d.threat_level >= threshold]
        return [d.to_dict(include_features=include_features) for d in matching[:limit]]

    @api.delete("/detections")
    def clear_detections(request: Request) -> Dict[str, str]:
        """Clear detection history (does not unblock anything)."""
        svc = service(request)
        with svc.exclusive("clearing history"):
            svc.soc.detection_agent.clear_history()
        return {"status": "cleared"}

    @api.get("/responses")
    def responses(
        request: Request,
        limit: int = Query(100, ge=1, le=10_000),
    ) -> List[Dict[str, Any]]:
        """Most recent response actions first (blocks, alerts, logs)."""
        history = service(request).soc.response_agent.get_action_history()
        return list(reversed(history))[:limit]

    @api.get("/export")
    def export(request: Request) -> Dict[str, Any]:
        """Full export: stats, detections with features, responses, blocklist."""
        soc = service(request).soc
        return {
            "stats": dict(soc.stats),
            "detections": soc.detection_agent.get_alerts(),
            "responses": soc.response_agent.get_action_history(),
            "blocklist": soc.response_agent.get_blocklist(),
        }

    # ------------------------------------------------------------ blocklist

    @api.get("/blocklist")
    def blocklist(request: Request) -> Dict[str, Any]:
        svc = service(request)
        return {
            "ips": svc.soc.response_agent.get_blocklist(),
            "dry_run": svc.settings.dry_run,
        }

    def _record(svc: AgentService, action) -> Dict[str, Any]:
        """Keep manual actions in the response history for auditing."""
        svc.soc.response_agent.action_history.append(action)
        result = action.to_dict()
        if action.status == "FAILED":
            raise HTTPException(status_code=400, detail=result)
        return result

    @api.post("/blocklist")
    def block(request: Request, body: IPRequest) -> Dict[str, Any]:
        """Manually block an IP (respects dry-run and the allowlist)."""
        svc = service(request)
        action = svc.soc.response_agent.ip_blocker.block_ip(body.ip)
        action.details["source"] = "manual (API)"
        return _record(svc, action)

    @api.delete("/blocklist/{ip}")
    def unblock(request: Request, ip: str) -> Dict[str, Any]:
        """Remove an IP from the firewall and blocklist."""
        svc = service(request)
        action = svc.soc.response_agent.ip_blocker.unblock_ip(ip)
        action.details["source"] = "manual (API)"
        return _record(svc, action)

    app.include_router(api, prefix="/api")
    return app


def _app_from_env() -> FastAPI:
    settings = load_settings()
    logging.basicConfig(
        level=settings.log_level,
        format="%(asctime)s - %(name)s - %(levelname)s - %(message)s",
    )
    return create_app(settings)


# Module-level app for `uvicorn src.api:app`; built lazily so importing this
# module (e.g. in tests) doesn't load settings or start an agent.
def __getattr__(name: str) -> Any:
    if name == "app":
        global app
        app = _app_from_env()
        return app
    raise AttributeError(f"module {__name__!r} has no attribute {name!r}")


if __name__ == "__main__":
    import uvicorn

    settings = load_settings()
    uvicorn.run("src.api:app", host=settings.api_host, port=settings.api_port)

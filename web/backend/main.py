"""
Backend FastAPI mínimo de la web del TFG (Fase 2, modo IA OFF).

Sirve los datos locales de `web/data/` como API para el mapa mental interactivo:
detección explicativa de anomalías NetFlow (UGR'16) con LLMs + clasificador
contextual. Versión principal recomendada: v5 integrated; base estable: v3.

- No ejecuta el clasificador ni usa CSV grandes: solo lee JSON pequeños.
- Rutas robustas con pathlib (funciona desde la raíz del proyecto o desde web/backend).
- CORS habilitado para el frontend de desarrollo (Vite, puerto 5173).

Ejecución:
    cd web/backend
    pip install -r requirements.txt
    uvicorn main:app --reload
"""

import asyncio
import json
import logging
import os as _os
import sys
from contextlib import asynccontextmanager
from pathlib import Path

from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse, PlainTextResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel

import config  # carga web/backend/.env si existe (sin dependencias externas)
import simulator
from services import notebooklm_service
from services import classifier_service

logger = logging.getLogger("tfg.backend")

# ---------------------------------------------------------------------------
# Metadatos
# ---------------------------------------------------------------------------

API_VERSION = "1.0.0"
PROJECT_NAME = "Mapa mental del TFG: detección explicativa de anomalías NetFlow (UGR'16) con LLMs"
PRINCIPAL_CLASSIFIER = "v5 integrated"
BASE_CLASSIFIER = "v3"

DATA_DIR = Path(__file__).resolve().parent.parent / "data"
DIST_DIR = Path(__file__).resolve().parent.parent / "frontend" / "dist"
INDEX_FILE = DIST_DIR / "index.html"
ASSETS_DIR = DIST_DIR / "assets"
NOT_BUILT_MSG = "Frontend no compilado. Ejecuta: cd web/frontend && npm run build"

# Orígenes explícitos: desarrollo local + los que se añadan vía CORS_ORIGINS (CSV).
ALLOWED_ORIGINS = [
    "http://localhost:5173",
    "http://127.0.0.1:5173",
    *[o.strip() for o in _os.environ.get("CORS_ORIGINS", "").split(",") if o.strip()],
]

# Regex que cubre cualquier subdominio de Vercel (*.vercel.app) y el dominio
# personalizado si se configura en CORS_ORIGIN_REGEX.
_VERCEL_REGEX = r"https://[a-zA-Z0-9-]+(\.vercel\.app)$"
ALLOWED_ORIGIN_REGEX = _os.environ.get("CORS_ORIGIN_REGEX", _VERCEL_REGEX)

# Intervalo del keepalive de NotebookLM en segundos (por defecto 6 horas).
_NOTEBOOKLM_KEEPALIVE_INTERVAL = int(_os.environ.get("NOTEBOOKLM_KEEPALIVE_INTERVAL", "3600"))


# ---------------------------------------------------------------------------
# Tarea de fondo: keepalive periódico de NotebookLM
# ---------------------------------------------------------------------------

async def _notebooklm_keepalive_loop() -> None:
    """Hace una petición ligera a NotebookLM cada 6 horas para renovar las cookies
    de sesión sin necesidad de login interactivo.

    Ejecuta `notebooklm list` en headless: no abre ventana de navegador, solo
    usa las cookies guardadas en storage_state.json y las refresca si el servidor
    devuelve cookies nuevas.

    Solo arranca si NOTEBOOKLM_ENABLED=true y NOTEBOOKLM_AUTH_PATH está definido.
    """
    if not (config.env_bool("NOTEBOOKLM_ENABLED") and config.env_str("NOTEBOOKLM_AUTH_PATH")):
        logger.info("NotebookLM keepalive: desactivado (IA OFF o sin AUTH_PATH).")
        return

    logger.info("NotebookLM keepalive: activo, intervalo=%ds.", _NOTEBOOKLM_KEEPALIVE_INTERVAL)

    while True:
        await asyncio.sleep(_NOTEBOOKLM_KEEPALIVE_INTERVAL)
        logger.info("NotebookLM keepalive: refrescando cookies…")
        try:
            proc = await asyncio.create_subprocess_exec(
                sys.executable, "-m", "notebooklm", "auth", "refresh", "--quiet",
                stdout=asyncio.subprocess.DEVNULL,
                stderr=asyncio.subprocess.PIPE,
            )
            _, stderr = await asyncio.wait_for(proc.communicate(), timeout=120)
            if proc.returncode == 0:
                logger.info("NotebookLM keepalive: cookies renovadas correctamente.")
            else:
                logger.warning(
                    "NotebookLM keepalive: código %d — la sesión puede haber expirado. %s",
                    proc.returncode, stderr.decode().strip(),
                )
        except asyncio.TimeoutError:
            logger.error("NotebookLM keepalive: timeout (>120 s).")
        except Exception as exc:
            logger.error("NotebookLM keepalive: error inesperado: %s", exc)


# ---------------------------------------------------------------------------
# Lifespan: arranca la tarea de fondo al iniciar el servidor
# ---------------------------------------------------------------------------

@asynccontextmanager
async def lifespan(_: FastAPI):
    task = asyncio.create_task(_notebooklm_keepalive_loop())
    yield
    task.cancel()
    try:
        await task
    except asyncio.CancelledError:
        pass


# ---------------------------------------------------------------------------
# App
# ---------------------------------------------------------------------------

app = FastAPI(title=PROJECT_NAME, version=API_VERSION, lifespan=lifespan)

app.add_middleware(
    CORSMiddleware,
    allow_origins=ALLOWED_ORIGINS,
    allow_origin_regex=ALLOWED_ORIGIN_REGEX,
    allow_credentials=True,
    allow_methods=["GET", "POST", "OPTIONS"],
    allow_headers=["*"],
)


# ---------------------------------------------------------------------------
# Modelos del simulador
# ---------------------------------------------------------------------------

class SimulatorRequest(BaseModel):
    attack_id: str
    attack_flows: int = 50
    intensity: str = "media"                  # "baja" | "media" | "alta"
    include_context_background: bool = True
    mode: str = "offline"                     # "offline" | "notebooklm"


class ChatRequest(BaseModel):
    attack_id: str
    question: str


class ClassifierRunRequest(BaseModel):
    filename: str = "ventana.csv"
    csv_text: str


# ---------------------------------------------------------------------------
# Utilidad: carga robusta de JSON con manejo de errores
# ---------------------------------------------------------------------------

def load_json(filename: str):
    """Carga un JSON de web/data/ devolviendo errores HTTP claros."""
    path = DATA_DIR / filename
    if not path.exists():
        raise HTTPException(
            status_code=503,
            detail=f"Archivo de datos no encontrado: '{filename}' (esperado en {DATA_DIR}).",
        )
    try:
        with path.open("r", encoding="utf-8") as f:
            return json.load(f)
    except json.JSONDecodeError as exc:
        raise HTTPException(
            status_code=500,
            detail=f"JSON mal formado en '{filename}': {exc}",
        )
    except OSError as exc:
        raise HTTPException(
            status_code=500,
            detail=f"No se pudo leer '{filename}': {exc}",
        )


# ---------------------------------------------------------------------------
# Endpoints
# ---------------------------------------------------------------------------

@app.get("/api")
def api_index():
    """Índice de endpoints disponibles (antes en '/'; ahora '/' sirve la web React)."""
    return {
        "project": PROJECT_NAME,
        "api_version": API_VERSION,
        "endpoints": [
            "/api/health",
            "/api/summary",
            "/api/attacks",
            "/api/attacks/{attack_id}",
            "/api/ai/status",
            "/api/simulator/generate (POST)",
            "/api/notebooklm/chat (POST)",
            "/api/classifier/expected-columns",
            "/api/classifier/run (POST)",
        ],
    }


@app.get("/api/health")
def health():
    """Estado del servicio y versión del clasificador."""
    return {
        "status": "ok",
        "project": PROJECT_NAME,
        "classifier": PRINCIPAL_CLASSIFIER,
        "base_classifier": BASE_CLASSIFIER,
        "api_version": API_VERSION,
        "data_dir_found": DATA_DIR.exists(),
    }


@app.get("/api/summary")
def summary():
    """Resumen del proyecto (web/data/project_summary.json)."""
    return load_json("project_summary.json")


@app.get("/api/attacks")
def attacks():
    """Listado completo de ataques (web/data/attacks.json)."""
    return load_json("attacks.json")


@app.get("/api/attacks/{attack_id}")
def attack(attack_id: str):
    """Ficha de un ataque concreto por su id."""
    data = load_json("attacks.json")
    ataques = data.get("ataques", [])
    for a in ataques:
        if a.get("id") == attack_id:
            return a
    available = [a.get("id") for a in ataques]
    raise HTTPException(
        status_code=404,
        detail={
            "message": f"Ataque '{attack_id}' no encontrado.",
            "available_ids": available,
        },
    )


# ---------------------------------------------------------------------------
# Modo IA (NotebookLM) y simulador de ataques
# ---------------------------------------------------------------------------

@app.get("/api/ai/status")
def ai_status():
    """Indica si el modo IA ON (NotebookLM) está disponible y qué ataques tienen
    cuaderno configurado. No expone credenciales: solo banderas y un motivo legible.
    """
    st = notebooklm_service.status()
    return {
        "ia_on_available": st["available"],
        "base_ready": st["base_ready"],
        "package_installed": st["package_installed"],
        "configured_attacks": st["configured_attacks"],
        "missing_attacks": st["missing_attacks"],
        "reason": st["reason"],
        "supported_attacks": simulator.SUPPORTED_ATTACKS,
        "fallback_mode": "offline",
    }


@app.post("/api/simulator/generate")
def simulator_generate(req: SimulatorRequest):
    """Genera una VENTANA NetFlow *sintética* (5 background + N ataque + 5 background).

    - mode="offline": usa plantillas locales controladas (siempre disponible).
    - mode="notebooklm": usa el cuaderno NotebookLM ESPECÍFICO del ataque, que devuelve
      una descripción estructurada del patrón; el backend valida y genera las filas.
      Si ese ataque no tiene cuaderno o IA ON no está disponible, responde 503/502 con
      un mensaje claro para que el frontend ofrezca el modo IA OFF.
    """
    template = simulator.get_template(req.attack_id)
    if template is None:
        raise HTTPException(
            status_code=404,
            detail={
                "message": f"Ataque '{req.attack_id}' no soportado por el simulador.",
                "supported_attacks": simulator.SUPPORTED_ATTACKS,
            },
        )
    if req.intensity not in simulator.INTENSITY_FACTOR:
        raise HTTPException(status_code=422, detail="intensity debe ser 'baja', 'media' o 'alta'.")
    if req.mode not in ("offline", "notebooklm"):
        raise HTTPException(status_code=422, detail="mode debe ser 'offline' o 'notebooklm'.")

    attack_flows = simulator.clamp_num_flows(req.attack_flows)
    pattern_summary = template["pattern_summary"]
    signals = template["signals"]
    explanation = template["explanation_for_teacher"]
    override = None
    mode_used = "offline"
    notebook_used = False

    if req.mode == "notebooklm":
        params = {
            "attack_id": req.attack_id,
            "attack_flows": attack_flows,
            "intensity": req.intensity,
            "include_context_background": req.include_context_background,
        }
        try:
            payload = notebooklm_service.generate_pattern(req.attack_id, params)
            override = payload.get("generation_rules")
            pattern_summary = payload.get("pattern_summary", pattern_summary)
            signals = payload.get("signals", signals)
            explanation = payload.get("explanation_for_teacher", explanation)
            mode_used = "notebooklm"
            notebook_used = True
        except notebooklm_service.NotebookLMUnavailable as exc:
            raise HTTPException(status_code=503, detail={
                "message": "Modo IA ON (NotebookLM) no disponible para este ataque.",
                "reason": str(exc),
                "suggestion": "Usa el modo IA OFF (plantilla local) para continuar.",
                "fallback_mode": "offline",
            })
        except notebooklm_service.NotebookLMError as exc:
            raise HTTPException(status_code=502, detail={
                "message": "NotebookLM devolvió una respuesta no válida.",
                "reason": str(exc),
                "suggestion": "Usa el modo IA OFF (plantilla local) para continuar.",
                "fallback_mode": "offline",
            })

    try:
        rules = simulator.merge_and_validate_rules(template, override)
    except simulator.SimulatorError as exc:
        raise HTTPException(status_code=502, detail=f"Reglas de generación no válidas: {exc}")

    before = 5 if req.include_context_background else 0
    after = 5 if req.include_context_background else 0
    rows = simulator.generate_window(
        template, rules, attack_flows, req.intensity,
        req.include_context_background, before=5, after=5,
    )

    return {
        "mode_used": mode_used,
        "attack_id": req.attack_id,
        "notebook_used": notebook_used,
        "window_structure": {
            "background_before": before,
            "attack_flows": attack_flows,
            "background_after": after,
        },
        "pattern_summary": pattern_summary,
        "signals": signals,
        "explanation_for_teacher": explanation,
        "rows": rows,
        "summary": simulator.summarize(rows, rules),
        "columns": simulator.COLUMNS,
        "csv_preview": simulator.to_csv_preview(rows, limit=before + min(attack_flows, 10) + after),
        "synthetic_notice": (
            "Estos datos son sintéticos: sirven para explicar patrones. "
            "La validación real se hizo con UGR'16."
        ),
    }


@app.post("/api/notebooklm/chat")
def notebooklm_chat(req: ChatRequest):
    """Envía una pregunta al cuaderno NotebookLM específico del ataque (modo IA ON)."""
    if req.attack_id not in config.ATTACK_NOTEBOOK_ENV:
        raise HTTPException(status_code=404, detail={
            "message": f"Ataque '{req.attack_id}' no reconocido.",
            "supported_attacks": list(config.ATTACK_NOTEBOOK_ENV.keys()),
        })
    if not (req.question or "").strip():
        raise HTTPException(status_code=422, detail="La pregunta no puede estar vacía.")
    try:
        answer = notebooklm_service.chat(req.attack_id, req.question.strip())
    except notebooklm_service.NotebookLMUnavailable as exc:
        raise HTTPException(status_code=503, detail={
            "message": "Chat de NotebookLM no disponible para este ataque.",
            "reason": str(exc),
            "suggestion": "Activa IA ON y configura el cuaderno, o usa el modo IA OFF.",
            "notebook_configured": bool(config.notebook_id_for(req.attack_id)),
        })
    except notebooklm_service.NotebookLMError as exc:
        raise HTTPException(status_code=502, detail={
            "message": "NotebookLM no pudo responder.",
            "reason": str(exc),
        })
    return {
        "attack_id": req.attack_id,
        "answer": answer,
        "mode_used": "notebooklm",
        "notebook_configured": True,
    }


@app.get("/api/classifier/expected-columns")
def classifier_expected_columns():
    """Columnas esperadas para subir una ventana al clasificador v5 (wrapper web)."""
    return classifier_service.expected_columns()


@app.post("/api/classifier/run")
def classifier_run(req: ClassifierRunRequest):
    """Ejecuta el wrapper web del clasificador v5 sobre una ventana CSV pequeña (≤5 MB).

    Reutiliza la lógica científica de la v3 (importada) + override SSH de la v5. La
    validación científica completa está en los scripts de análisis, no aquí.
    """
    try:
        result = classifier_service.run(req.csv_text)
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=str(exc))
    return result


# ---------------------------------------------------------------------------
# Frontend compilado (Vite). Debe ir AL FINAL: las rutas /api/* de arriba tienen
# prioridad; el resto se sirve desde web/frontend/dist.
# ---------------------------------------------------------------------------

# Assets con cabeceras de estático (hash en el nombre -> cacheables).
if ASSETS_DIR.is_dir():
    app.mount("/assets", StaticFiles(directory=str(ASSETS_DIR)), name="assets")


@app.get("/")
def serve_root():
    """Sirve la web React compilada; si no está compilada, un mensaje claro."""
    if INDEX_FILE.is_file():
        return FileResponse(str(INDEX_FILE))
    return PlainTextResponse(NOT_BUILT_MSG, status_code=200)


@app.get("/{full_path:path}")
def spa_fallback(full_path: str):
    """Sirve archivos del build (favicon, etc.) y hace fallback a index.html.

    No interfiere con la API: cualquier ruta que empiece por 'api' devuelve 404
    (las rutas /api/* reales ya se han resuelto antes que este catch-all).
    """
    if full_path == "api" or full_path.startswith("api/"):
        raise HTTPException(status_code=404, detail="Not found")
    if not INDEX_FILE.is_file():
        return PlainTextResponse(NOT_BUILT_MSG, status_code=200)
    candidate = (DIST_DIR / full_path).resolve()
    if candidate.is_file() and DIST_DIR.resolve() in candidate.parents:
        return FileResponse(str(candidate))
    return FileResponse(str(INDEX_FILE))

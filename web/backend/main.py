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

import json
from pathlib import Path

from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel

import config  # carga web/backend/.env si existe (sin dependencias externas)
import simulator
from services import notebooklm_service
from services import classifier_service

# ---------------------------------------------------------------------------
# Metadatos
# ---------------------------------------------------------------------------

API_VERSION = "1.0.0"
PROJECT_NAME = "Mapa mental del TFG: detección explicativa de anomalías NetFlow (UGR'16) con LLMs"
PRINCIPAL_CLASSIFIER = "v5 integrated"
BASE_CLASSIFIER = "v3"

# Ruta a web/data/ resuelta respecto a ESTE archivo (no al directorio de trabajo),
# de modo que funcione tanto desde la raíz del proyecto como desde web/backend.
DATA_DIR = Path(__file__).resolve().parent.parent / "data"

# Orígenes permitidos para el frontend de desarrollo (Vite).
ALLOWED_ORIGINS = [
    "http://localhost:5173",
    "http://127.0.0.1:5173",
]

# ---------------------------------------------------------------------------
# App
# ---------------------------------------------------------------------------

app = FastAPI(title=PROJECT_NAME, version=API_VERSION)

app.add_middleware(
    CORSMiddleware,
    allow_origins=ALLOWED_ORIGINS,
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

@app.get("/")
def index():
    """Índice de endpoints disponibles."""
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

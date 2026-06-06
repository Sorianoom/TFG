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
    allow_methods=["GET"],
    allow_headers=["*"],
)


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

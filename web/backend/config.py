"""
Configuración del backend leída de variables de entorno.

Carga opcionalmente un archivo `web/backend/.env` (si existe) SIN depender de
librerías externas. El `.env` NO se versiona (contiene rutas a credenciales).
Nunca se guardan credenciales reales en el código.

Soporta un cuaderno de NotebookLM POR ATAQUE (no un único id global).
"""

import os
from pathlib import Path

_ENV_PATH = Path(__file__).resolve().parent / ".env"


def load_dotenv_if_present() -> None:
    """Carga pares CLAVE=VALOR de web/backend/.env en os.environ (sin sobrescribir)."""
    if not _ENV_PATH.exists():
        return
    try:
        for raw in _ENV_PATH.read_text(encoding="utf-8").splitlines():
            line = raw.strip()
            if not line or line.startswith("#") or "=" not in line:
                continue
            key, value = line.split("=", 1)
            os.environ.setdefault(key.strip(), value.strip().strip('"').strip("'"))
    except OSError:
        # Un .env ilegible no debe tumbar el backend.
        pass


def env_bool(name: str, default: bool = False) -> bool:
    val = os.getenv(name)
    if val is None:
        return default
    return val.strip().lower() in ("1", "true", "yes", "on", "si", "sí")


def env_str(name: str, default: str = "") -> str:
    return os.getenv(name, default)


# Mapa ataque -> variable de entorno con el id del cuaderno de NotebookLM.
ATTACK_NOTEBOOK_ENV = {
    "dos": "NOTEBOOKLM_DOS_ID",
    "scan11": "NOTEBOOKLM_SCAN11_ID",
    "scan44": "NOTEBOOKLM_SCAN44_ID",
    "anomaly-udpscan": "NOTEBOOKLM_UDPSCAN_ID",
    "nerisbotnet": "NOTEBOOKLM_NERISBOTNET_ID",
    "anomaly-sshscan": "NOTEBOOKLM_SSHSCAN_ID",
    "anomaly-spam": "NOTEBOOKLM_SPAM_ID",
}


def notebook_id_for(attack_id: str) -> str:
    """Id del cuaderno NotebookLM configurado para ese ataque ('' si no hay)."""
    return env_str(ATTACK_NOTEBOOK_ENV.get(attack_id, ""), "")


def notebook_map() -> dict:
    """{attack_id: True/False según tenga cuaderno configurado}."""
    return {aid: bool(notebook_id_for(aid)) for aid in ATTACK_NOTEBOOK_ENV}


# Cargar .env al importar.
load_dotenv_if_present()

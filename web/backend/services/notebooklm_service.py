"""
Servicio NotebookLM (modo IA ON) — arquitectura preparada, sin credenciales en repo.

Novedad: un cuaderno de NotebookLM POR ATAQUE (no un único id global). Cada ataque
se comunica con su propio cuaderno (ver config.ATTACK_NOTEBOOK_ENV).

Idea central del TFG: en modo IA ON, NotebookLM NO genera filas CSV directamente.
Se le pide una **descripción estructurada** del patrón del ataque (resumen, descripción
del antes/ataque/después y unas "reglas de generación"). El backend valida esa respuesta
y, a partir de ella, genera las filas de forma controlada (ver `simulator.py`).

Seguridad y robustez:
  - No se guardan credenciales/cookies/tokens en el código ni en el repo.
  - La configuración se lee de variables de entorno (ver `config.py` y `.env.example`).
  - Si NotebookLM no está configurado/instalado, el servicio informa de que NO está
    disponible con un motivo claro (la web sigue funcionando en modo IA OFF).
  - La respuesta de NotebookLM se valida antes de usarla.
"""

from __future__ import annotations

import asyncio
import json
import re

import config

# Campos mínimos que validamos de la respuesta estructurada de NotebookLM.
REQUIRED_KEYS = ("pattern_summary", "generation_rules", "explanation_for_teacher")


class NotebookLMUnavailable(RuntimeError):
    """NotebookLM no está configurado/instalado para este caso: usar modo IA OFF."""


class NotebookLMError(RuntimeError):
    """NotebookLM respondió, pero la respuesta no es válida/utilizable."""


def _package_installed() -> bool:
    try:
        import importlib.util
        return importlib.util.find_spec("notebooklm") is not None
    except Exception:
        return False


def status() -> dict:
    """Estado del modo IA ON para el frontend (no expone credenciales)."""
    enabled = config.env_bool("NOTEBOOKLM_ENABLED", False)
    auth_path = config.env_str("NOTEBOOKLM_AUTH_PATH", "")
    pkg = _package_installed()
    nb_map = config.notebook_map()
    configured = [a for a, ok in nb_map.items() if ok]
    missing = [a for a, ok in nb_map.items() if not ok]

    base_ready = bool(enabled and pkg and auth_path)
    available = bool(base_ready and configured)

    if available:
        reason = f"NotebookLM disponible para {len(configured)} ataque(s)."
    elif not enabled:
        reason = "Modo IA ON desactivado (NOTEBOOKLM_ENABLED no está a true)."
    elif not pkg:
        reason = "Falta la librería 'notebooklm-py' (instálala con requirements-ai.txt)."
    elif not auth_path:
        reason = "Falta NOTEBOOKLM_AUTH_PATH (ruta local a credenciales, fuera del repo)."
    elif not configured:
        reason = "No hay ningún cuaderno de ataque configurado (NOTEBOOKLM_*_ID vacíos)."
    else:
        reason = "NotebookLM no disponible."

    return {
        "available": available,
        "base_ready": base_ready,
        "package_installed": pkg,
        "configured_attacks": configured,
        "missing_attacks": missing,
        "reason": reason,
    }


def is_available() -> bool:
    return status()["available"]


def _ensure_ready_for(attack_id: str) -> str:
    """Comprueba que IA ON está lista y que ESTE ataque tiene cuaderno. Devuelve el notebook_id."""
    st = status()
    if not st["base_ready"]:
        raise NotebookLMUnavailable(st["reason"])
    notebook_id = config.notebook_id_for(attack_id)
    if not notebook_id:
        raise NotebookLMUnavailable(f"No hay cuaderno de NotebookLM configurado para '{attack_id}'.")
    if not st["package_installed"]:
        raise NotebookLMUnavailable("Falta la librería 'notebooklm-py'.")
    return notebook_id


def _ask(notebook_id: str, prompt: str) -> str:
    """Llamada SÍNCRONA al cuaderno: abre la sesión desde storage_state.json y pregunta.

    Internamente usa la API async de notebooklm-py 0.6
    (`NotebookLMClient.from_storage(...)` + `client.chat.ask(notebook_id, question)`).
    """
    auth_path = config.env_str("NOTEBOOKLM_AUTH_PATH", "")
    try:
        import notebooklm  # type: ignore
    except Exception as exc:  # pragma: no cover - depende del entorno del usuario
        raise NotebookLMUnavailable(f"No se pudo importar notebooklm-py: {exc}")

    # NotebookLM puede tardar ~40 s en responder; el timeout por defecto (30 s) se queda corto.
    timeout = float(config.env_str("NOTEBOOKLM_TIMEOUT", "120") or 120)

    async def _run() -> str:
        async with notebooklm.NotebookLMClient.from_storage(auth_path, timeout=timeout) as client:  # type: ignore[attr-defined]
            result = await client.chat.ask(notebook_id, prompt)
            return getattr(result, "answer", "") or ""

    try:
        return asyncio.run(_run())
    except (NotebookLMUnavailable, NotebookLMError):
        raise
    except Exception as exc:  # pragma: no cover - errores de red/sesión/API
        raise NotebookLMError(f"Fallo consultando NotebookLM: {exc}")


def _extract_json(text: str) -> dict:
    """Extrae el primer objeto JSON de la respuesta (NotebookLM añade markdown/citas)."""
    try:
        return json.loads(text)
    except (ValueError, TypeError):
        pass
    m = re.search(r"\{.*\}", text or "", re.DOTALL)
    if not m:
        raise NotebookLMError("NotebookLM no devolvió un JSON reconocible.")
    try:
        return json.loads(m.group(0))
    except (ValueError, TypeError) as exc:
        raise NotebookLMError(f"NotebookLM no devolvió JSON válido: {exc}")


def _build_pattern_prompt(attack_id: str, params: dict) -> str:
    """Pide a NotebookLM una salida JSON estructurada (no texto libre, no filas CSV)."""
    return (
        f"Eres el asistente del cuaderno de NotebookLM del ataque '{attack_id}' (proyecto NetFlow/UGR'16). "
        "Describe el patrón para generar una VENTANA de tráfico SINTÉTICO de demostración con esta forma: "
        "5 trazas de tráfico normal antes, N trazas de ataque y 5 trazas de tráfico normal después.\n"
        f"Parámetros: {json.dumps(params, ensure_ascii=False)}.\n\n"
        "Responde EXCLUSIVAMENTE con un JSON con esta forma exacta:\n"
        "{\n"
        '  "pattern_summary": "una frase clara",\n'
        '  "background_before_description": "qué tráfico normal hay antes",\n'
        '  "attack_description": "cómo se ve el ataque",\n'
        '  "background_after_description": "qué tráfico normal hay después",\n'
        '  "signals": ["...", "..."],\n'
        '  "generation_rules": {\n'
        '    "src_hosts": 1, "dst_hosts": 100, "dst_port": 22, "vary_dst_ports": false,\n'
        '    "protocol": "TCP", "packets_range": [1, 3], "bytes_range": [40, 300],\n'
        f'    "flags": ["S", "R"], "label": "{attack_id}"\n'
        "  },\n"
        '  "explanation_for_teacher": "explicación breve y comprensible"\n'
        "}\n"
        "Puedes usar los resúmenes estadísticos del cuaderno para elegir rangos aproximados de "
        "packets, bytes y duración. Sin embargo, las restricciones estructurales del ataque tienen "
        "prioridad. No cambies la forma principal del patrón para ajustar los rangos estadísticos. "
        "Por ejemplo: si el ataque es anomaly-udpscan, debe seguir siendo UDP con muchos destinos "
        "distintos y flujos ligeros; si es anomaly-sshscan, debe seguir siendo TCP hacia puerto 22 "
        "con muchos destinos distintos; si es scan11, debe seguir siendo un origen contra muchos "
        "puertos de un destino.\n"
        "No incluyas texto fuera del JSON. No generes filas CSV."
    )


def _validate_payload(payload) -> dict:
    if not isinstance(payload, dict):
        raise NotebookLMError("La respuesta de NotebookLM no es un objeto JSON.")
    missing = [k for k in REQUIRED_KEYS if k not in payload]
    if missing:
        raise NotebookLMError(f"Faltan campos en la respuesta de NotebookLM: {missing}.")
    if not isinstance(payload.get("generation_rules"), dict):
        raise NotebookLMError("'generation_rules' debe ser un objeto.")
    return payload


def generate_pattern(attack_id: str, params: dict) -> dict:
    """Pide al cuaderno del ataque la descripción estructurada del patrón y la valida."""
    notebook_id = _ensure_ready_for(attack_id)
    prompt = _build_pattern_prompt(attack_id, params)
    answer = _ask(notebook_id, prompt)
    payload = _extract_json(answer)
    return _validate_payload(payload)


def chat(attack_id: str, question: str) -> str:
    """Envía una pregunta libre al cuaderno de NotebookLM del ataque y devuelve la respuesta."""
    notebook_id = _ensure_ready_for(attack_id)
    prompt = (
        f"Pregunta sobre el ataque '{attack_id}' (proyecto NetFlow/UGR'16). "
        "Responde de forma clara y breve, para un profesor de informática no especialista. "
        f"Pregunta: {question}"
    )
    answer = _ask(notebook_id, prompt)
    if not answer.strip():
        raise NotebookLMError("NotebookLM devolvió una respuesta vacía.")
    return answer

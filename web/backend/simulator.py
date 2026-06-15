"""
Simulador de ataques sintéticos (modo IA OFF: plantillas locales controladas).

Genera flujos NetFlow *sintéticos* para explicar visualmente el patrón de cada
familia de ataque. No usa datos reales ni CSV grandes: todo se genera en memoria
a partir de plantillas seguras. Las mismas "reglas de generación" pueden venir de
NotebookLM (modo IA ON); en ese caso el backend sigue generando las filas aquí,
de forma controlada (NotebookLM nunca produce miles de filas directamente).

Columnas sintéticas:
    timestamp, src_ip, dst_ip, protocol, src_port, dst_port, packets, bytes, flags, label

Prioridad estructura > rangos (modo IA ON):
    NotebookLM puede ayudar a elegir rangos realistas (packets/bytes/duración) a partir del
    cuaderno, pero el backend mantiene las restricciones principales del patrón (protocolo,
    puerto, fan-out, etc.) para que la simulación siga siendo coherente. NotebookLM solo influye
    en `packets_range`/`bytes_range`, que además se recortan a los límites del ataque.
"""

from __future__ import annotations

import random
from datetime import datetime, timedelta

COLUMNS = [
    "timestamp", "src_ip", "dst_ip", "protocol",
    "src_port", "dst_port", "packets", "bytes", "flags", "label",
]

MAX_FLOWS = 2000          # límite de seguridad para la demo
INTENSITY_FACTOR = {"baja": 0.5, "media": 1.0, "alta": 2.0}
NOISE_RATIO = 0.25        # proporción de tráfico normal cuando include_noise=True
BASE_TIME = datetime(2016, 7, 27, 13, 0, 0)

# ---------------------------------------------------------------------------
# Plantillas por familia de ataque
# ---------------------------------------------------------------------------
# `generation_rules` describe el patrón de forma estructurada (el mismo formato
# que pedimos a NotebookLM). `scale_target` indica qué dimensión crece con la
# intensidad: el número de orígenes (src), de destinos (dst) o ambos.

ATTACK_TEMPLATES = {
    "scan11": {
        "pattern_summary": "Un único origen prueba muchos puertos distintos de una misma víctima.",
        "signals": ["mismo origen", "mismo destino", "muchos puertos destino", "conexiones cortas"],
        "generation_rules": {
            "src_hosts": 1, "dst_hosts": 1, "dst_port": None, "vary_dst_ports": True,
            "protocol": "TCP", "packets_range": [1, 2], "bytes_range": [40, 60],
            "flags": ["S"], "label": "scan11",
        },
        "scale_target": "dst",
        "light": True,
        "explanation_for_teacher": (
            "Esta simulación representa un escaneo vertical: una sola máquina recorre muchos "
            "puertos de una misma víctima con conexiones mínimas y repetitivas, buscando qué "
            "servicios tiene abiertos."
        ),
    },
    "scan44": {
        "pattern_summary": "Varias máquinas colaboran para escanear los puertos de un mismo objetivo.",
        "signals": ["varios orígenes", "mismo objetivo", "muchos puertos destino", "patrón repetitivo"],
        "generation_rules": {
            "src_hosts": 5, "dst_hosts": 1, "dst_port": None, "vary_dst_ports": True,
            "protocol": "TCP", "packets_range": [1, 2], "bytes_range": [40, 60],
            "flags": ["S"], "label": "scan44",
        },
        "scale_target": "src",
        "light": True,
        "explanation_for_teacher": (
            "Esta simulación representa un escaneo vertical distribuido: varias máquinas se "
            "reparten el trabajo de sondear los puertos de un mismo objetivo, lo que dificulta "
            "atribuirlo a un solo atacante."
        ),
    },
    "anomaly-udpscan": {
        "pattern_summary": "Un origen envía muchos mensajes UDP ligeros hacia muchos destinos.",
        "signals": ["protocolo UDP", "muchos destinos", "flujos de un paquete", "dispersión"],
        "generation_rules": {
            "src_hosts": 1, "dst_hosts": 60, "dst_port": None, "vary_dst_ports": True,
            "protocol": "UDP", "packets_range": [1, 1], "bytes_range": [28, 80],
            "flags": ["."], "label": "anomaly-udpscan",
        },
        "scale_target": "dst",
        "light": True,
        "explanation_for_teacher": (
            "Esta simulación representa un escaneo UDP: una máquina lanza muchos mensajes muy "
            "pequeños (un paquete cada uno) hacia muchos destinos para ver quién responde. Se "
            "evita el tráfico DNS, que también es UDP pero normal."
        ),
    },
    "dos": {
        "pattern_summary": "Mucho tráfico se concentra contra un mismo servicio para saturarlo.",
        "signals": ["mismo destino:puerto", "concentración temporal", "volumen elevado"],
        "generation_rules": {
            "src_hosts": 3, "dst_hosts": 1, "dst_port": 80, "vary_dst_ports": False,
            "protocol": "TCP", "packets_range": [2, 8], "bytes_range": [300, 1200],
            "flags": ["S", "SA", "A"], "label": "dos",
        },
        "scale_target": "src",
        "time_dense": True,
        "explanation_for_teacher": (
            "Esta simulación representa una denegación de servicio: gran cantidad de tráfico se "
            "concentra contra un único servicio (aquí, el puerto 80) en muy poco tiempo, "
            "intentando agotar sus recursos."
        ),
    },
    "nerisbotnet": {
        "pattern_summary": "Varios equipos repiten un comportamiento casi idéntico, como una red de bots.",
        "signals": ["varios orígenes", "métricas repetidas", "destino/servicio común"],
        "generation_rules": {
            "src_hosts": 8, "dst_hosts": 1, "dst_port": 6667, "vary_dst_ports": False,
            "protocol": "TCP", "packets_range": [3, 3], "bytes_range": [200, 200],
            "flags": ["A"], "label": "nerisbotnet",
        },
        "scale_target": "src",
        "explanation_for_teacher": (
            "Esta simulación representa una red de bots coordinada: muchos equipos distintos "
            "generan flujos casi idénticos hacia un mismo punto de control, como si los manejara "
            "el mismo programa."
        ),
    },
    "anomaly-sshscan": {
        "pattern_summary": "Un origen contacta muchos destinos por SSH (puerto 22) con conexiones ligeras.",
        "signals": ["puerto 22", "muchos destinos", "conexiones ligeras", "patrón por origen"],
        "generation_rules": {
            "src_hosts": 1, "dst_hosts": 100, "dst_port": 22, "vary_dst_ports": False,
            "protocol": "TCP", "packets_range": [1, 3], "bytes_range": [40, 300],
            "flags": ["S", "R"], "label": "anomaly-sshscan",
        },
        "scale_target": "dst",
        "light": True,
        "explanation_for_teacher": (
            "Esta simulación representa un escaneo horizontal SSH: una sola máquina intenta "
            "conectarse al puerto 22 (SSH) de muchísimos destinos distintos. Esa apertura 'en "
            "abanico' de un origen hacia muchos destinos es el patrón que detecta la v5."
        ),
    },
}

SUPPORTED_ATTACKS = list(ATTACK_TEMPLATES.keys())


class SimulatorError(ValueError):
    """Error de validación de parámetros o de reglas de generación."""


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _rand_ip(prefix: str) -> str:
    return f"{prefix}.{random.randint(0, 255)}.{random.randint(1, 254)}"


def _scaled(n: int, intensity: str) -> int:
    return max(1, round(n * INTENSITY_FACTOR.get(intensity, 1.0)))


def get_template(attack_id: str) -> dict | None:
    return ATTACK_TEMPLATES.get(attack_id)


def clamp_num_flows(num_flows: int) -> int:
    try:
        n = int(num_flows)
    except (TypeError, ValueError):
        n = 100
    return max(1, min(MAX_FLOWS, n))


# ---------------------------------------------------------------------------
# Validación / fusión de reglas (también para la respuesta de NotebookLM)
# ---------------------------------------------------------------------------

# Límites de packets/bytes para ataques de "flujos ligeros" (restricción estructural):
# si NotebookLM sugiere rangos mayores, se recortan a estos topes para no romper el patrón.
LIGHT_PACKETS_BOUNDS = [1, 4]
LIGHT_BYTES_BOUNDS = [1, 1500]


def _as_int(v, default=0):
    try:
        return int(float(v))
    except (TypeError, ValueError):
        return default


def _coerce_range(rng, fallback):
    """Convierte un rango sugerido a [min, max] de enteros >= 0 (tolerante)."""
    if not isinstance(rng, (list, tuple)) or len(rng) != 2:
        rng = fallback
    lo, hi = _as_int(rng[0], fallback[0]), _as_int(rng[1], fallback[1])
    lo = max(0, lo)
    hi = max(lo, hi)
    return [lo, hi]


def _apply_bounds(rng, bounds):
    """Recorta un rango dentro de unos límites estructurales (si los hay)."""
    if not bounds:
        return rng
    blo, bhi = bounds
    lo = min(max(rng[0], blo), bhi)
    hi = min(max(rng[1], lo), bhi)
    return [lo, hi]


def merge_and_validate_rules(template: dict, override: dict | None) -> dict:
    """Construye las reglas de generación con PRIORIDAD a la estructura del ataque.

    Orden (según el diseño con NotebookLM):
      1. La ESTRUCTURA del patrón viene SIEMPRE de la plantilla y NO se puede
         sobrescribir: protocolo, puerto destino, vary_dst_ports, nº de orígenes/
         destinos, flags y label. Esto garantiza que, p. ej., anomaly-udpscan siga
         siendo UDP con muchos destinos, o anomaly-sshscan siga siendo TCP al 22.
      2. NotebookLM SOLO puede sugerir rangos estadísticos: `packets_range` y
         `bytes_range` (a partir de los resúmenes del cuaderno).
      3. Si esos rangos contradicen el patrón (p. ej. flujos "ligeros"), se recortan
         a los límites estructurales del ataque; si no son válidos, se usa la plantilla.
    """
    base = template["generation_rules"]
    # 1) Estructura: copia íntegra de la plantilla (no se sobrescribe).
    rules = dict(base)

    # 2) Rangos estadísticos: solo packets_range / bytes_range pueden venir del override.
    pkt = _coerce_range(override.get("packets_range") if override else None, base["packets_range"]) \
        if (override and override.get("packets_range") is not None) else list(base["packets_range"])
    byt = _coerce_range(override.get("bytes_range") if override else None, base["bytes_range"]) \
        if (override and override.get("bytes_range") is not None) else list(base["bytes_range"])

    # 3) Recorte a límites estructurales (ataques de flujos ligeros).
    if template.get("light"):
        pkt = _apply_bounds(pkt, LIGHT_PACKETS_BOUNDS)
        byt = _apply_bounds(byt, LIGHT_BYTES_BOUNDS)
    rules["packets_range"] = pkt
    rules["bytes_range"] = byt

    # Saneado final de la estructura (por seguridad, aunque venga de la plantilla).
    rules["protocol"] = str(rules.get("protocol", "TCP")).upper().strip()
    rules["src_hosts"] = max(1, min(500, _as_int(rules.get("src_hosts", 1), 1)))
    rules["dst_hosts"] = max(1, min(2000, _as_int(rules.get("dst_hosts", 1), 1)))
    if rules.get("dst_port") is not None:
        rules["dst_port"] = max(0, min(65535, _as_int(rules["dst_port"], 0)))
    rules["vary_dst_ports"] = bool(rules.get("vary_dst_ports", False))
    flags = rules.get("flags")
    if isinstance(flags, str):
        flags = [flags]
    if not isinstance(flags, list) or not flags:
        flags = list(base["flags"])
    rules["flags"] = [str(f) for f in flags]
    rules["label"] = str(rules.get("label") or base["label"])
    return rules


# ---------------------------------------------------------------------------
# Generación de filas (controlada por el backend)
# ---------------------------------------------------------------------------

def generate_rows(rules: dict, num_flows: int, intensity: str, include_noise: bool,
                  scale_target: str = "dst", time_dense: bool = False) -> list[dict]:
    num_flows = clamp_num_flows(num_flows)
    noise_count = round(num_flows * NOISE_RATIO) if include_noise else 0
    attack_count = max(0, num_flows - noise_count)

    n_src = _scaled(rules["src_hosts"], intensity) if scale_target in ("src", "both") else rules["src_hosts"]
    n_dst = _scaled(rules["dst_hosts"], intensity) if scale_target in ("dst", "both") else rules["dst_hosts"]
    n_src = max(1, min(n_src, attack_count or 1))
    n_dst = max(1, min(n_dst, max(1, attack_count)))

    src_pool = [_rand_ip("10.0") for _ in range(n_src)]
    dst_pool = [_rand_ip("192.168") for _ in range(n_dst)]

    rows: list[dict] = []
    step_ms = 5 if time_dense else 120

    for i in range(attack_count):
        dport = random.randint(1, 65535) if rules["vary_dst_ports"] else rules["dst_port"]
        ts = BASE_TIME + timedelta(milliseconds=i * step_ms + random.randint(0, step_ms))
        rows.append({
            "timestamp": ts.strftime("%Y-%m-%d %H:%M:%S.") + f"{ts.microsecond // 1000:03d}",
            "src_ip": random.choice(src_pool),
            "dst_ip": random.choice(dst_pool),
            "protocol": rules["protocol"],
            "src_port": random.randint(1024, 65535),
            "dst_port": dport if dport is not None else random.randint(1, 65535),
            "packets": random.randint(rules["packets_range"][0], rules["packets_range"][1]),
            "bytes": random.randint(rules["bytes_range"][0], rules["bytes_range"][1]),
            "flags": random.choice(rules["flags"]),
            "label": rules["label"],
        })

    # Tráfico normal de fondo (ruido), claramente distinto del patrón de ataque
    for i in range(noise_count):
        proto = random.choice(["TCP", "TCP", "UDP"])
        ts = BASE_TIME + timedelta(milliseconds=random.randint(0, max(1, attack_count) * step_ms))
        rows.append({
            "timestamp": ts.strftime("%Y-%m-%d %H:%M:%S.") + f"{ts.microsecond // 1000:03d}",
            "src_ip": _rand_ip("172.16"),
            "dst_ip": _rand_ip("203.0"),
            "protocol": proto,
            "src_port": random.randint(1024, 65535),
            "dst_port": random.choice([80, 443, 53, 123, 993]),
            "packets": random.randint(5, 40),
            "bytes": random.randint(400, 8000),
            "flags": random.choice(["A", "SA", "."]),
            "label": "background",
        })

    rows.sort(key=lambda r: r["timestamp"])
    return rows


def _attack_row(rules: dict, src_pool: list, dst_pool: list, ts: datetime) -> dict:
    dport = random.randint(1, 65535) if rules["vary_dst_ports"] else rules["dst_port"]
    return {
        "timestamp": ts.strftime("%Y-%m-%d %H:%M:%S.") + f"{ts.microsecond // 1000:03d}",
        "src_ip": random.choice(src_pool),
        "dst_ip": random.choice(dst_pool),
        "protocol": rules["protocol"],
        "src_port": random.randint(1024, 65535),
        "dst_port": dport if dport is not None else random.randint(1, 65535),
        "packets": random.randint(rules["packets_range"][0], rules["packets_range"][1]),
        "bytes": random.randint(rules["bytes_range"][0], rules["bytes_range"][1]),
        "flags": random.choice(rules["flags"]),
        "label": rules["label"],
        "section": "attack",
    }


def _background_row(ts: datetime, section: str) -> dict:
    proto = random.choice(["TCP", "TCP", "UDP"])
    return {
        "timestamp": ts.strftime("%Y-%m-%d %H:%M:%S.") + f"{ts.microsecond // 1000:03d}",
        "src_ip": _rand_ip("172.16"),
        "dst_ip": _rand_ip("203.0"),
        "protocol": proto,
        "src_port": random.randint(1024, 65535),
        "dst_port": random.choice([80, 443, 53, 123, 993]),
        "packets": random.randint(5, 40),
        "bytes": random.randint(400, 8000),
        "flags": random.choice(["A", "SA", "."]),
        "label": "background",
        "section": section,
    }


def generate_window(template: dict, rules: dict, attack_flows: int, intensity: str,
                    include_context_background: bool, before: int = 5, after: int = 5) -> list[dict]:
    """Genera una VENTANA: `before` background + N ataque + `after` background.

    Cada fila lleva un campo extra `section` (background_before / attack / background_after)
    para que el frontend pueda distinguirlas visualmente. Ese campo NO va en el CSV.

    Cada ejecución genera una variante distinta del mismo patrón (datos sintéticos de demo).
    """
    attack_flows = clamp_num_flows(attack_flows)
    scale_target = template.get("scale_target", "dst")
    time_dense = template.get("time_dense", False)

    n_src = _scaled(rules["src_hosts"], intensity) if scale_target in ("src", "both") else rules["src_hosts"]
    n_dst = _scaled(rules["dst_hosts"], intensity) if scale_target in ("dst", "both") else rules["dst_hosts"]
    n_src = max(1, min(n_src, attack_flows))
    n_dst = max(1, min(n_dst, attack_flows))
    src_pool = [_rand_ip("10.0") for _ in range(n_src)]
    dst_pool = [_rand_ip("192.168") for _ in range(n_dst)]

    before = before if include_context_background else 0
    after = after if include_context_background else 0
    step_ms = 5 if time_dense else 120

    rows: list[dict] = []
    t = BASE_TIME
    for _ in range(before):
        rows.append(_background_row(t, "background_before"))
        t += timedelta(milliseconds=random.randint(200, 600))
    for _ in range(attack_flows):
        rows.append(_attack_row(rules, src_pool, dst_pool, t))
        t += timedelta(milliseconds=step_ms + random.randint(0, step_ms))
    for _ in range(after):
        rows.append(_background_row(t, "background_after"))
        t += timedelta(milliseconds=random.randint(200, 600))
    return rows


def summarize(rows: list[dict], rules: dict) -> dict:
    attack_label = rules["label"]
    attack_rows = [r for r in rows if r["label"] == attack_label]
    return {
        "total_rows": len(rows),
        "attack_rows": len(attack_rows),
        "noise_rows": len(rows) - len(attack_rows),
        "distinct_src": len({r["src_ip"] for r in attack_rows}),
        "distinct_dst": len({r["dst_ip"] for r in attack_rows}),
        "distinct_dst_ports": len({r["dst_port"] for r in attack_rows}),
        "protocol": rules["protocol"],
        "label": attack_label,
    }


def to_csv(rows: list[dict]) -> str:
    lines = [",".join(COLUMNS)]
    for r in rows:
        lines.append(",".join(str(r[c]) for c in COLUMNS))
    return "\n".join(lines)


def to_csv_preview(rows: list[dict], limit: int = 15) -> str:
    return to_csv(rows[:limit])

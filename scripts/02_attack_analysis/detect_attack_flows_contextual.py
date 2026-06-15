"""
Script: detect_attack_flows_contextual.py

Clasificador CONTEXTUAL POR TRAZA para el TFG.

Objetivo
--------
El objetivo del TFG es detectar TRAZAS CONCRETAS de ataque, no solo clasificar
ventanas completas. Pero una traza NetFlow aislada rara vez tiene información
suficiente: muchos ataques solo emergen del PATRÓN que forman varias trazas
juntas (barridos de puertos, ráfagas, dispersión de destinos, coordinación entre
nodos o repetición de métricas).

Por eso este clasificador decide la etiqueta de cada fila por PERTENENCIA a un
patrón conductual detectado en su CONTEXTO LOCAL:

    para cada fila i
      -> tomar N filas anteriores y N posteriores (contexto local)
      -> calcular propiedades del contexto
      -> comprobar si la fila i pertenece a un grupo que cumple un patrón
      -> asignar predicted_label a esa traza concreta

Así se puede defender que el sistema clasifica trazas concretas, pero no de forma
aislada, sino por pertenencia a comportamientos medibles en su contexto.

Principios (coherentes con el enfoque LLM + validación heurística)
------------------------------------------------------------------
- NO se usan IPs concretas como regla (solo relaciones estructurales).
- NO se usan las etiquetas como criterio de detección (solo para evaluar).
- Ninguna traza se clasifica por una métrica aislada.
- Cada decisión se basa en el contexto local y deja evidencia interpretable.
- No es Machine Learning: son reglas explicables con umbrales ajustables.
- Las limitaciones se registran explícitamente; no se fuerzan resultados.

Entrada
-------
Ventanas CSV NetFlow dentro de data/attack_analysis/ (se ignoran resúmenes,
resultados previos y ficheros que no son ventanas).

Salida
------
- data/attack_analysis/flow_level_detection_results.csv   (una fila por traza)
- data/attack_analysis/flow_level_detection_summary.csv    (resumen/evaluación)

Uso
---
    python scripts/02_attack_analysis/detect_attack_flows_contextual.py

NOTA: no modifica detect_synthetic_behavior.py ni detect_synthetic_behavior_extended.py.
"""

import csv
from pathlib import Path
from collections import Counter, defaultdict
from statistics import variance

# ---------------------------------------------------------------------------
# Configuración general
# ---------------------------------------------------------------------------

BASE_DIR = Path("data/attack_analysis")
RESULTS_FILE = BASE_DIR / "flow_level_detection_results.csv"
SUMMARY_FILE = BASE_DIR / "flow_level_detection_summary.csv"

EXPECTED_COLUMNS = 13

SKIP_SUFFIXES = ("_extraction_summary.csv",)
SKIP_NAMES = (
    "behavior_detection_results.csv",
    "behavior_detection_results_extended.csv",
    "window_extraction_summary.csv",
    "flow_level_detection_results.csv",
    "flow_level_detection_summary.csv",
)

# ---------------------------------------------------------------------------
# Tamaño del contexto local (fácilmente ajustable)
# ---------------------------------------------------------------------------

CONTEXT_ROWS_BEFORE = 30
CONTEXT_ROWS_AFTER = 30

# Estructura preparada para un futuro contexto TEMPORAL (no implementado todavía).
# Si se activara, se acotaría el contexto además por una ventana de tiempo en
# segundos alrededor del timestamp de la fila objetivo.
USE_TEMPORAL_CONTEXT = False
CONTEXT_TIME_WINDOW_SECONDS = 10  # reservado para uso futuro

# ---------------------------------------------------------------------------
# Umbrales por familia (escalados al tamaño del CONTEXTO LOCAL, no de la ventana)
# ---------------------------------------------------------------------------

# Definición de flujo "atómico" / de baja entropía
ZERO_DURATION_THRESHOLD = 0.01
LOW_PACKET_THRESHOLD = 2
SMALL_BYTES_MAX = 100          # "bytes pequeños" (firma de control TCP/escaneo)
LOW_BYTES_VARIANCE = 50        # baja entropía de bytes (firma sintética)

# scan11 / scan44 (barrido vertical TCP SYN)
CTX_SCAN_MIN_DST_PORTS = 8     # verticalidad dentro del contexto local
SCAN_SINGLE_DOMINANCE = 0.7    # cuota del origen principal: >= -> un origen domina

# anomaly-udpscan
CTX_UDP_MIN_DST_IPS = 4
CTX_UDP_MIN_DST_PORTS = 6
CTX_UDP_BYTES_VAR_MAX = 200
DNS_PORT = 53                  # se descarta tráfico DNS
UDP_KNOWN_SRC_PORTS = {5061, 5062, 5066, 5068}  # corroborativo, NO decisivo

# dos
CTX_DOS_MIN_GROUP = 8          # flujos al mismo dst_port dentro del contexto
DOS_PORT_CONCENTRATION = 0.6   # cuota del puerto dominante en el par src->dst
DOS_BYTES_VAR_MAX = 10_000

# anomaly-sshscan
SSH_PORT = 22
CTX_SSH_MIN_DST_IPS = 3
SSH_BYTES_MAX = 44

# nerisbotnet
NERIS_C2_PORTS = {25, 6667, 2077}            # puertos C2/servicio "fuertes"
NERIS_SERVICE_PORTS = {25, 6667, 53, 2077}   # contexto multivector
CTX_NERIS_MIN_SOURCES = 3                    # coordinación entre nodos

# anomaly-spam
SPAM_PORT = 25
CTX_SPAM_MIN_FLOWS = 3
SPAM_PACKET_RANGE = (8, 13)
SPAM_KNOWN_BYTES = {763, 815, 841, 893, 3136, 3143}  # corroborativo, NO decisivo

# Familias conocidas (para evaluación y resumen)
FAMILIES = [
    "scan11", "scan44", "anomaly-udpscan", "dos",
    "nerisbotnet", "anomaly-sshscan", "anomaly-spam",
]

# Precedencia para desempatar (patrón más específico/distribuido gana).
WIN_PRECEDENCE = [
    "anomaly-udpscan", "scan44", "scan11", "dos",
    "nerisbotnet", "anomaly-spam", "anomaly-sshscan",
]

CONFIDENCE_RANK = {"insuficiente": 0, "baja": 1, "media": 2, "alta": 3}


# ---------------------------------------------------------------------------
# Utilidades
# ---------------------------------------------------------------------------

def safe_int(value, default=0):
    try:
        return int(value)
    except Exception:
        return default


def safe_float(value, default=0.0):
    try:
        return float(value)
    except Exception:
        return default


def safe_variance(values):
    return variance(values) if len(values) > 1 else 0.0


def mode_value(values):
    return Counter(values).most_common(1)[0][0] if values else 0


def has_flag(flags, flag_char):
    return flag_char in (flags or "")


def subnet_24(ip):
    parts = ip.split(".")
    return ".".join(parts[:3]) if len(parts) == 4 else ip


def ratio(count, total):
    return round(count / total, 3) if total else 0.0


def is_mostly_sequential(values, min_ratio=0.65):
    """Progresión mayoritariamente secuencial (acepta saltos de +1 o +2)."""
    values = sorted(set(v for v in values if v > 0))
    if len(values) < 5:
        return False
    diffs = [b - a for a, b in zip(values, values[1:])]
    if not diffs:
        return False
    valid = [d for d in diffs if d in (1, 2)]
    return len(valid) / len(diffs) >= min_ratio


def grade(signals, cap=None):
    """Convierte señales booleanas en (nº_señales, confianza), con tope opcional."""
    total = len(signals)
    passed = sum(1 for v in signals.values() if v)
    frac = passed / total if total else 0.0
    if frac >= 0.8:
        level = "alta"
    elif frac >= 0.6:
        level = "media"
    elif frac >= 0.4:
        level = "baja"
    else:
        level = "insuficiente"
    if cap is not None and CONFIDENCE_RANK[level] > CONFIDENCE_RANK[cap]:
        level = cap
    return passed, level


def signals_text(signals):
    on = [k for k, v in signals.items() if v]
    off = [k for k, v in signals.items() if not v]
    parts = []
    if on:
        parts.append("señales=[" + ", ".join(on) + "]")
    if off:
        parts.append("ausentes=[" + ", ".join(off) + "]")
    return "; ".join(parts)


def is_atomic(r):
    return r["duration"] <= ZERO_DURATION_THRESHOLD and r["packets"] <= LOW_PACKET_THRESHOLD


# ---------------------------------------------------------------------------
# Carga de ventanas
# ---------------------------------------------------------------------------

def load_window(file_path):
    """Carga una ventana y devuelve la lista de flujos (dicts), en orden."""
    rows = []
    with open(file_path, "r", encoding="utf-8", errors="ignore", newline="") as f:
        for row in csv.reader(f):
            if len(row) != EXPECTED_COLUMNS:
                continue
            rows.append({
                "timestamp": row[0],
                "duration": safe_float(row[1]),
                "src_ip": row[2],
                "dst_ip": row[3],
                "src_port": safe_int(row[4]),
                "dst_port": safe_int(row[5]),
                "protocol": row[6],
                "flags": row[7],
                "packets": safe_int(row[10]),
                "bytes": safe_int(row[11]),
                "label": row[12].strip(),
            })
    return rows


# ---------------------------------------------------------------------------
# Propiedades del contexto local
# ---------------------------------------------------------------------------

def compute_context_features(context):
    """
    Calcula las propiedades del contexto local pedidas en la especificación.
    Se usan tanto para las decisiones como para la evidencia interpretable.
    """
    n = len(context)
    protocols = [r["protocol"] for r in context]
    src_ips = [r["src_ip"] for r in context]
    dst_ips = [r["dst_ip"] for r in context]
    src_ports = [r["src_port"] for r in context]
    dst_ports = [r["dst_port"] for r in context]
    flags = [r["flags"] for r in context]
    durations = [r["duration"] for r in context]
    packets = [r["packets"] for r in context]
    bytes_values = [r["bytes"] for r in context]
    timestamps = [r["timestamp"] for r in context]

    top_src, top_src_n = Counter(src_ips).most_common(1)[0]
    top_dst, top_dst_n = Counter(dst_ips).most_common(1)[0]
    _, top_dport_n = Counter(dst_ports).most_common(1)[0]
    ts_counts = Counter(timestamps)
    _, max_same_ts = ts_counts.most_common(1)[0]

    # cardinalidades relacionales
    dports_per_pair = defaultdict(set)
    dsts_per_src = defaultdict(set)
    srcs_per_dst = defaultdict(set)
    for r in context:
        dports_per_pair[(r["src_ip"], r["dst_ip"])].add(r["dst_port"])
        dsts_per_src[r["src_ip"]].add(r["dst_ip"])
        srcs_per_dst[r["dst_ip"]].add(r["src_ip"])

    return {
        "dominant_protocol": Counter(protocols).most_common(1)[0][0],
        "unique_src_ips": len(set(src_ips)),
        "unique_dst_ips": len(set(dst_ips)),
        "unique_src_ports": len(set(src_ports)),
        "unique_dst_ports": len(set(dst_ports)),
        "avg_duration": round(sum(durations) / n, 6),
        "zero_duration_ratio": ratio(sum(1 for d in durations if d <= ZERO_DURATION_THRESHOLD), n),
        "avg_packets": round(sum(packets) / n, 3),
        "low_packet_ratio": ratio(sum(1 for p in packets if p <= LOW_PACKET_THRESHOLD), n),
        "avg_bytes": round(sum(bytes_values) / n, 3),
        "bytes_variance": round(safe_variance(bytes_values), 3),
        "dominant_flags": Counter(flags).most_common(1)[0][0],
        "flows_per_timestamp": round(n / max(1, len(ts_counts)), 3),
        "max_flows_same_timestamp": max_same_ts,
        "src_ip_concentration": ratio(top_src_n, n),
        "dst_ip_concentration": ratio(top_dst_n, n),
        "dst_port_concentration": ratio(top_dport_n, n),
        "max_dst_ports_per_pair": max(len(s) for s in dports_per_pair.values()),
        "max_dsts_per_src": max(len(s) for s in dsts_per_src.values()),
        "max_srcs_per_dst": max(len(s) for s in srcs_per_dst.values()),
        "src_port_sequential": is_mostly_sequential(src_ports),
        "dst_port_sequential": is_mostly_sequential(dst_ports),
        "low_bytes_entropy": safe_variance(bytes_values) < LOW_BYTES_VARIANCE,
        "temporal_sync": max_same_ts >= 3,
    }


# ---------------------------------------------------------------------------
# Estructura compartida: escáneres verticales SYN en el contexto
# ---------------------------------------------------------------------------

def context_vertical_scanners(context, min_ports):
    """Pares y orígenes que realizan barrido vertical TCP SYN dentro del contexto."""
    cand = [r for r in context
            if r["protocol"] == "TCP" and is_atomic(r) and has_flag(r["flags"], "S")]
    pairs = defaultdict(list)
    for r in cand:
        pairs[(r["src_ip"], r["dst_ip"])].append(r)
    vertical = {k: g for k, g in pairs.items()
                if len({r["dst_port"] for r in g}) >= min_ports}

    by_src = defaultdict(int)
    for (src, _dst), g in vertical.items():
        by_src[src] += len(g)
    scanners = sorted(by_src.items(), key=lambda kv: kv[1], reverse=True)
    total = sum(n for _s, n in scanners)
    top_share = ratio(scanners[0][1], total) if scanners else 0.0

    return {
        "vertical_pairs": vertical,
        "scanners": scanners,
        "top_share": top_share,
    }


# ---------------------------------------------------------------------------
# Detectores de pertenencia por familia
#   Cada uno: ¿pertenece la traza objetivo a un grupo contextual que cumple el
#   patrón? Devuelve dict(family, n_signals, confidence, evidence, limitations)
#   o None si la traza no es miembro.
# ---------------------------------------------------------------------------

def member_scan11(target, context, vscan):
    if not (target["protocol"] == "TCP" and is_atomic(target) and has_flag(target["flags"], "S")):
        return None
    pair = (target["src_ip"], target["dst_ip"])
    if pair not in vscan["vertical_pairs"]:
        return None
    group = vscan["vertical_pairs"][pair]
    dports = {r["dst_port"] for r in group}
    bvals = [r["bytes"] for r in group]
    dominant_src = vscan["scanners"][0][0] if vscan["scanners"] else None

    signals = {
        "verticalidad_puertos": len(dports) >= CTX_SCAN_MIN_DST_PORTS,
        "origen_dominante": vscan["top_share"] >= SCAN_SINGLE_DOMINANCE and target["src_ip"] == dominant_src,
        "flujos_atomicos": is_atomic(target),
        "bytes_pequenos": mode_value(bvals) <= SMALL_BYTES_MAX,
        "baja_entropia_bytes": safe_variance(bvals) < LOW_BYTES_VARIANCE,
    }
    if not (signals["verticalidad_puertos"] and signals["origen_dominante"]):
        return None
    n, level = grade(signals)
    return {
        "family": "scan11", "n_signals": n, "confidence": level,
        "evidence": f"traza pertenece a barrido vertical {pair[0]}->{pair[1]} "
                    f"({len(dports)} puertos destino en el contexto, cuota origen "
                    f"{vscan['top_share']}); " + signals_text(signals),
        "limitations": [],
    }


def member_scan44(target, context, vscan):
    if not (target["protocol"] == "TCP" and is_atomic(target) and has_flag(target["flags"], "S")):
        return None
    pair = (target["src_ip"], target["dst_ip"])
    if pair not in vscan["vertical_pairs"]:
        return None
    scanners = vscan["scanners"]
    if len(scanners) < 2 or vscan["top_share"] >= SCAN_SINGLE_DOMINANCE:
        return None

    # sincronización: timestamps con >=2 orígenes verticales activos a la vez
    ts_srcs = defaultdict(set)
    for (src, _dst), g in vscan["vertical_pairs"].items():
        for r in g:
            ts_srcs[r["timestamp"]].add(src)
    temporal_sync = any(len(s) >= 2 for s in ts_srcs.values())

    subnets = Counter(subnet_24(s) for s, _n in scanners)
    all_bytes = [r["bytes"] for g in vscan["vertical_pairs"].values() for r in g]

    signals = {
        "multiples_origenes": len(scanners) >= 2,
        "reparto_entre_origenes": vscan["top_share"] < SCAN_SINGLE_DOMINANCE,
        "sincronizacion_temporal": temporal_sync,
        "flujos_atomicos": is_atomic(target),
        "baja_entropia_bytes": safe_variance(all_bytes) < LOW_BYTES_VARIANCE,
        "origenes_misma_subred": subnets.most_common(1)[0][1] >= 2,
    }
    n, level = grade(signals)
    return {
        "family": "scan44", "n_signals": n, "confidence": level,
        "evidence": f"traza pertenece a barrido vertical DISTRIBUIDO "
                    f"({len(scanners)} orígenes, cuota origen {vscan['top_share']}); "
                    + signals_text(signals),
        "limitations": [],
    }


def member_udp_scan(target, context):
    if not (target["protocol"] == "UDP" and target["packets"] == 1 and is_atomic(target)):
        return None
    if target["src_port"] == DNS_PORT or target["dst_port"] == DNS_PORT:
        return None  # tráfico DNS, no escaneo
    group = [r for r in context
             if r["src_ip"] == target["src_ip"] and r["protocol"] == "UDP"
             and r["packets"] == 1 and is_atomic(r)
             and r["src_port"] != DNS_PORT and r["dst_port"] != DNS_PORT]
    dst_ips = {r["dst_ip"] for r in group}
    dst_ports = [r["dst_port"] for r in group]
    bvals = [r["bytes"] for r in group]
    src_ports = {r["src_port"] for r in group}

    signals = {
        "muchas_ips_destino": len(dst_ips) >= CTX_UDP_MIN_DST_IPS,
        "muchos_puertos_destino": len(set(dst_ports)) >= CTX_UDP_MIN_DST_PORTS,
        "baja_varianza_bytes": safe_variance(bvals) < CTX_UDP_BYTES_VAR_MAX,
        "barrido_secuencial": is_mostly_sequential(dst_ports),
        "puerto_origen_caracteristico": bool(src_ports & UDP_KNOWN_SRC_PORTS),
    }
    if not (signals["muchas_ips_destino"] and signals["muchos_puertos_destino"]):
        return None
    n, level = grade(signals)
    return {
        "family": "anomaly-udpscan", "n_signals": n, "confidence": level,
        "evidence": f"traza pertenece a escaneo UDP desde {target['src_ip']} "
                    f"({len(dst_ips)} IPs / {len(set(dst_ports))} puertos destino en contexto); "
                    + signals_text(signals),
        "limitations": [],
    }


def member_dos(target, context):
    if not (target["protocol"] == "TCP" and is_atomic(target)):
        return None
    group = [r for r in context
             if r["src_ip"] == target["src_ip"] and r["dst_ip"] == target["dst_ip"]
             and r["dst_port"] == target["dst_port"] and r["protocol"] == "TCP" and is_atomic(r)]
    if len(group) < CTX_DOS_MIN_GROUP:
        return None
    pair_total = sum(1 for r in context
                     if r["src_ip"] == target["src_ip"] and r["dst_ip"] == target["dst_ip"]
                     and r["protocol"] == "TCP" and is_atomic(r))
    port_share = ratio(len(group), pair_total)
    src_ports = [r["src_port"] for r in group]
    bvals = [r["bytes"] for r in group]
    ts = [r["timestamp"] for r in group]
    burst = ratio(Counter(ts).most_common(1)[0][1], len(group))

    signals = {
        "concentracion_volumen": len(group) >= CTX_DOS_MIN_GROUP,
        "puerto_destino_concentrado": port_share >= DOS_PORT_CONCENTRATION,
        "secuencial_o_rafaga": is_mostly_sequential(src_ports) or burst >= 0.5,
        "duracion_cero": ratio(sum(1 for r in group if r["duration"] <= ZERO_DURATION_THRESHOLD), len(group)) >= 0.9,
        "baja_varianza_bytes": safe_variance(bvals) < DOS_BYTES_VAR_MAX,
    }
    if not (signals["concentracion_volumen"] and signals["puerto_destino_concentrado"]
            and signals["secuencial_o_rafaga"]):
        return None
    n, level = grade(signals)
    return {
        "family": "dos", "n_signals": n, "confidence": level,
        "evidence": f"traza pertenece a inundación TCP {target['src_ip']}->"
                    f"{target['dst_ip']}:{target['dst_port']} ({len(group)} flujos, "
                    f"cuota puerto {port_share}); " + signals_text(signals),
        "limitations": [],
    }


def member_ssh_scan(target, context):
    if not (target["protocol"] == "TCP" and target["dst_port"] == SSH_PORT
            and is_atomic(target) and target["bytes"] <= SSH_BYTES_MAX):
        return None
    group = [r for r in context
             if r["src_ip"] == target["src_ip"] and r["protocol"] == "TCP"
             and r["dst_port"] == SSH_PORT and is_atomic(r)]
    dst_ips = {r["dst_ip"] for r in group}
    control = ratio(sum(1 for r in group if has_flag(r["flags"], "R") or has_flag(r["flags"], "S")), len(group))

    signals = {
        "barrido_horizontal": len(dst_ips) >= CTX_SSH_MIN_DST_IPS,
        "flujos_incompletos": control >= 0.5,
        "flujos_atomicos": is_atomic(target),
    }
    if not signals["barrido_horizontal"]:
        return None
    n, level = grade(signals, cap="media")  # low-and-slow: confianza máx. media
    return {
        "family": "anomaly-sshscan", "n_signals": n, "confidence": level,
        "evidence": f"traza pertenece a sondeo SSH horizontal desde {target['src_ip']} "
                    f"({len(dst_ips)} destinos al puerto 22 en contexto); " + signals_text(signals),
        "limitations": ["patrón low-and-slow: la persistencia entre ventanas no se valida en el contexto local"],
    }


def member_nerisbotnet(target, context):
    # La señal de botnet es la COORDINACIÓN entre nodos sobre servicios C2/spam.
    # Se restringe a puertos C2 fuertes (25/6667/2077): un clúster de métricas
    # idénticas en cualquier puerto coincide con ráfagas triviales de background
    # (SYN a puerto 80, DNS, etc.) y generaría falsos positivos masivos.
    if target["dst_port"] not in NERIS_C2_PORTS:
        return None
    # Coordinación: varios orígenes con métricas idénticas en el mismo instante.
    cluster = [r for r in context
               if r["dst_port"] == target["dst_port"] and r["bytes"] == target["bytes"]
               and r["packets"] == target["packets"] and r["timestamp"] == target["timestamp"]]
    srcs = {r["src_ip"] for r in cluster}
    if len(srcs) < CTX_NERIS_MIN_SOURCES:
        return None
    service_ports = {p for p in NERIS_SERVICE_PORTS if any(r["dst_port"] == p for r in context)}
    subnets = Counter(subnet_24(s) for s in srcs)

    signals = {
        "cluster_coordinado": len(srcs) >= CTX_NERIS_MIN_SOURCES,
        "puerto_c2": True,  # garantizado por el filtro previo
        "multivector": len(service_ports) >= 2,
        "origenes_agrupados": subnets.most_common(1)[0][1] >= CTX_NERIS_MIN_SOURCES,
    }
    n, level = grade(signals)
    return {
        "family": "nerisbotnet", "n_signals": n, "confidence": level,
        "evidence": f"traza pertenece a clúster C2 coordinado de {len(srcs)} orígenes con firma "
                    f"idéntica (puerto {target['dst_port']}, {target['bytes']} bytes, "
                    f"{target['packets']} paquetes); " + signals_text(signals),
        "limitations": [],
    }


def member_spam(target, context):
    if not (target["protocol"] == "TCP" and target["dst_port"] == SPAM_PORT):
        return None
    block = subnet_24(target["src_ip"])
    group = [r for r in context
             if r["protocol"] == "TCP" and r["dst_port"] == SPAM_PORT
             and (r["src_ip"] == target["src_ip"] or subnet_24(r["src_ip"]) == block)]
    if len(group) < CTX_SPAM_MIN_FLOWS:
        return None
    dst_ips = {r["dst_ip"] for r in group}
    packets = [r["packets"] for r in group]
    bvals = [r["bytes"] for r in group]
    lo, hi = SPAM_PACKET_RANGE
    packet_match = ratio(sum(1 for p in packets if lo <= p <= hi), len(group))
    bytes_match = ratio(sum(1 for b in bvals if b in SPAM_KNOWN_BYTES), len(group))

    signals = {
        "metricas_repetitivas": packet_match >= 0.5 or bytes_match >= 0.3,
        "barrido_horizontal": len(dst_ips) >= 2,
        "baja_varianza_bytes": safe_variance(bvals) < 5_000,
    }
    if not signals["metricas_repetitivas"]:
        return None
    n, level = grade(signals, cap="baja")  # baja evidencia
    return {
        "family": "anomaly-spam", "n_signals": n, "confidence": level,
        "evidence": f"traza pertenece a posible patrón SMTP horizontal desde {block}.x "
                    f"({len(group)} flujos al puerto 25, {len(dst_ips)} destinos); " + signals_text(signals),
        "limitations": ["anomaly-spam es exploratorio: baja evidencia y riesgo de confusión con SMTP legítimo"],
    }


# ---------------------------------------------------------------------------
# Filtro previo barato: ¿merece la traza un análisis contextual?
# ---------------------------------------------------------------------------

def is_interesting(r):
    """
    Una sesión completa (multipaquete, duración apreciable) no encaja en los
    patrones sintéticos estudiados; se marca background sin coste de contexto.
    Solo se analizan en detalle las trazas atómicas o hacia servicios sensibles.
    """
    if r["protocol"] == "TCP" and is_atomic(r):
        return True
    if r["protocol"] == "UDP" and r["packets"] == 1 and r["duration"] <= ZERO_DURATION_THRESHOLD:
        return True
    if r["dst_port"] in (SSH_PORT, SPAM_PORT):
        return True
    if r["dst_port"] in NERIS_C2_PORTS:
        return True
    return False


# ---------------------------------------------------------------------------
# Clasificación de una traza por su contexto
# ---------------------------------------------------------------------------

def classify_flow(target, context):
    """Devuelve (predicted_family|None, confidence, evidence, limitations)."""
    results = []

    if target["protocol"] == "TCP" and is_atomic(target) and has_flag(target["flags"], "S"):
        vscan = context_vertical_scanners(context, CTX_SCAN_MIN_DST_PORTS)
        for fn in (member_scan44, member_scan11):
            r = fn(target, context, vscan)
            if r:
                results.append(r)

    for fn in (member_udp_scan, member_dos, member_ssh_scan, member_nerisbotnet, member_spam):
        r = fn(target, context)
        if r:
            results.append(r)

    if not results:
        return None, "insuficiente", "", []

    # scan44 (distribuido) subsume scan11 (un origen)
    fams = {r["family"] for r in results}
    if "scan44" in fams:
        results = [r for r in results if r["family"] != "scan11"]

    # Prioridad: nº de señales -> confianza -> especificidad del patrón
    winner = max(results, key=lambda r: (
        r["n_signals"],
        CONFIDENCE_RANK[r["confidence"]],
        -WIN_PRECEDENCE.index(r["family"]),
    ))
    others = [r["family"] for r in results if r["family"] != winner["family"]]
    evidence = winner["evidence"]
    if others:
        evidence += " | otras señales: " + ", ".join(sorted(set(others)))
    return winner["family"], winner["confidence"], evidence, winner["limitations"]


# ---------------------------------------------------------------------------
# Recorrido de ficheros
# ---------------------------------------------------------------------------

def is_window_file(path):
    if "descartados" in path.parts:  # material retirado del análisis principal
        return False
    if path.name in SKIP_NAMES:
        return False
    if any(path.name.endswith(s) for s in SKIP_SUFFIXES):
        return False
    return True


OUTPUT_FIELDS = [
    "source_file", "row_index", "timestamp", "src_ip", "dst_ip",
    "src_port", "dst_port", "protocol", "flags", "duration", "packets", "bytes",
    "original_label", "predicted_label", "predicted_family", "is_attack",
    "confidence", "context_start", "context_end", "context_size",
    "evidence", "limitations",
]


def process_window(rows, source_file, writer, stats):
    n = len(rows)
    for i, target in enumerate(rows):
        start = max(0, i - CONTEXT_ROWS_BEFORE)
        end = min(n, i + CONTEXT_ROWS_AFTER + 1)
        context_size = end - start

        if is_interesting(target):
            context = rows[start:end]
            family, confidence, evidence, limitations = classify_flow(target, context)
        else:
            family, confidence, evidence, limitations = (
                None, "insuficiente",
                "flujo no atómico / sesión completa: no encaja en patrones sintéticos", [])

        if family is not None:
            predicted_label = family
            predicted_family = family
            is_attack = True
            stats["attack"] += 1
        else:
            # interesante pero sin grupo -> no_clasificado; resto -> background
            predicted_label = "no_clasificado" if is_interesting(target) else "background"
            predicted_family = "none"
            is_attack = False
            stats["background"] += 1

        # contexto parcial en los bordes de la ventana
        if context_size < (CONTEXT_ROWS_BEFORE + CONTEXT_ROWS_AFTER + 1):
            limitations = list(limitations) + ["contexto parcial (borde de ventana)"]

        original_label = target["label"]
        stats["pred_counts"][predicted_label] += 1
        stats["orig_counts"][original_label] += 1
        if predicted_family != "none" and predicted_family == original_label:
            stats["correct"][predicted_family] += 1
        stats["total"] += 1

        writer.writerow({
            "source_file": source_file,
            "row_index": i,
            "timestamp": target["timestamp"],
            "src_ip": target["src_ip"],
            "dst_ip": target["dst_ip"],
            "src_port": target["src_port"],
            "dst_port": target["dst_port"],
            "protocol": target["protocol"],
            "flags": target["flags"],
            "duration": target["duration"],
            "packets": target["packets"],
            "bytes": target["bytes"],
            "original_label": original_label,
            "predicted_label": predicted_label,
            "predicted_family": predicted_family,
            "is_attack": str(is_attack).lower(),
            "confidence": confidence,
            "context_start": start,
            "context_end": end - 1,
            "context_size": context_size,
            "evidence": evidence,
            "limitations": " | ".join(limitations),
        })


def write_summary(stats):
    SUMMARY_FILE.parent.mkdir(parents=True, exist_ok=True)
    labels = sorted(set(stats["pred_counts"]) | set(stats["orig_counts"]))
    with open(SUMMARY_FILE, "w", encoding="utf-8", newline="") as f:
        w = csv.writer(f)
        w.writerow(["label", "predicted_count", "original_count",
                    "correct_match", "approx_precision"])
        for lbl in labels:
            pred = stats["pred_counts"].get(lbl, 0)
            orig = stats["orig_counts"].get(lbl, 0)
            correct = stats["correct"].get(lbl, 0)
            prec = round(correct / pred, 3) if pred else ""
            w.writerow([lbl, pred, orig, correct, prec])
        w.writerow([])
        w.writerow(["TOTAL_trazas", stats["total"], "", "", ""])
        w.writerow(["trazas_ataque", stats["attack"], "", "", ""])
        w.writerow(["trazas_background", stats["background"], "", "", ""])


def print_summary(stats):
    print("\n===== RESUMEN CLASIFICACIÓN POR TRAZA =====")
    print(f"Total de trazas analizadas: {stats['total']}")
    print(f"  Marcadas como ataque:     {stats['attack']}")
    print(f"  Marcadas como background: {stats['background']}")
    print("\nConteo por predicted_label:")
    for lbl, c in stats["pred_counts"].most_common():
        print(f"  {lbl:<18} {c}")
    print("\nComparación con original_label (precisión aproximada por familia):")
    for fam in FAMILIES:
        pred = stats["pred_counts"].get(fam, 0)
        correct = stats["correct"].get(fam, 0)
        if pred:
            print(f"  {fam:<18} {correct}/{pred}  (prec~{round(correct/pred, 3)})")
        else:
            print(f"  {fam:<18} 0 predichas")
    print("\nLimitaciones de la evaluación:")
    print("  - La etiqueta original del UGR'16 se usa SOLO como referencia, no es infalible.")
    print("  - Las ventanas solapan vistas del mismo tráfico: hay trazas duplicadas entre ficheros.")
    print("  - La precisión por familia depende de la densidad del ataque dentro del contexto local.")


def main():
    if not BASE_DIR.exists():
        print(f"[ERROR] No existe la carpeta de ventanas: {BASE_DIR}")
        return

    files = sorted(p for p in BASE_DIR.rglob("*.csv") if is_window_file(p))
    if not files:
        print("[ERROR] No se han encontrado ventanas CSV en data/attack_analysis/")
        return

    stats = {
        "total": 0, "attack": 0, "background": 0,
        "pred_counts": Counter(), "orig_counts": Counter(), "correct": Counter(),
    }

    RESULTS_FILE.parent.mkdir(parents=True, exist_ok=True)
    print(f"\n===== CLASIFICACIÓN CONTEXTUAL POR TRAZA ({len(files)} ventanas) =====")
    print(f"Contexto local: -{CONTEXT_ROWS_BEFORE} / +{CONTEXT_ROWS_AFTER} filas\n")

    with open(RESULTS_FILE, "w", encoding="utf-8", newline="") as out:
        writer = csv.DictWriter(out, fieldnames=OUTPUT_FIELDS, extrasaction="ignore")
        writer.writeheader()
        for idx, file_path in enumerate(files, 1):
            rows = load_window(file_path)
            source_file = str(file_path).replace("\\", "/")
            if rows:
                process_window(rows, source_file, writer, stats)
            print(f"[{idx}/{len(files)}] {source_file}  ({len(rows)} trazas)")

    write_summary(stats)
    print_summary(stats)
    print(f"\nResultados por traza: {RESULTS_FILE}")
    print(f"Resumen:              {SUMMARY_FILE}")


if __name__ == "__main__":
    main()

"""
Script: detect_attack_flows_contextual_v2.py

Clasificador CONTEXTUAL POR TRAZA, versión 2 (JERÁRQUICO en dos etapas).

Motivación
----------
El análisis de errores de la v1 (Docs/NotebookLLM/23_...) mostró que las
métricas bajas mezclaban DOS problemas distintos:
  1. confusión entre subtipos de ataque (scan44 etiquetado como scan11), y
  2. fuga real a background/no_clasificado (udpscan, nerisbotnet).

La v2 separa explícitamente ambos planos mediante dos etapas:

  ETAPA 1 - Detección binaria contextual
    Para cada traza, usando su contexto local, decide:
        attack | background | insufficient_evidence
    Responde "¿esta traza pertenece a comportamiento sintético/anómalo?",
    sin intentar todavía el subtipo exacto.

  ETAPA 2 - Clasificación conductual (solo para trazas 'attack')
    Asigna familia conductual, subtipo (con su propia confianza), evidencia y
    limitaciones.

Familias conductuales:
    vertical_scan, udp_scan, tcp_flood, coordinated_botnet,
    ssh_horizontal_scan, smtp_campaign, unknown_attack

Subtipos (más finos, pueden quedar indeterminados):
    scan11, scan44, anomaly-udpscan, dos, nerisbotnet,
    anomaly-sshscan, anomaly-spam

Reglas clave (según especificación):
  1. scan11 y scan44 comparten PRIMERO la familia vertical_scan.
  2. La separación scan11/scan44 es SECUNDARIA y puede tener incertidumbre.
  3. Si el contexto solo permite afirmar vertical_scan, NO se fuerza scan11/scan44.
  4. tcp_flood (dos) se separa de vertical_scan por concentración fuerte en
     dst_ip/dst_port y BAJA diversidad de dst_port.
  5. udp_scan usa dispersión UDP por src_ip, con un contexto algo más amplio.
  6. coordinated_botnet exige coordinación multinodo; si es débil, baja confianza.
  7. ssh_horizontal_scan y smtp_campaign se tratan como baja evidencia salvo
     persistencia suficiente.
  8. No se usan IPs concretas. 9. No se usan labels para detectar (solo evaluar).
  10. No es ML. 11. Evidencia interpretable por traza.

Salida:
  - data/attack_analysis/flow_level_detection_results_v2.csv
  - data/attack_analysis/flow_level_detection_summary_v2.csv

Uso:
  python scripts/02_attack_analysis/detect_attack_flows_contextual_v2.py

NOTA: no modifica detect_attack_flows_contextual.py, detect_synthetic_behavior.py
ni detect_synthetic_behavior_extended.py.
"""

import csv
from pathlib import Path
from collections import Counter, defaultdict
from statistics import variance

# ---------------------------------------------------------------------------
# Configuración general
# ---------------------------------------------------------------------------

BASE_DIR = Path("data/attack_analysis")
RESULTS_FILE = BASE_DIR / "flow_level_detection_results_v2.csv"
SUMMARY_FILE = BASE_DIR / "flow_level_detection_summary_v2.csv"

EXPECTED_COLUMNS = 13

SKIP_SUFFIXES = ("_extraction_summary.csv",)
SKIP_NAMES = (
    "behavior_detection_results.csv",
    "behavior_detection_results_extended.csv",
    "window_extraction_summary.csv",
    "flow_level_detection_results.csv",
    "flow_level_detection_summary.csv",
    "flow_level_detection_results_v2.csv",
    "flow_level_detection_summary_v2.csv",
)

# ---------------------------------------------------------------------------
# Contexto local (ajustable)
# ---------------------------------------------------------------------------

CONTEXT_ROWS_BEFORE = 30
CONTEXT_ROWS_AFTER = 30

# Regla 5: udp_scan usa un contexto algo más amplio para captar dispersión lenta.
CONTEXT_UDP_BEFORE = 60
CONTEXT_UDP_AFTER = 60

# Reservado para un futuro contexto temporal (no implementado).
USE_TEMPORAL_CONTEXT = False
CONTEXT_TIME_WINDOW_SECONDS = 10

# ---------------------------------------------------------------------------
# Umbrales (escalados al contexto local)
# ---------------------------------------------------------------------------

ZERO_DURATION_THRESHOLD = 0.01
LOW_PACKET_THRESHOLD = 2
SMALL_BYTES_MAX = 100
LOW_BYTES_VARIANCE = 50

# Barrido vertical (familia vertical_scan)
CTX_VERTICAL_MIN_DST_PORTS = 8        # core: verticalidad confirmada
CTX_VERTICAL_PARTIAL_DST_PORTS = 4    # estructura parcial -> insufficient_evidence
DOM_HIGH = 0.8                        # un origen domina con claridad -> scan11
DOM_LOW = 0.6                         # reparto claro entre orígenes -> scan44

# tcp_flood (subtipo dos)
CTX_FLOOD_MIN_GROUP = 10              # flujos al mismo dst_ip:puerto
FLOOD_PORT_CONCENTRATION = 0.6        # cuota del puerto dominante en el par
FLOOD_MAX_PAIR_DST_PORTS = 3          # baja diversidad de dst_port (regla 4)
FLOOD_BYTES_VAR_MAX = 10_000

# udp_scan (subtipo anomaly-udpscan)
CTX_UDP_MIN_DST_IPS = 4
CTX_UDP_MIN_DST_PORTS = 6
CTX_UDP_PARTIAL_DST_IPS = 2
CTX_UDP_BYTES_VAR_MAX = 200
DNS_PORT = 53

# coordinated_botnet (subtipo nerisbotnet)
NERIS_C2_PORTS = {25, 6667, 2077}
NERIS_SERVICE_PORTS = {25, 6667, 53, 2077}
CTX_NERIS_MIN_SOURCES = 3            # coordinación firme
CTX_NERIS_WEAK_SOURCES = 2           # coordinación débil -> baja confianza (regla 6)

# ssh_horizontal_scan (subtipo anomaly-sshscan)
SSH_PORT = 22
CTX_SSH_MIN_DST_IPS = 3
SSH_BYTES_MAX = 44

# smtp_campaign (subtipo anomaly-spam)
SPAM_PORT = 25
CTX_SPAM_MIN_FLOWS = 3
SPAM_PACKET_RANGE = (8, 13)
SPAM_KNOWN_BYTES = {763, 815, 841, 893, 3136, 3143}

# unknown_attack: ráfaga atómica estructurada de tipo ambiguo (catch-all ESTRICTO)
CTX_UNKNOWN_MIN_GROUP = 20
CTX_UNKNOWN_BYTES_VAR_MAX = 5     # entropía casi nula (sintético), no ráfaga normal

# Etapa 1: umbral de score para confirmar ataque genérico
ATTACK_SCORE_STRONG = 0.6

CONFIDENCE_RANK = {"insuficiente": 0, "baja": 1, "media": 2, "alta": 3}

# Familias y precedencia (más específica gana el desempate)
FAMILY_PRECEDENCE = [
    "coordinated_botnet", "udp_scan", "tcp_flood", "vertical_scan",
    "ssh_horizontal_scan", "smtp_campaign", "unknown_attack",
]

# Mapa subtipo original -> familia conductual (solo para evaluación)
LABEL_TO_FAMILY = {
    "scan11": "vertical_scan",
    "scan44": "vertical_scan",
    "anomaly-udpscan": "udp_scan",
    "dos": "tcp_flood",
    "nerisbotnet": "coordinated_botnet",
    "anomaly-sshscan": "ssh_horizontal_scan",
    "anomaly-spam": "smtp_campaign",
}
ATTACK_LABELS = set(LABEL_TO_FAMILY)


# ---------------------------------------------------------------------------
# Utilidades
# ---------------------------------------------------------------------------

def safe_int(v, d=0):
    try:
        return int(v)
    except Exception:
        return d


def safe_float(v, d=0.0):
    try:
        return float(v)
    except Exception:
        return d


def safe_variance(values):
    return variance(values) if len(values) > 1 else 0.0


def mode_value(values):
    return Counter(values).most_common(1)[0][0] if values else 0


def has_flag(flags, ch):
    return ch in (flags or "")


def subnet_24(ip):
    p = ip.split(".")
    return ".".join(p[:3]) if len(p) == 4 else ip


def ratio(c, t):
    return round(c / t, 3) if t else 0.0


def is_mostly_sequential(values, min_ratio=0.65):
    values = sorted(set(v for v in values if v > 0))
    if len(values) < 5:
        return False
    diffs = [b - a for a, b in zip(values, values[1:])]
    if not diffs:
        return False
    valid = [d for d in diffs if d in (1, 2)]
    return len(valid) / len(diffs) >= min_ratio


def level_from_fraction(frac, cap=None):
    if frac >= 0.8:
        lvl = "alta"
    elif frac >= 0.6:
        lvl = "media"
    elif frac >= 0.4:
        lvl = "baja"
    else:
        lvl = "insuficiente"
    if cap is not None and CONFIDENCE_RANK[lvl] > CONFIDENCE_RANK[cap]:
        lvl = cap
    return lvl


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
# Carga
# ---------------------------------------------------------------------------

def load_window(file_path):
    rows = []
    with open(file_path, "r", encoding="utf-8", errors="ignore", newline="") as f:
        for row in csv.reader(f):
            if len(row) != EXPECTED_COLUMNS:
                continue
            rows.append({
                "timestamp": row[0], "duration": safe_float(row[1]),
                "src_ip": row[2], "dst_ip": row[3],
                "src_port": safe_int(row[4]), "dst_port": safe_int(row[5]),
                "protocol": row[6], "flags": row[7],
                "packets": safe_int(row[10]), "bytes": safe_int(row[11]),
                "label": row[12].strip(),
            })
    return rows


# ---------------------------------------------------------------------------
# Estructura compartida: escáneres verticales SYN en el contexto
# ---------------------------------------------------------------------------

def context_vertical_scanners(context, min_ports):
    cand = [r for r in context
            if r["protocol"] == "TCP" and is_atomic(r) and has_flag(r["flags"], "S")]
    pairs = defaultdict(list)
    for r in cand:
        pairs[(r["src_ip"], r["dst_ip"])].append(r)
    vertical = {k: g for k, g in pairs.items()
                if len({r["dst_port"] for r in g}) >= min_ports}
    by_src = defaultdict(int)
    ts_srcs = defaultdict(set)
    for (src, _d), g in vertical.items():
        by_src[src] += len(g)
        for r in g:
            ts_srcs[r["timestamp"]].add(src)
    scanners = sorted(by_src.items(), key=lambda kv: kv[1], reverse=True)
    total = sum(n for _s, n in scanners)
    top_share = ratio(scanners[0][1], total) if scanners else 0.0
    temporal_sync = any(len(s) >= 2 for s in ts_srcs.values())
    return {"vertical_pairs": vertical, "scanners": scanners,
            "top_share": top_share, "temporal_sync": temporal_sync}


# ---------------------------------------------------------------------------
# Detectores de familia (ETAPA 2). Devuelven dict con:
#   family, subtype, subtype_confidence, core_ok, partial, strength,
#   confidence, evidence, limitations
# o None si la traza no es ni siquiera candidata.
# ---------------------------------------------------------------------------

def detect_vertical_scan(target, context, vscan):
    if not (target["protocol"] == "TCP" and is_atomic(target) and has_flag(target["flags"], "S")):
        return None
    pair = (target["src_ip"], target["dst_ip"])

    # ¿pertenece a un par con verticalidad (parcial o confirmada)?
    same_pair = [r for r in context
                 if r["src_ip"] == pair[0] and r["dst_ip"] == pair[1]
                 and r["protocol"] == "TCP" and is_atomic(r) and has_flag(r["flags"], "S")]
    n_dports = len({r["dst_port"] for r in same_pair})
    if n_dports < CTX_VERTICAL_PARTIAL_DST_PORTS:
        return None  # sin verticalidad ni parcial

    bvals = [r["bytes"] for r in same_pair]
    signals = {
        "verticalidad": n_dports >= CTX_VERTICAL_MIN_DST_PORTS,
        "flujos_atomicos": is_atomic(target),
        "bytes_pequenos": mode_value(bvals) <= SMALL_BYTES_MAX,
        "baja_entropia_bytes": safe_variance(bvals) < LOW_BYTES_VARIANCE,
    }
    core_ok = signals["verticalidad"]
    strength = sum(1 for v in signals.values() if v) / len(signals)

    # Subtipo (secundario, con incertidumbre) - reglas 1, 2, 3
    n_scanners = len(vscan["scanners"]) if vscan else 0
    top_share = vscan["top_share"] if vscan else 0.0
    sync = vscan["temporal_sync"] if vscan else False
    is_dominant_src = bool(vscan and vscan["scanners"] and target["src_ip"] == vscan["scanners"][0][0])

    subtype, sub_conf = "undetermined", "insuficiente"
    if core_ok:
        if n_scanners <= 1 or (top_share >= DOM_HIGH and is_dominant_src):
            subtype, sub_conf = "scan11", "alta"
        elif top_share >= DOM_LOW and is_dominant_src:
            subtype, sub_conf = "scan11", "media"
        elif n_scanners >= 2 and top_share < DOM_LOW and sync:
            subtype, sub_conf = "scan44", "media"
        elif n_scanners >= 2 and top_share < DOM_HIGH:
            subtype, sub_conf = "scan44", "baja"
        else:
            subtype, sub_conf = "undetermined", "insuficiente"

    limitations = []
    if core_ok and subtype == "undetermined":
        limitations.append("contexto local insuficiente para separar scan11/scan44")
    return {
        "family": "vertical_scan", "subtype": subtype, "subtype_confidence": sub_conf,
        "core_ok": core_ok, "partial": (not core_ok),
        "strength": strength, "confidence": level_from_fraction(strength),
        "evidence": f"par {pair[0]}->{pair[1]} con {n_dports} puertos destino SYN en contexto "
                    f"(orígenes verticales={n_scanners}, cuota={top_share}); " + signals_text(signals),
        "limitations": limitations,
    }


def detect_tcp_flood(target, context):
    if not (target["protocol"] == "TCP" and is_atomic(target)):
        return None
    pair_rows = [r for r in context
                 if r["src_ip"] == target["src_ip"] and r["dst_ip"] == target["dst_ip"]
                 and r["protocol"] == "TCP" and is_atomic(r)]
    group = [r for r in pair_rows if r["dst_port"] == target["dst_port"]]
    if len(group) < CTX_FLOOD_MIN_GROUP:
        return None
    pair_dst_ports = len({r["dst_port"] for r in pair_rows})
    port_share = ratio(len(group), len(pair_rows))
    src_ports = [r["src_port"] for r in group]
    bvals = [r["bytes"] for r in group]
    ts = [r["timestamp"] for r in group]
    burst = ratio(Counter(ts).most_common(1)[0][1], len(group))

    signals = {
        "concentracion_volumen": len(group) >= CTX_FLOOD_MIN_GROUP,
        "puerto_destino_concentrado": port_share >= FLOOD_PORT_CONCENTRATION,
        "baja_diversidad_puertos": pair_dst_ports <= FLOOD_MAX_PAIR_DST_PORTS,  # regla 4
        "secuencial_o_rafaga": is_mostly_sequential(src_ports) or burst >= 0.5,
        "baja_varianza_bytes": safe_variance(bvals) < FLOOD_BYTES_VAR_MAX,
    }
    # Núcleo: concentración + puerto fijo + BAJA diversidad (no es barrido vertical)
    core_ok = (signals["concentracion_volumen"] and signals["puerto_destino_concentrado"]
               and signals["baja_diversidad_puertos"] and signals["secuencial_o_rafaga"])
    strength = sum(1 for v in signals.values() if v) / len(signals)
    if not core_ok and strength < 0.4:
        return None
    return {
        "family": "tcp_flood", "subtype": "dos", "subtype_confidence": level_from_fraction(strength),
        "core_ok": core_ok, "partial": (not core_ok),
        "strength": strength, "confidence": level_from_fraction(strength),
        "evidence": f"inundación TCP {target['src_ip']}->{target['dst_ip']}:{target['dst_port']} "
                    f"({len(group)} flujos, cuota puerto {port_share}, "
                    f"diversidad puertos del par={pair_dst_ports}); " + signals_text(signals),
        "limitations": [],
    }


def detect_udp_scan(target, wide_context):
    if not (target["protocol"] == "UDP" and target["packets"] == 1 and is_atomic(target)):
        return None
    if target["src_port"] == DNS_PORT or target["dst_port"] == DNS_PORT:
        return None
    group = [r for r in wide_context
             if r["src_ip"] == target["src_ip"] and r["protocol"] == "UDP"
             and r["packets"] == 1 and is_atomic(r)
             and r["src_port"] != DNS_PORT and r["dst_port"] != DNS_PORT]
    n_ips = len({r["dst_ip"] for r in group})
    dports = [r["dst_port"] for r in group]
    n_ports = len(set(dports))
    if n_ips < CTX_UDP_PARTIAL_DST_IPS:
        return None
    bvals = [r["bytes"] for r in group]
    signals = {
        "muchas_ips_destino": n_ips >= CTX_UDP_MIN_DST_IPS,
        "muchos_puertos_destino": n_ports >= CTX_UDP_MIN_DST_PORTS,
        "baja_varianza_bytes": safe_variance(bvals) < CTX_UDP_BYTES_VAR_MAX,
        "barrido_secuencial": is_mostly_sequential(dports),
    }
    core_ok = signals["muchas_ips_destino"] and signals["muchos_puertos_destino"]
    strength = sum(1 for v in signals.values() if v) / len(signals)
    return {
        "family": "udp_scan", "subtype": "anomaly-udpscan",
        "subtype_confidence": level_from_fraction(strength),
        "core_ok": core_ok, "partial": (not core_ok),
        "strength": strength, "confidence": level_from_fraction(strength),
        "evidence": f"dispersión UDP desde {target['src_ip']} ({n_ips} IPs / {n_ports} puertos "
                    f"destino en contexto amplio); " + signals_text(signals),
        "limitations": [],
    }


def detect_coordinated_botnet(target, context):
    if target["dst_port"] not in NERIS_C2_PORTS:
        return None
    cluster = [r for r in context
               if r["dst_port"] == target["dst_port"] and r["bytes"] == target["bytes"]
               and r["packets"] == target["packets"] and r["timestamp"] == target["timestamp"]]
    n_srcs = len({r["src_ip"] for r in cluster})
    if n_srcs < CTX_NERIS_WEAK_SOURCES:
        return None
    service_ports = {p for p in NERIS_SERVICE_PORTS if any(r["dst_port"] == p for r in context)}
    subnets = Counter(subnet_24(r["src_ip"]) for r in cluster)
    signals = {
        "coordinacion_firme": n_srcs >= CTX_NERIS_MIN_SOURCES,
        "puerto_c2": True,
        "multivector": len(service_ports) >= 2,
        "origenes_agrupados": subnets.most_common(1)[0][1] >= CTX_NERIS_WEAK_SOURCES,
    }
    core_ok = signals["coordinacion_firme"]
    strength = sum(1 for v in signals.values() if v) / len(signals)
    # Regla 6: coordinación débil -> baja confianza
    cap = None if n_srcs >= CTX_NERIS_MIN_SOURCES else "baja"
    conf = level_from_fraction(strength, cap=cap)
    limitations = []
    if n_srcs < CTX_NERIS_MIN_SOURCES:
        limitations.append("coordinación multinodo débil (pocos orígenes): baja confianza")
    return {
        "family": "coordinated_botnet", "subtype": "nerisbotnet", "subtype_confidence": conf,
        "core_ok": core_ok, "partial": (not core_ok),
        "strength": strength, "confidence": conf,
        "evidence": f"clúster C2 de {n_srcs} orígenes con firma idéntica (puerto "
                    f"{target['dst_port']}, {target['bytes']} bytes); " + signals_text(signals),
        "limitations": limitations,
    }


def detect_ssh_horizontal(target, context):
    if not (target["protocol"] == "TCP" and target["dst_port"] == SSH_PORT
            and is_atomic(target) and target["bytes"] <= SSH_BYTES_MAX):
        return None
    group = [r for r in context
             if r["src_ip"] == target["src_ip"] and r["protocol"] == "TCP"
             and r["dst_port"] == SSH_PORT and is_atomic(r)]
    n_ips = len({r["dst_ip"] for r in group})
    if n_ips < CTX_SSH_MIN_DST_IPS:
        return None
    control = ratio(sum(1 for r in group if has_flag(r["flags"], "R") or has_flag(r["flags"], "S")), len(group))
    signals = {"barrido_horizontal": n_ips >= CTX_SSH_MIN_DST_IPS, "flujos_incompletos": control >= 0.5}
    core_ok = signals["barrido_horizontal"]
    strength = sum(1 for v in signals.values() if v) / len(signals)
    # Regla 7: baja evidencia salvo persistencia (no observable en contexto local)
    conf = level_from_fraction(strength, cap="baja")
    return {
        "family": "ssh_horizontal_scan", "subtype": "anomaly-sshscan", "subtype_confidence": conf,
        "core_ok": core_ok, "partial": (not core_ok),
        "strength": strength, "confidence": conf,
        "evidence": f"sondeo SSH horizontal desde {target['src_ip']} ({n_ips} destinos al puerto 22); "
                    + signals_text(signals),
        "limitations": ["persistencia temporal no verificable en contexto local: posible falso positivo de fondo"],
    }


def detect_smtp_campaign(target, context):
    if not (target["protocol"] == "TCP" and target["dst_port"] == SPAM_PORT):
        return None
    block = subnet_24(target["src_ip"])
    group = [r for r in context
             if r["protocol"] == "TCP" and r["dst_port"] == SPAM_PORT
             and (r["src_ip"] == target["src_ip"] or subnet_24(r["src_ip"]) == block)]
    if len(group) < CTX_SPAM_MIN_FLOWS:
        return None
    n_ips = len({r["dst_ip"] for r in group})
    packets = [r["packets"] for r in group]
    bvals = [r["bytes"] for r in group]
    lo, hi = SPAM_PACKET_RANGE
    pmatch = ratio(sum(1 for p in packets if lo <= p <= hi), len(group))
    bmatch = ratio(sum(1 for b in bvals if b in SPAM_KNOWN_BYTES), len(group))
    signals = {
        "repeticion_metricas": pmatch >= 0.5 or bmatch >= 0.3,
        "barrido_horizontal": n_ips >= 2,
        "baja_varianza_bytes": safe_variance(bvals) < 5_000,
    }
    if not signals["repeticion_metricas"]:
        return None
    core_ok = signals["repeticion_metricas"] and signals["barrido_horizontal"]
    strength = sum(1 for v in signals.values() if v) / len(signals)
    conf = level_from_fraction(strength, cap="baja")  # regla 7
    return {
        "family": "smtp_campaign", "subtype": "anomaly-spam", "subtype_confidence": conf,
        "core_ok": core_ok, "partial": (not core_ok),
        "strength": strength, "confidence": conf,
        "evidence": f"patrón SMTP horizontal desde {block}.x ({len(group)} flujos al 25, "
                    f"{n_ips} destinos); " + signals_text(signals),
        "limitations": ["baja evidencia: difícil separar de SMTP legítimo"],
    }


def detect_unknown_attack(target, context):
    """Ráfaga atómica estructurada de tipo ambiguo (catch-all conservador)."""
    if not is_atomic(target):
        return None
    # Solo flujos de UN paquete: firma sintética fuerte (no ráfagas normales).
    group = [r for r in context
             if r["src_ip"] == target["src_ip"] and r["dst_ip"] == target["dst_ip"]
             and r["protocol"] == target["protocol"] and is_atomic(r) and r["packets"] == 1]
    if target["packets"] != 1 or len(group) < CTX_UNKNOWN_MIN_GROUP:
        return None
    bvals = [r["bytes"] for r in group]
    ts = [r["timestamp"] for r in group]
    burst = ratio(Counter(ts).most_common(1)[0][1], len(group))
    signals = {
        "grupo_atomico_denso": len(group) >= CTX_UNKNOWN_MIN_GROUP,
        "entropia_casi_nula": safe_variance(bvals) < CTX_UNKNOWN_BYTES_VAR_MAX,
        "rafaga_temporal": burst >= 0.7,
    }
    core_ok = all(signals.values())
    if not core_ok:
        return None
    strength = sum(1 for v in signals.values() if v) / len(signals)
    return {
        "family": "unknown_attack", "subtype": "", "subtype_confidence": "insuficiente",
        "core_ok": True, "partial": False,
        "strength": strength, "confidence": level_from_fraction(strength, cap="media"),
        "evidence": f"ráfaga atómica de baja entropía sin firma de familia clara "
                    f"({len(group)} flujos {target['protocol']}); " + signals_text(signals),
        "limitations": ["comportamiento anómalo no asignable a una familia conocida"],
    }


# ---------------------------------------------------------------------------
# Filtro previo barato
# ---------------------------------------------------------------------------

def is_interesting(r):
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
# Clasificación jerárquica de una traza
# ---------------------------------------------------------------------------

def classify_flow(target, context, wide_context):
    # ETAPA 2 (se evalúan todas las familias; la etapa 1 se deriva de ellas)
    results = []
    if target["protocol"] == "TCP" and is_atomic(target) and has_flag(target["flags"], "S"):
        vscan = context_vertical_scanners(context, CTX_VERTICAL_MIN_DST_PORTS)
    else:
        vscan = None

    for r in (
        detect_vertical_scan(target, context, vscan),
        detect_tcp_flood(target, context),
        detect_udp_scan(target, wide_context),
        detect_coordinated_botnet(target, context),
        detect_ssh_horizontal(target, context),
        detect_smtp_campaign(target, context),
        detect_unknown_attack(target, context),
    ):
        if r is not None:
            results.append(r)

    confirmed = [r for r in results if r["core_ok"]]
    partial = [r for r in results if not r["core_ok"]]

    # ETAPA 1: decisión binaria
    if confirmed:
        # vertical_scan y tcp_flood son excluyentes; el resto por precedencia/confianza
        if any(r["family"] == "tcp_flood" for r in confirmed):
            confirmed = [r for r in confirmed if r["family"] != "vertical_scan"]
        winner = max(confirmed, key=lambda r: (
            CONFIDENCE_RANK[r["confidence"]], r["strength"],
            -FAMILY_PRECEDENCE.index(r["family"]),
        ))
        attack_score = round(max(r["strength"] for r in confirmed), 3)
        binary = "attack"
        reason = f"miembro confirmado de {winner['family']}"
        return {
            "is_attack_predicted": binary, "attack_score": attack_score,
            "attack_binary_reason": reason,
            "predicted_behavior_family": winner["family"],
            "predicted_attack_subtype": winner["subtype"],
            "subtype_confidence": winner["subtype_confidence"],
            "evidence": winner["evidence"],
            "limitations": " | ".join(winner["limitations"]),
        }

    if partial:
        best = max(partial, key=lambda r: r["strength"])
        attack_score = round(best["strength"], 3)
        return {
            "is_attack_predicted": "insufficient_evidence", "attack_score": attack_score,
            "attack_binary_reason": f"estructura parcial de {best['family']} sin núcleo confirmado",
            "predicted_behavior_family": "", "predicted_attack_subtype": "",
            "subtype_confidence": "",
            "evidence": best["evidence"],
            "limitations": " | ".join(best["limitations"]) if best["limitations"] else "evidencia parcial",
        }

    # background
    if is_interesting(target):
        reason = "flujo atómico aislado: sin estructura de ataque en el contexto"
    else:
        reason = "sesión completa / flujo no atómico: tráfico normal"
    return {
        "is_attack_predicted": "background", "attack_score": 0.0,
        "attack_binary_reason": reason,
        "predicted_behavior_family": "", "predicted_attack_subtype": "",
        "subtype_confidence": "", "evidence": "", "limitations": "",
    }


# ---------------------------------------------------------------------------
# Recorrido y persistencia
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
    "source_file", "row_index", "original_label",
    "is_attack_predicted", "attack_score", "attack_binary_reason",
    "predicted_behavior_family", "predicted_attack_subtype", "subtype_confidence",
    "evidence", "limitations",
]


def process_window(rows, source_file, writer, stats):
    n = len(rows)
    for i, target in enumerate(rows):
        if is_interesting(target):
            s = max(0, i - CONTEXT_ROWS_BEFORE)
            e = min(n, i + CONTEXT_ROWS_AFTER + 1)
            context = rows[s:e]
            if target["protocol"] == "UDP":
                sw = max(0, i - CONTEXT_UDP_BEFORE)
                ew = min(n, i + CONTEXT_UDP_AFTER + 1)
                wide_context = rows[sw:ew]
            else:
                wide_context = context
            res = classify_flow(target, context, wide_context)
        else:
            res = {
                "is_attack_predicted": "background", "attack_score": 0.0,
                "attack_binary_reason": "sesión completa / flujo no atómico: tráfico normal",
                "predicted_behavior_family": "", "predicted_attack_subtype": "",
                "subtype_confidence": "", "evidence": "", "limitations": "",
            }

        original_label = target["label"]
        binary = res["is_attack_predicted"]
        fam = res["predicted_behavior_family"]
        sub = res["predicted_attack_subtype"]

        # --- estadística para el resumen ---
        stats["total"] += 1
        stats["binary"][binary] += 1
        if fam:
            stats["family_pred"][fam] += 1
        if sub:
            stats["subtype_pred"][sub] += 1

        orig_is_attack = original_label in ATTACK_LABELS
        pred_is_attack = binary == "attack"
        if orig_is_attack and pred_is_attack:
            stats["bin_tp"] += 1
        elif orig_is_attack and not pred_is_attack:
            stats["bin_fn"] += 1
        elif (not orig_is_attack) and pred_is_attack:
            stats["bin_fp"] += 1
        else:
            stats["bin_tn"] += 1

        if fam:
            exp_fam = LABEL_TO_FAMILY.get(original_label)
            if exp_fam == fam:
                stats["family_correct"][fam] += 1
        if sub and sub == original_label:
            stats["subtype_correct"][sub] += 1
        if orig_is_attack:
            stats["orig_family"][LABEL_TO_FAMILY[original_label]] += 1
            stats["orig_subtype"][original_label] += 1

        writer.writerow({
            "source_file": source_file, "row_index": i, "original_label": original_label,
            "is_attack_predicted": binary, "attack_score": res["attack_score"],
            "attack_binary_reason": res["attack_binary_reason"],
            "predicted_behavior_family": fam, "predicted_attack_subtype": sub,
            "subtype_confidence": res["subtype_confidence"],
            "evidence": res["evidence"], "limitations": res["limitations"],
        })


def write_summary(stats):
    SUMMARY_FILE.parent.mkdir(parents=True, exist_ok=True)
    with open(SUMMARY_FILE, "w", encoding="utf-8", newline="") as f:
        w = csv.writer(f)
        w.writerow(["seccion", "clave", "valor1", "valor2", "valor3"])

        w.writerow(["TOTALES", "trazas", stats["total"], "", ""])
        for k in ("attack", "background", "insufficient_evidence"):
            w.writerow(["ETAPA1_binaria", k, stats["binary"].get(k, 0), "", ""])

        tp, fp, fn, tn = stats["bin_tp"], stats["bin_fp"], stats["bin_fn"], stats["bin_tn"]
        prec = round(tp / (tp + fp), 3) if (tp + fp) else ""
        rec = round(tp / (tp + fn), 3) if (tp + fn) else ""
        w.writerow(["ETAPA1_eval", "TP/FP/FN/TN", f"{tp}/{fp}/{fn}/{tn}", "", ""])
        w.writerow(["ETAPA1_eval", "precision_ataque", prec, "recall_ataque", rec])

        w.writerow(["FAMILIA", "familia", "predichas", "etiq_original", "aciertos"])
        fams = set(stats["family_pred"]) | set(stats["orig_family"])
        for fam in sorted(fams):
            pred = stats["family_pred"].get(fam, 0)
            orig = stats["orig_family"].get(fam, 0)
            corr = stats["family_correct"].get(fam, 0)
            w.writerow(["FAMILIA", fam, pred, orig, corr])

        w.writerow(["SUBTIPO", "subtipo", "predichos", "etiq_original", "aciertos"])
        subs = set(stats["subtype_pred"]) | set(stats["orig_subtype"])
        for s in sorted(subs):
            pred = stats["subtype_pred"].get(s, 0)
            orig = stats["orig_subtype"].get(s, 0)
            corr = stats["subtype_correct"].get(s, 0)
            w.writerow(["SUBTIPO", s, pred, orig, corr])


def print_summary(stats):
    print("\n===== RESUMEN v2 (jerárquico) =====")
    print(f"Total trazas: {stats['total']}")
    print("ETAPA 1 (binaria):")
    for k in ("attack", "background", "insufficient_evidence"):
        print(f"  {k:<22} {stats['binary'].get(k, 0)}")
    tp, fp, fn, tn = stats["bin_tp"], stats["bin_fp"], stats["bin_fn"], stats["bin_tn"]
    prec = round(tp / (tp + fp), 3) if (tp + fp) else 0
    rec = round(tp / (tp + fn), 3) if (tp + fn) else 0
    print(f"  binaria TP/FP/FN/TN = {tp}/{fp}/{fn}/{tn}  prec={prec} recall={rec}")
    print("ETAPA 2 (familia conductual)  predichas / aciertos:")
    for fam in FAMILY_PRECEDENCE:
        p = stats["family_pred"].get(fam, 0)
        c = stats["family_correct"].get(fam, 0)
        if p:
            print(f"  {fam:<22} {p}  (aciertos {c})")
    print("Subtipos predichos:")
    for s, c in stats["subtype_pred"].most_common():
        print(f"  {s:<18} {c}")


def main():
    if not BASE_DIR.exists():
        print(f"[ERROR] No existe la carpeta: {BASE_DIR}")
        return
    files = sorted(p for p in BASE_DIR.rglob("*.csv") if is_window_file(p))
    if not files:
        print("[ERROR] No hay ventanas CSV.")
        return

    stats = {
        "total": 0, "binary": Counter(),
        "bin_tp": 0, "bin_fp": 0, "bin_fn": 0, "bin_tn": 0,
        "family_pred": Counter(), "family_correct": Counter(), "orig_family": Counter(),
        "subtype_pred": Counter(), "subtype_correct": Counter(), "orig_subtype": Counter(),
    }

    RESULTS_FILE.parent.mkdir(parents=True, exist_ok=True)
    print(f"\n===== CLASIFICADOR CONTEXTUAL v2 ({len(files)} ventanas) =====")
    print(f"Contexto: -{CONTEXT_ROWS_BEFORE}/+{CONTEXT_ROWS_AFTER} (UDP -{CONTEXT_UDP_BEFORE}/+{CONTEXT_UDP_AFTER})\n")
    with open(RESULTS_FILE, "w", encoding="utf-8", newline="") as out:
        writer = csv.DictWriter(out, fieldnames=OUTPUT_FIELDS, extrasaction="ignore")
        writer.writeheader()
        for idx, fp in enumerate(files, 1):
            rows = load_window(fp)
            sf = str(fp).replace("\\", "/")
            if rows:
                process_window(rows, sf, writer, stats)
            print(f"[{idx}/{len(files)}] {sf} ({len(rows)})")

    write_summary(stats)
    print_summary(stats)
    print(f"\nResultados por traza: {RESULTS_FILE}")
    print(f"Resumen:              {SUMMARY_FILE}")


if __name__ == "__main__":
    main()

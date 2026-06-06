"""
Script: detect_synthetic_behavior_extended.py

Descripción:
Detector heurístico AMPLIADO de comportamiento sintético para el TFG.

Amplía el detector original (detect_synthetic_behavior.py) cubriendo siete
familias de ataque descritas en la especificación NotebookLM:

    - dos               -> Distributed TCP Flood / TCP DoS
    - anomaly-udpscan   -> UDP Hybrid Scan / UDP Low-Entropy Scan
    - scan11            -> Single-Source Vertical Scan
    - scan44            -> Distributed Vertical Scan
    - anomaly-sshscan   -> Low-and-Slow SSH Horizontal Scan
    - nerisbotnet       -> Botnet multivector orquestada / Distributed C2
    - anomaly-spam      -> SMTP Spam Burst / Low-Entropy SMTP Campaign

Objetivo:
El objetivo NO es construir un IDS completo ni entrenar modelos de ML, sino
validar programáticamente si los patrones de comportamiento descritos por
NotebookLM son medibles en las ventanas reales del dataset UGR'16.

Principios de diseño (según especificación):
- La clasificación se basa en COMPORTAMIENTO, no en la etiqueta.
  La etiqueta solo se usa a posteriori para comparar (attack_expected).
- Ningún ataque se decide con una única métrica aislada: cada detector
  combina topología, protocolo, puertos, duración, paquetes, bytes, flags,
  concentración, dispersión, secuencialidad y sincronización temporal.
- Cada detector devuelve: detected, confidence, score, evidence y limitations.
- Cuando la evidencia es insuficiente se registra explícitamente, en lugar de
  forzar una clasificación.
- Los umbrales son constantes ajustables al inicio del script.

Salida:
- data/attack_analysis/behavior_detection_results_extended.csv

Uso:
    python scripts/02_attack_analysis/detect_synthetic_behavior_extended.py

NOTA: este script es independiente y no modifica detect_synthetic_behavior.py.
"""

import csv
from dataclasses import dataclass, field
from pathlib import Path
from collections import Counter, defaultdict
from statistics import mean, variance

# ---------------------------------------------------------------------------
# Configuración general
# ---------------------------------------------------------------------------

BASE_DIR = Path("data/attack_analysis")
OUTPUT_FILE = BASE_DIR / "behavior_detection_results_extended.csv"

# Estructura de columnas de las ventanas NetFlow del proyecto (sin cabecera).
EXPECTED_COLUMNS = 13

# Ficheros que NO son ventanas y deben ignorarse al recorrer la carpeta.
SKIP_SUFFIXES = ("_extraction_summary.csv",)
SKIP_NAMES = (
    "behavior_detection_results.csv",
    "behavior_detection_results_extended.csv",
    "window_extraction_summary.csv",
)

# Carpeta "normal" -> no se espera ningún ataque (control de falsos positivos).
NORMAL_FOLDER = "normal"

# ---------------------------------------------------------------------------
# Umbrales ajustables por familia
# ---------------------------------------------------------------------------

# Generales: definición de flujo "atómico" / de baja entropía.
ZERO_DURATION_THRESHOLD = 0.01   # duración considerada ~0
LOW_PACKET_THRESHOLD = 2         # flujos con <= 2 paquetes

# DoS (Distributed TCP Flood)
DOS_MIN_GROUP = 20               # flujos mínimos en el grupo src->dst:puerto
DOS_BYTES_VAR_MAX = 10_000       # varianza de bytes baja
DOS_MAX_PAIR_DST_PORTS = 3       # puerto destino fijo (no es escaneo vertical)

# anomaly-udpscan (UDP Low-Entropy Scan)
UDP_MIN_GROUP = 20
UDP_MIN_DST_IPS = 5
UDP_MIN_DST_PORTS = 10
UDP_BYTES_VAR_MAX = 200
UDP_KNOWN_SRC_PORTS = {5061, 5062, 5066, 5068}
DNS_PORT = 53                    # se usa para descartar tráfico DNS normal

# scan11 (Single-Source Vertical Scan)
SCAN11_MIN_GROUP = 20            # flujos del par src->dst
SCAN11_MIN_DST_PORTS = 20        # verticalidad: muchos puertos destino
SCAN11_BYTES_VAR_MAX = 50        # firma 44 bytes constante
SCAN11_MAX_DOMINANT_PORT_SHARE = 0.6  # si un puerto domina, es DoS, no scan
SCAN_SYN_BYTES = 44              # firma del paquete SYN de escaneo (vs 40 = respuesta RST/ACK)

# scan44 (Distributed Vertical Scan)
SCAN44_MIN_VERTICAL_PORTS = 15   # puertos destino por par para contar como vertical
SCAN44_MIN_SOURCES = 2           # varios orígenes escaneando = distribuido
SCAN44_MIN_VERTICAL_PAIRS = 2

# Dominancia: cuota de flujos de escaneo que concentra el origen principal.
# >= umbral -> un solo origen domina (scan11); < umbral -> reparto (scan44).
SCAN_SINGLE_DOMINANCE = 0.7

# anomaly-sshscan (Low-and-Slow SSH Horizontal Scan)
SSH_PORT = 22
SSH_MIN_DST_IPS = 3              # patrón horizontal, NO por volumen
SSH_BYTES_MAX = 44

# nerisbotnet (Distributed C2 / botnet)
NERIS_MIN_SOURCES = 3            # coordinación entre nodos
NERIS_SERVICE_PORTS = {25, 6667, 53, 2077}  # SMTP, IRC/C2, DNS, UDP C2 (contexto multivector)
# Puertos C2/servicio "fuertes" sobre los que se busca el clúster coordinado.
# Se excluye explícitamente el 53 (DNS) porque genera clústeres triviales de background.
NERIS_C2_PORTS = {25, 6667, 2077}

# anomaly-spam (SMTP Spam Burst)
SPAM_PORT = 25
SPAM_MIN_FLOWS = 3               # caso exploratorio / baja evidencia
SPAM_PACKET_RANGE = (8, 13)
SPAM_KNOWN_BYTES = {763, 815, 841, 893, 3136, 3143}

# Categorías técnicas por familia (texto descriptivo del comportamiento).
CATEGORY_LABELS = {
    "dos": "Distributed TCP Flood / TCP DoS",
    "anomaly-udpscan": "UDP Hybrid Scan / UDP Low-Entropy Scan",
    "scan11": "Single-Source Vertical Scan",
    "scan44": "Distributed Vertical Scan",
    "anomaly-sshscan": "Low-and-Slow SSH Horizontal Scan",
    "nerisbotnet": "Botnet multivector orquestada / Distributed C2",
    "anomaly-spam": "SMTP Spam Burst / Low-Entropy SMTP Campaign",
}

# Orden de implementación recomendado por la especificación (sección 6).
PRIORITY_ORDER = [
    "scan11",
    "scan44",
    "anomaly-udpscan",
    "dos",
    "nerisbotnet",
    "anomaly-sshscan",
    "anomaly-spam",
]

# Precedencia para DESEMPATAR la clasificación cuando varios detectores se
# activan con el mismo score. Gana el patrón más específico/estructurado:
# los escaneos con firma propia y la coordinación distribuida prevalecen sobre
# las firmas genéricas de baja entropía.
WIN_PRECEDENCE = [
    "anomaly-udpscan",
    "scan44",
    "scan11",
    "dos",
    "nerisbotnet",
    "anomaly-spam",
    "anomaly-sshscan",
]


# ---------------------------------------------------------------------------
# Utilidades de parseo y métricas
# ---------------------------------------------------------------------------

def safe_int(value: str, default: int = 0) -> int:
    try:
        return int(value)
    except Exception:
        return default


def safe_float(value: str, default: float = 0.0) -> float:
    try:
        return float(value)
    except Exception:
        return default


def safe_variance(values: list) -> float:
    if len(values) <= 1:
        return 0.0
    return variance(values)


def mode_value(values: list):
    if not values:
        return 0
    return Counter(values).most_common(1)[0][0]


def has_flag(flags: str, flag_char: str) -> bool:
    """Las flags UGR'16 son posicionales (p.ej. '....S.', '...R..', '.AP.SF')."""
    return flag_char in (flags or "")


def subnet_24(ip: str) -> str:
    parts = ip.split(".")
    return ".".join(parts[:3]) if len(parts) == 4 else ip


def is_mostly_sequential(values: list, min_ratio: float = 0.65) -> bool:
    """
    Detecta si una lista de puertos sigue una progresión mayoritariamente
    secuencial. Acepta saltos de +1 o +2 porque ambos aparecen en el dataset.
    (Mismo criterio que el detector original, para mantener compatibilidad.)
    """
    values = sorted(set(v for v in values if v > 0))

    if len(values) < 5:
        return False

    diffs = [b - a for a, b in zip(values, values[1:])]
    if not diffs:
        return False

    valid_diffs = [d for d in diffs if d in (1, 2)]
    return len(valid_diffs) / len(diffs) >= min_ratio


def ratio(count: int, total: int) -> float:
    return round(count / total, 3) if total else 0.0


# ---------------------------------------------------------------------------
# Carga de ventanas
# ---------------------------------------------------------------------------

def load_window(file_path: Path) -> list:
    """Carga una ventana CSV y devuelve una lista de flujos (dicts)."""
    rows = []

    with open(file_path, "r", encoding="utf-8", errors="ignore", newline="") as f:
        reader = csv.reader(f)
        for row in reader:
            if len(row) != EXPECTED_COLUMNS:
                continue
            rows.append(
                {
                    "timestamp": row[0],
                    "duration": safe_float(row[1]),
                    "src_ip": row[2],
                    "dst_ip": row[3],
                    "src_port": safe_int(row[4]),
                    "dst_port": safe_int(row[5]),
                    "protocol": row[6],
                    "flags": row[7],
                    "src_tos": row[8],
                    "dst_tos": row[9],
                    "packets": safe_int(row[10]),
                    "bytes": safe_int(row[11]),
                    "label": row[12].strip(),
                }
            )

    return rows


# ---------------------------------------------------------------------------
# Métricas generales de la ventana
# ---------------------------------------------------------------------------

def compute_general_metrics(rows: list) -> dict:
    """Calcula las métricas generales descritas en la especificación."""
    total = len(rows)

    labels = [r["label"] for r in rows]
    protocols = [r["protocol"] for r in rows]
    src_ips = [r["src_ip"] for r in rows]
    dst_ips = [r["dst_ip"] for r in rows]
    src_ports = [r["src_port"] for r in rows]
    dst_ports = [r["dst_port"] for r in rows]
    flags = [r["flags"] for r in rows]
    durations = [r["duration"] for r in rows]
    packets = [r["packets"] for r in rows]
    bytes_values = [r["bytes"] for r in rows]
    timestamps = [r["timestamp"] for r in rows]

    dominant_label, _ = Counter(labels).most_common(1)[0]
    dominant_protocol, _ = Counter(protocols).most_common(1)[0]
    top_src_ip, top_src_count = Counter(src_ips).most_common(1)[0]
    top_dst_ip, top_dst_count = Counter(dst_ips).most_common(1)[0]
    top_src_port, _ = Counter(src_ports).most_common(1)[0]
    top_dst_port, top_dst_port_count = Counter(dst_ports).most_common(1)[0]
    top_flags, _ = Counter(flags).most_common(1)[0]
    _, max_flows_same_ts = Counter(timestamps).most_common(1)[0]

    return {
        "total_flows": total,
        "dominant_label": dominant_label,
        "dominant_protocol": dominant_protocol,
        "unique_src_ips": len(set(src_ips)),
        "unique_dst_ips": len(set(dst_ips)),
        "unique_src_ports": len(set(src_ports)),
        "unique_dst_ports": len(set(dst_ports)),
        "avg_duration": round(mean(durations), 6),
        "avg_packets": round(mean(packets), 3),
        "avg_bytes": round(mean(bytes_values), 3),
        "bytes_variance": round(safe_variance(bytes_values), 3),
        "duration_variance": round(safe_variance(durations), 6),
        "zero_duration_ratio": ratio(sum(1 for d in durations if d <= ZERO_DURATION_THRESHOLD), total),
        "low_packet_ratio": ratio(sum(1 for p in packets if p <= LOW_PACKET_THRESHOLD), total),
        "top_src_ip": top_src_ip,
        "top_dst_ip": top_dst_ip,
        "top_src_port": top_src_port,
        "top_dst_port": top_dst_port,
        "top_flags": top_flags,
        "src_ip_concentration": ratio(top_src_count, total),
        "dst_ip_concentration": ratio(top_dst_count, total),
        "dst_port_concentration": ratio(top_dst_port_count, total),
        "max_flows_same_timestamp": max_flows_same_ts,
        "unique_timestamps": len(set(timestamps)),
    }


# ---------------------------------------------------------------------------
# Estructura de resultado de cada detector
# ---------------------------------------------------------------------------

@dataclass
class DetectionResult:
    family: str
    detected: bool = False
    confidence: str = "insuficiente"   # alta | media | baja | insuficiente
    score: float = 0.0
    evidence: dict = field(default_factory=dict)
    limitations: list = field(default_factory=list)

    @property
    def category(self) -> str:
        return CATEGORY_LABELS.get(self.family, self.family)


def grade(signals: dict, cap: str | None = None) -> tuple:
    """
    Convierte un diccionario de señales booleanas en (score, nivel).
    El nivel puede limitarse con `cap` (p.ej. ataques de baja evidencia).
    """
    total = len(signals)
    passed = sum(1 for v in signals.values() if v)
    score = round(passed / total, 3) if total else 0.0

    if score >= 0.8:
        level = "alta"
    elif score >= 0.6:
        level = "media"
    elif score >= 0.4:
        level = "baja"
    else:
        level = "insuficiente"

    if cap is not None:
        order = ["insuficiente", "baja", "media", "alta"]
        if order.index(level) > order.index(cap):
            level = cap

    return score, level


def summarize_signals(signals: dict) -> str:
    activas = [k for k, v in signals.items() if v]
    inactivas = [k for k, v in signals.items() if not v]
    partes = []
    if activas:
        partes.append("señales=[" + ", ".join(activas) + "]")
    if inactivas:
        partes.append("ausentes=[" + ", ".join(inactivas) + "]")
    return "; ".join(partes)


def _select_atomic_tcp(rows: list) -> list:
    return [
        r for r in rows
        if r["protocol"] == "TCP"
        and r["duration"] <= ZERO_DURATION_THRESHOLD
        and r["packets"] <= LOW_PACKET_THRESHOLD
    ]


def syn_vertical_scanners(rows: list, min_ports: int) -> dict:
    """
    Identifica los orígenes que realizan barrido vertical TCP SYN.

    Devuelve una estructura compartida por los detectores scan11 y scan44 para
    distinguirlos por DOMINANCIA (un origen frente a varios), no por la mera
    presencia de ruido de escaneo de fondo:

        {
          "pairs":      {(src, dst): [flows]},        # pares src->dst SYN atómicos
          "scanners":   [ {src, flows, ports, best_dst, best_group}, ... ] desc,
          "total_flows": nº de flujos en pares verticales,
          "top_share":  cuota del origen principal sobre el total vertical,
        }
    """
    cand = [r for r in _select_atomic_tcp(rows) if has_flag(r["flags"], "S")]

    pairs = defaultdict(list)
    for r in cand:
        pairs[(r["src_ip"], r["dst_ip"])].append(r)

    # Pares que se comportan como barrido vertical (muchos puertos destino).
    vertical_pairs = {
        key: group for key, group in pairs.items()
        if len({r["dst_port"] for r in group}) >= min_ports
    }

    by_src = defaultdict(list)
    for (src, dst), group in vertical_pairs.items():
        by_src[src].append((dst, group))

    scanners = []
    for src, pair_list in by_src.items():
        best_dst, best_group = max(pair_list, key=lambda pg: len({r["dst_port"] for r in pg[1]}))
        scanners.append({
            "src": src,
            "flows": sum(len(g) for _d, g in pair_list),
            "ports": len({r["dst_port"] for r in best_group}),
            "best_dst": best_dst,
            "best_group": best_group,
        })
    scanners.sort(key=lambda s: s["flows"], reverse=True)

    total_flows = sum(s["flows"] for s in scanners)
    top_share = ratio(scanners[0]["flows"], total_flows) if scanners else 0.0

    return {
        "pairs": pairs,
        "vertical_pairs": vertical_pairs,
        "scanners": scanners,
        "total_flows": total_flows,
        "top_share": top_share,
    }


# ---------------------------------------------------------------------------
# Detectores por familia
# ---------------------------------------------------------------------------

def detect_dos(rows: list) -> DetectionResult:
    """
    Distributed TCP Flood / TCP DoS.

    Combina: concentración TCP hacia un puerto destino FIJO, duración ~0,
    baja varianza de bytes, secuencialidad de puerto origen y ráfagas densas.
    Se distingue de scan11 porque el puerto destino no se dispersa.
    """
    res = DetectionResult(family="dos")
    cand = _select_atomic_tcp(rows)

    groups = defaultdict(list)
    for r in cand:
        groups[(r["src_ip"], r["dst_ip"], r["dst_port"])].append(r)

    if not groups:
        res.limitations.append("sin flujos TCP atómicos: evidencia insuficiente para DoS")
        return res

    best_key, best_group = max(groups.items(), key=lambda kv: len(kv[1]))
    group_size = len(best_group)
    src_ip, dst_ip, dst_port = best_key

    src_ports = [r["src_port"] for r in best_group]
    bytes_values = [r["bytes"] for r in best_group]
    durations = [r["duration"] for r in best_group]
    timestamps = [r["timestamp"] for r in best_group]

    # Concentración de puerto: cuota del grupo (puerto fijo) sobre todos los
    # flujos del par src->dst. DoS concentra en un puerto; un escaneo dispersa.
    pair_total = sum(1 for r in cand if r["src_ip"] == src_ip and r["dst_ip"] == dst_ip)
    pair_dst_ports = len({r["dst_port"] for r in cand
                          if r["src_ip"] == src_ip and r["dst_ip"] == dst_ip})
    port_share = ratio(group_size, pair_total)

    src_port_sequential = is_mostly_sequential(src_ports)
    bytes_var = safe_variance(bytes_values)
    zero_dur = ratio(sum(1 for d in durations if d <= ZERO_DURATION_THRESHOLD), group_size)
    burst_ratio = ratio(Counter(timestamps).most_common(1)[0][1], group_size)
    syn_ratio = ratio(sum(1 for r in best_group if has_flag(r["flags"], "S")), group_size)

    signals = {
        "concentracion_volumen": group_size >= DOS_MIN_GROUP,
        "puerto_destino_concentrado": port_share >= 0.6,
        "src_port_secuencial": src_port_sequential,
        "duracion_cero": zero_dur >= 0.9,
        "baja_varianza_bytes": bytes_var < DOS_BYTES_VAR_MAX,
        "rafaga_temporal": burst_ratio >= 0.5,
    }

    score, level = grade(signals)
    # Núcleo: volumen + puerto concentrado + secuencialidad + ráfaga densa.
    # La ráfaga distingue una inundación real de un goteo de RST de background.
    core = (
        signals["concentracion_volumen"]
        and signals["puerto_destino_concentrado"]
        and signals["src_port_secuencial"]
        and signals["rafaga_temporal"]
    )

    res.detected = bool(core and score >= 0.6)
    res.confidence = level if res.detected else "insuficiente"
    res.score = score
    res.evidence = {
        "src_ip": src_ip,
        "dst_ip": dst_ip,
        "dst_port": dst_port,
        "group_size": group_size,
        "pair_dst_ports": pair_dst_ports,
        "port_share": port_share,
        "src_port_sequential": src_port_sequential,
        "bytes_mode": mode_value(bytes_values),
        "bytes_variance": round(bytes_var, 3),
        "zero_duration_ratio": zero_dur,
        "syn_ratio": syn_ratio,
        "burst_ratio": burst_ratio,
        "summary": f"flood TCP {src_ip}->{dst_ip}:{dst_port}, {group_size} flujos; "
                   + summarize_signals(signals),
    }

    if not res.detected and group_size < DOS_MIN_GROUP:
        res.limitations.append("grupo TCP demasiado pequeño para confirmar DoS")
    if not res.detected and port_share < 0.6:
        res.limitations.append("el par dispersa puertos destino: parece escaneo, no DoS")

    return res


def detect_udp_scan(rows: list) -> DetectionResult:
    """
    UDP Low-Entropy Scan.

    Una IP origen estable genera muchos flujos UDP atómicos hacia múltiples
    destinos y puertos destino (secuenciales), con baja varianza de bytes.
    Se descarta el tráfico DNS (puerto 53 en origen o destino).
    """
    res = DetectionResult(family="anomaly-udpscan")

    cand = [
        r for r in rows
        if r["protocol"] == "UDP"
        and r["duration"] <= ZERO_DURATION_THRESHOLD
        and r["packets"] == 1
    ]

    if not cand:
        res.limitations.append("sin flujos UDP atómicos: evidencia insuficiente para UDP scan")
        return res

    # Agrupa por IP origen y escoge la fuente que mejor encaja con un escaneo
    # (mayor número de puertos destino) descartando servidores DNS.
    by_src = defaultdict(list)
    for r in cand:
        by_src[r["src_ip"]].append(r)

    best_src = None
    best_group = []
    best_dst_ports = 0
    for src, group in by_src.items():
        dom_src_port = mode_value([r["src_port"] for r in group])
        dom_dst_port = mode_value([r["dst_port"] for r in group])
        if dom_src_port == DNS_PORT or dom_dst_port == DNS_PORT:
            continue  # tráfico DNS, no escaneo
        n_dst_ports = len({r["dst_port"] for r in group})
        if n_dst_ports > best_dst_ports:
            best_src, best_group, best_dst_ports = src, group, n_dst_ports

    if not best_group:
        res.limitations.append("solo se observa tráfico UDP tipo DNS: no es escaneo")
        return res

    group_size = len(best_group)
    dst_ips = {r["dst_ip"] for r in best_group}
    dst_ports = [r["dst_port"] for r in best_group]
    src_ports = {r["src_port"] for r in best_group}
    bytes_values = [r["bytes"] for r in best_group]

    unique_dst_ips = len(dst_ips)
    unique_dst_ports = len(set(dst_ports))
    dst_port_sequential = is_mostly_sequential(dst_ports)
    bytes_var = safe_variance(bytes_values)

    signals = {
        "origen_estable": group_size >= UDP_MIN_GROUP,
        "muchas_ips_destino": unique_dst_ips >= UDP_MIN_DST_IPS,
        "muchos_puertos_destino": unique_dst_ports >= UDP_MIN_DST_PORTS,
        "barrido_secuencial": dst_port_sequential,
        "baja_varianza_bytes": bytes_var < UDP_BYTES_VAR_MAX,
        "puerto_origen_caracteristico": bool(src_ports & UDP_KNOWN_SRC_PORTS),
    }

    score, level = grade(signals)
    core = signals["origen_estable"] and signals["muchas_ips_destino"] \
        and signals["muchos_puertos_destino"]

    res.detected = bool(core and score >= 0.6)
    res.confidence = level if res.detected else "insuficiente"
    res.score = score
    res.evidence = {
        "src_ip": best_src,
        "group_size": group_size,
        "unique_dst_ips": unique_dst_ips,
        "unique_dst_ports": unique_dst_ports,
        "dst_port_sequential": dst_port_sequential,
        "src_ports": sorted(src_ports)[:8],
        "bytes_mode": mode_value(bytes_values),
        "bytes_variance": round(bytes_var, 3),
        "summary": f"escaneo UDP desde {best_src}: {unique_dst_ips} IPs / "
                   f"{unique_dst_ports} puertos destino; " + summarize_signals(signals),
    }

    if not res.detected and not core:
        res.limitations.append("dispersión de destinos/puertos insuficiente para UDP scan")

    return res


def detect_single_source_vertical_scan(rows: list) -> DetectionResult:
    """
    scan11 - Single-Source Vertical Scan.

    Un único par src->dst recorre muchos puertos destino con flujos SYN
    atómicos (~44 bytes, duración 0). Se diferencia de DoS por la dispersión
    de puertos destino (no hay un puerto fijo dominante).
    """
    res = DetectionResult(family="scan11")

    scan = syn_vertical_scanners(rows, SCAN11_MIN_DST_PORTS)
    scanners = scan["scanners"]

    if not scanners:
        res.limitations.append("sin barrido vertical SYN: evidencia insuficiente para scan11")
        return res

    # Origen principal del barrido vertical (debe dominar para ser scan11).
    top = scanners[0]
    src_ip, dst_ip = top["src"], top["best_dst"]
    best_group = top["best_group"]
    group_size = len(best_group)

    dst_ports = [r["dst_port"] for r in best_group]
    bytes_values = [r["bytes"] for r in best_group]
    durations = [r["duration"] for r in best_group]
    packets = [r["packets"] for r in best_group]

    unique_dst_ports = len(set(dst_ports))
    dominant_port_share = ratio(Counter(dst_ports).most_common(1)[0][1], group_size)
    zero_dur = ratio(sum(1 for d in durations if d <= ZERO_DURATION_THRESHOLD), group_size)
    pkt1_ratio = ratio(sum(1 for p in packets if p == 1), group_size)
    bytes_var = safe_variance(bytes_values)
    bytes_mode = mode_value(bytes_values)

    signals = {
        "verticalidad_puertos": unique_dst_ports >= SCAN11_MIN_DST_PORTS,
        "volumen_par": group_size >= SCAN11_MIN_GROUP,
        "firma_syn_44_bytes": bytes_mode == SCAN_SYN_BYTES,
        "flujos_atomicos": zero_dur >= 0.8 and pkt1_ratio >= 0.8,
        "baja_entropia_bytes": bytes_var < SCAN11_BYTES_VAR_MAX,
        "no_es_dos": dominant_port_share < SCAN11_MAX_DOMINANT_PORT_SHARE,
        "origen_dominante": scan["top_share"] >= SCAN_SINGLE_DOMINANCE,
    }

    score, level = grade(signals)
    core = (
        signals["verticalidad_puertos"]
        and signals["volumen_par"]
        and signals["no_es_dos"]
        and signals["firma_syn_44_bytes"]
        and signals["origen_dominante"]
    )

    res.detected = bool(core and score >= 0.6)
    res.confidence = level if res.detected else "insuficiente"
    res.score = score
    res.evidence = {
        "src_ip": src_ip,
        "dst_ip": dst_ip,
        "group_size": group_size,
        "unique_dst_ports": unique_dst_ports,
        "dominant_port_share": dominant_port_share,
        "n_scanners": len(scanners),
        "top_share": scan["top_share"],
        "bytes_mode": bytes_mode,
        "bytes_variance": round(bytes_var, 3),
        "summary": f"escaneo vertical {src_ip}->{dst_ip}: {unique_dst_ports} puertos "
                   f"destino SYN en {group_size} flujos (cuota origen {scan['top_share']}); "
                   + summarize_signals(signals),
    }

    if not res.detected:
        if unique_dst_ports < SCAN11_MIN_DST_PORTS:
            res.limitations.append("verticalidad SYN insuficiente para scan11")
        elif scan["top_share"] < SCAN_SINGLE_DOMINANCE:
            res.limitations.append("barrido vertical repartido entre orígenes: corresponde a scan44")

    return res


def detect_distributed_vertical_scan(rows: list) -> DetectionResult:
    """
    scan44 - Distributed Vertical Scan.

    Varios orígenes realizan escaneos verticales TCP SYN sincronizados.
    Extiende scan11 exigiendo coordinación entre múltiples fuentes.
    """
    res = DetectionResult(family="scan44")

    scan = syn_vertical_scanners(rows, SCAN44_MIN_VERTICAL_PORTS)
    vertical_pairs = scan["vertical_pairs"]
    scanners = scan["scanners"]

    if not vertical_pairs:
        res.limitations.append("sin barrido vertical SYN: evidencia insuficiente para scan44")
        return res

    scanning_sources = {s["src"] for s in scanners}
    scanning_dsts = {dst for (_src, dst) in vertical_pairs}

    # Sincronización: timestamps con >=2 orígenes verticales activos a la vez.
    ts_sources = defaultdict(set)
    for (src, _dst), group in vertical_pairs.items():
        for r in group:
            ts_sources[r["timestamp"]].add(src)
    temporal_sync = any(len(s) >= 2 for s in ts_sources.values())

    # Agrupación de orígenes por subred /24.
    subnets = Counter(subnet_24(src) for src in scanning_sources)
    same_subnet = bool(subnets and subnets.most_common(1)[0][1] >= SCAN44_MIN_SOURCES)

    all_bytes = [r["bytes"] for g in vertical_pairs.values() for r in g]

    signals = {
        "multiples_origenes": len(scanning_sources) >= SCAN44_MIN_SOURCES,
        "varios_pares_verticales": len(vertical_pairs) >= SCAN44_MIN_VERTICAL_PAIRS,
        "reparto_entre_origenes": scan["top_share"] < SCAN_SINGLE_DOMINANCE,
        "baja_entropia_bytes": safe_variance(all_bytes) < SCAN11_BYTES_VAR_MAX,
        "sincronizacion_temporal": temporal_sync,
        "origenes_misma_subred": same_subnet,
    }

    score, level = grade(signals)
    # Núcleo: varios orígenes verticales SIN que uno domine (eso sería scan11).
    core = (
        signals["multiples_origenes"]
        and signals["varios_pares_verticales"]
        and signals["reparto_entre_origenes"]
    )

    res.detected = bool(core and score >= 0.6)
    res.confidence = level if res.detected else "insuficiente"
    res.score = score
    res.evidence = {
        "scanning_sources": sorted(scanning_sources)[:8],
        "n_sources": len(scanning_sources),
        "n_targets": len(scanning_dsts),
        "n_vertical_pairs": len(vertical_pairs),
        "top_share": scan["top_share"],
        "temporal_sync": temporal_sync,
        "dominant_subnet": subnets.most_common(1)[0][0] if subnets else "",
        "summary": f"escaneo vertical distribuido: {len(scanning_sources)} orígenes / "
                   f"{len(vertical_pairs)} pares verticales (cuota origen "
                   f"{scan['top_share']}); " + summarize_signals(signals),
    }

    if not res.detected:
        if len(scanning_sources) < SCAN44_MIN_SOURCES:
            res.limitations.append("un solo origen vertical: corresponde a scan11, no a scan44")
        elif scan["top_share"] >= SCAN_SINGLE_DOMINANCE:
            res.limitations.append("un origen domina el barrido: corresponde a scan11")

    return res


def detect_ssh_horizontal_scan(rows: list) -> DetectionResult:
    """
    anomaly-sshscan - Low-and-Slow SSH Horizontal Scan.

    Un origen mantiene intentos TCP incompletos hacia el puerto 22 en
    múltiples destinos. Patrón de bajo volumen: NO se detecta por umbral alto,
    sino por incompletitud y dispersión horizontal.
    """
    res = DetectionResult(family="anomaly-sshscan")

    cand = [
        r for r in rows
        if r["protocol"] == "TCP"
        and r["dst_port"] == SSH_PORT
        and r["duration"] <= ZERO_DURATION_THRESHOLD
        and r["packets"] == 1
        and r["bytes"] <= SSH_BYTES_MAX
    ]

    if not cand:
        res.limitations.append("sin intentos atómicos hacia puerto 22: evidencia insuficiente")
        return res

    by_src = defaultdict(list)
    for r in cand:
        by_src[r["src_ip"]].append(r)
    best_src, best_group = max(by_src.items(), key=lambda kv: len({r["dst_ip"] for r in kv[1]}))

    dst_ips = {r["dst_ip"] for r in best_group}
    unique_dst_ips = len(dst_ips)
    control_flags = ratio(
        sum(1 for r in best_group if has_flag(r["flags"], "R") or has_flag(r["flags"], "S")),
        len(best_group),
    )
    # ¿Concentra este origen la mayor parte de los sondeos SSH de la ventana?
    ssh_source_share = ratio(len(best_group), len(cand))

    signals = {
        "barrido_horizontal": unique_dst_ips >= SSH_MIN_DST_IPS,
        "flujos_incompletos": control_flags >= 0.5,
        "origen_dominante": ssh_source_share >= 0.5,
    }

    score, level = grade(signals, cap="media")  # low-and-slow: confianza máx. media
    core = signals["barrido_horizontal"] and signals["origen_dominante"]

    res.detected = bool(core and score >= 0.6)
    res.confidence = level if res.detected else "insuficiente"
    res.score = score
    res.evidence = {
        "src_ip": best_src,
        "group_size": len(best_group),
        "unique_dst_ips": unique_dst_ips,
        "control_flag_ratio": control_flags,
        "summary": f"sondeo SSH horizontal desde {best_src} hacia {unique_dst_ips} destinos; "
                   + summarize_signals(signals),
    }

    # Limitaciones inherentes al patrón low-and-slow.
    res.limitations.append(
        "patrón low-and-slow: la persistencia entre ventanas no se valida en una sola ventana"
    )
    if unique_dst_ips < SSH_MIN_DST_IPS:
        res.limitations.append("muy pocos destinos hacia el puerto 22: posible flujo aislado")

    return res


def detect_nerisbotnet(rows: list) -> DetectionResult:
    """
    nerisbotnet - Distributed C2 / botnet multivector.

    La señal está en la CORRELACIÓN entre nodos: un clúster de varias IPs
    origen ejecuta acciones idénticas (mismos bytes, paquetes, puerto destino)
    de forma sincronizada. Si no hay coordinación suficiente, se registra
    evidencia insuficiente en lugar de forzar una clasificación.
    """
    res = DetectionResult(family="nerisbotnet")

    if not rows:
        res.limitations.append("ventana vacía: evidencia insuficiente para nerisbotnet")
        return res

    # La señal de botnet es la COORDINACIÓN entre nodos sobre servicios C2/spam
    # (SMTP/IRC/UDP-C2). Se buscan clústeres de flujos con métricas idénticas en
    # el mismo instante SOLO sobre puertos C2 fuertes; el puerto 53 (DNS) se
    # excluye porque genera clústeres triviales de tráfico de fondo.
    clusters = defaultdict(set)  # (dst_port, bytes, packets, ts) -> {src_ip}
    for r in rows:
        if r["dst_port"] not in NERIS_C2_PORTS:
            continue
        key = (r["dst_port"], r["bytes"], r["packets"], r["timestamp"])
        clusters[key].add(r["src_ip"])

    if not clusters:
        res.limitations.append(
            "sin tráfico hacia puertos C2 (25/6667/2077): nerisbotnet no validable"
        )
        return res

    best_key, best_srcs = max(clusters.items(), key=lambda kv: len(kv[1]))
    n_cluster_sources = len(best_srcs)

    # Multivector: presencia de varios servicios típicos de botnet (contexto).
    service_ports_present = {p for p in NERIS_SERVICE_PORTS
                             if any(r["dst_port"] == p for r in rows)}

    subnets = Counter(subnet_24(ip) for ip in best_srcs)
    same_subnet = bool(subnets and subnets.most_common(1)[0][1] >= NERIS_MIN_SOURCES)

    signals = {
        "cluster_coordinado": n_cluster_sources >= NERIS_MIN_SOURCES,
        "multivector": len(service_ports_present) >= 2,
        "origenes_agrupados": same_subnet,
    }

    score, level = grade(signals)
    core = signals["cluster_coordinado"]

    res.detected = bool(core and score >= 0.6)
    res.confidence = level if res.detected else "insuficiente"
    res.score = score
    res.evidence = {
        "cluster_sources": sorted(best_srcs)[:8],
        "n_cluster_sources": n_cluster_sources,
        "cluster_signature": {
            "dst_port": best_key[0], "bytes": best_key[1],
            "packets": best_key[2], "timestamp": best_key[3],
        },
        "service_ports_present": sorted(service_ports_present),
        "summary": f"clúster de {n_cluster_sources} orígenes con firma idéntica "
                   f"(puerto {best_key[0]}, {best_key[1]} bytes); "
                   + summarize_signals(signals),
    }

    if not res.detected:
        res.limitations.append(
            "sin coordinación multinodo suficiente: nerisbotnet no validable en esta ventana"
        )

    return res


def detect_spam_campaign(rows: list) -> DetectionResult:
    """
    anomaly-spam - SMTP Spam Burst / Low-Entropy SMTP Campaign.

    Conexiones TCP hacia el puerto 25 con métricas de paquetes/bytes muy
    repetitivas. Caso EXPLORATORIO: confianza limitada y limitaciones
    explícitas si las muestras son escasas.
    """
    res = DetectionResult(family="anomaly-spam")

    cand = [r for r in rows if r["protocol"] == "TCP" and r["dst_port"] == SPAM_PORT]

    if not cand:
        res.limitations.append("sin tráfico TCP hacia puerto 25: evidencia insuficiente para spam")
        return res

    by_src = defaultdict(list)
    for r in cand:
        by_src[r["src_ip"]].append(r)
    best_src, best_group = max(by_src.items(), key=lambda kv: len(kv[1]))

    dst_ips = {r["dst_ip"] for r in best_group}
    packets = [r["packets"] for r in best_group]
    bytes_values = [r["bytes"] for r in best_group]

    lo, hi = SPAM_PACKET_RANGE
    packet_match = ratio(sum(1 for p in packets if lo <= p <= hi), len(best_group))
    bytes_match = ratio(sum(1 for b in bytes_values if b in SPAM_KNOWN_BYTES), len(best_group))
    repetitive = packet_match >= 0.5 or bytes_match >= 0.3

    signals = {
        "metricas_repetitivas": repetitive,
        "barrido_horizontal": len(dst_ips) >= 2,
        "baja_varianza_bytes": safe_variance(bytes_values) < 5_000,
    }

    score, level = grade(signals, cap="baja")  # baja evidencia: confianza máx. baja
    core = len(best_group) >= SPAM_MIN_FLOWS and repetitive

    res.detected = bool(core and score >= 0.5)
    res.confidence = level if res.detected else "insuficiente"
    res.score = score
    res.evidence = {
        "src_ip": best_src,
        "group_size": len(best_group),
        "unique_dst_ips": len(dst_ips),
        "packet_match_ratio": packet_match,
        "bytes_match_ratio": bytes_match,
        "bytes_mode": mode_value(bytes_values),
        "summary": f"posible campaña SMTP desde {best_src} ({len(best_group)} flujos al 25); "
                   + summarize_signals(signals),
    }

    res.limitations.append(
        "anomaly-spam es exploratorio: baja evidencia y riesgo de confusión con SMTP legítimo"
    )
    if len(best_group) < SPAM_MIN_FLOWS:
        res.limitations.append("muestras SMTP escasas: no usar como validación fuerte")

    return res


# Registro de detectores en orden de prioridad de implementación.
DETECTORS = {
    "scan11": detect_single_source_vertical_scan,
    "scan44": detect_distributed_vertical_scan,
    "anomaly-udpscan": detect_udp_scan,
    "dos": detect_dos,
    "nerisbotnet": detect_nerisbotnet,
    "anomaly-sshscan": detect_ssh_horizontal_scan,
    "anomaly-spam": detect_spam_campaign,
}


# ---------------------------------------------------------------------------
# Análisis de una ventana
# ---------------------------------------------------------------------------

def family_from_path(file_path: Path) -> str:
    """Deriva la familia esperada a partir de la carpeta de la ventana."""
    try:
        rel = file_path.relative_to(BASE_DIR)
        return rel.parts[0]
    except ValueError:
        return file_path.parent.name


CONFIDENCE_RANK = {"insuficiente": 0, "baja": 1, "media": 2, "alta": 3}


def select_winner(detections: list) -> DetectionResult | None:
    """
    Elige la mejor detección priorizando, en este orden:
      1. nivel de confianza (alta > media > baja) -> los patrones estructurados
         con firma propia prevalecen sobre los de baja evidencia (sshscan/spam),
         que están capados a media/baja por especificación,
      2. score de señales,
      3. precedencia entre familias (patrón más específico/distribuido).
    """
    positivos = [d for d in detections if d.detected]
    if not positivos:
        return None

    # scan44 (vertical distribuido) subsume a scan11 (vertical de un origen).
    familias = {d.family for d in positivos}
    if "scan44" in familias:
        positivos = [d for d in positivos if d.family != "scan11"]

    return max(
        positivos,
        key=lambda d: (CONFIDENCE_RANK[d.confidence], d.score, -WIN_PRECEDENCE.index(d.family)),
    )


def analyze_window(file_path: Path) -> dict:
    rows = load_window(file_path)
    family_expected = family_from_path(file_path)
    attack_expected = "none" if family_expected == NORMAL_FOLDER else family_expected

    base = {
        "file": str(file_path).replace("\\", "/"),
        "attack_expected": attack_expected,
    }

    if not rows:
        base.update({
            "attack_detected": False,
            "predicted_category": "sin_datos",
            "confidence_level": "insuficiente",
            "evidence_summary": "ventana sin filas válidas",
            "limitations": "no hay datos que analizar",
        })
        return base

    metrics = compute_general_metrics(rows)

    # Filas etiquetadas con el ataque esperado (solo para comparación posterior).
    attack_label_rows = sum(1 for r in rows if r["label"] == family_expected)

    detections = [detector(rows) for detector in DETECTORS.values()]
    winner = select_winner(detections)

    detected_categories = [d.family for d in detections if d.detected]

    # Limitaciones agregadas de los detectores que no encontraron evidencia.
    all_limitations = []
    for d in detections:
        for lim in d.limitations:
            all_limitations.append(f"[{d.family}] {lim}")

    if winner is not None:
        predicted_category = winner.category
        confidence_level = winner.confidence
        attack_detected = True
        evidence_summary = winner.evidence.get("summary", "")
        confidence_score = winner.score
        if len(detected_categories) > 1:
            otras = ", ".join(c for c in detected_categories if c != winner.family)
            evidence_summary += f" | otras detecciones: {otras}"
    else:
        predicted_category = "no_clasificado"
        confidence_level = "insuficiente"
        attack_detected = False
        evidence_summary = "ningún detector reunió evidencia de comportamiento suficiente"
        confidence_score = 0.0

    base.update({
        "attack_detected": attack_detected,
        "predicted_category": predicted_category,
        "confidence_level": confidence_level,
        "confidence_score": confidence_score,
        "detected_categories": " + ".join(detected_categories) if detected_categories else "",
        "attack_label_rows": attack_label_rows,
        "evidence_summary": evidence_summary,
        "limitations": " | ".join(all_limitations) if all_limitations else "",
    })
    base.update(metrics)
    return base


# ---------------------------------------------------------------------------
# Recorrido de carpetas y persistencia
# ---------------------------------------------------------------------------

def is_window_file(path: Path) -> bool:
    if path.name in SKIP_NAMES:
        return False
    if any(path.name.endswith(suf) for suf in SKIP_SUFFIXES):
        return False
    return True


def run_detection_on_folder(input_dir: Path) -> list:
    files = sorted(p for p in input_dir.rglob("*.csv") if is_window_file(p))
    results = []

    print("\n===== ANÁLISIS DE VENTANAS (detector ampliado) =====\n")
    for file_path in files:
        result = analyze_window(file_path)
        results.append(result)

        print(f"Archivo: {result['file']}")
        print(f"  Ataque esperado:    {result.get('attack_expected')}")
        print(f"  Filas etiquetadas:  {result.get('attack_label_rows')}")
        print(f"  Categoría detectada:{result.get('predicted_category')}")
        print(f"  Confianza:          {result.get('confidence_level')} "
              f"(score={result.get('confidence_score')})")
        print(f"  Evidencia:          {result.get('evidence_summary')}")
        if result.get("limitations"):
            print(f"  Limitaciones:       {result.get('limitations')}")
        print()

    return results


# Orden de columnas del CSV de salida (campos mínimos de la especificación
# + algunos campos adicionales útiles para la validación).
OUTPUT_FIELDS = [
    "file",
    "attack_expected",
    "attack_detected",
    "predicted_category",
    "confidence_level",
    "confidence_score",
    "detected_categories",
    "total_flows",
    "attack_label_rows",
    "dominant_label",
    "dominant_protocol",
    "unique_src_ips",
    "unique_dst_ips",
    "unique_src_ports",
    "unique_dst_ports",
    "avg_duration",
    "avg_packets",
    "avg_bytes",
    "bytes_variance",
    "duration_variance",
    "zero_duration_ratio",
    "low_packet_ratio",
    "src_ip_concentration",
    "dst_ip_concentration",
    "dst_port_concentration",
    "max_flows_same_timestamp",
    "unique_timestamps",
    "top_src_ip",
    "top_dst_ip",
    "top_src_port",
    "top_dst_port",
    "top_flags",
    "evidence_summary",
    "limitations",
]


def save_results(results: list, output_file: Path) -> None:
    if not results:
        return

    output_file.parent.mkdir(parents=True, exist_ok=True)

    with open(output_file, "w", encoding="utf-8", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=OUTPUT_FIELDS, extrasaction="ignore")
        writer.writeheader()
        for row in results:
            writer.writerow({k: row.get(k, "") for k in OUTPUT_FIELDS})


def main() -> None:
    if not BASE_DIR.exists():
        print(f"[ERROR] No existe la carpeta de ventanas: {BASE_DIR}")
        return

    results = run_detection_on_folder(BASE_DIR)

    if not results:
        print("[ERROR] No se han encontrado ventanas CSV en data/attack_analysis/")
        return

    save_results(results, OUTPUT_FILE)

    detectadas = sum(1 for r in results if r.get("attack_detected"))
    print("===== RESULTADO =====")
    print(f"Ventanas analizadas:   {len(results)}")
    print(f"Ventanas con detección:{detectadas}")
    print(f"Resultados guardados en: {OUTPUT_FILE}")


if __name__ == "__main__":
    main()

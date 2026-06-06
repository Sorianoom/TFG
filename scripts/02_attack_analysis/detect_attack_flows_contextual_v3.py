"""
Script: detect_attack_flows_contextual_v3.py

Clasificador CONTEXTUAL POR TRAZA, versión 3 (DOS PASES: local + global/temporal).

Motivación
----------
La v2 logra una detección binaria por traza muy buena (precisión 0,961 /
recall 0,991), pero el análisis (docs 23 y 24) mostró que varias familias
necesitan una vista MÁS AMPLIA que el contexto local de ±N filas:
  - scan11/scan44: el subtipo depende de ver si el barrido es de un origen
    (scan11) o distribuido entre varios (scan44)  -> propiedad GLOBAL.
  - anomaly-sshscan: es low-and-slow; requiere PERSISTENCIA por src_ip hacia
    el puerto 22 -> agregación por origen, no ráfaga local.
  - nerisbotnet: requiere COORDINACIÓN multinodo en buckets temporales.
  - anomaly-spam: baja evidencia; solo fan-out claro hacia el 25 (no forzar).

Arquitectura
------------
PASE 1 (local/contextual) - igual que la v2 pero SIN emitir ssh/smtp/botnet
  localmente (eran fuente de falsos positivos). Produce:
    attack | background | insufficient_evidence
    familia local: vertical_scan | udp_scan | tcp_flood | unknown_attack

PASE 2 (global/temporal, por VENTANA) - revisa las trazas y:
    1) resuelve el subtipo scan11/scan44 con la estructura global del barrido,
    2) emite ssh_horizontal_scan solo por persistencia agregada por src_ip,
    3) emite coordinated_botnet por coordinación en buckets temporales
       (puertos C2 SUMAN confianza, no son gate duro),
    4) confirma udp_scan por dispersión global por src_ip,
    5) emite smtp_campaign solo con fan-out claro (si no, unknown/background).

Restricciones (mantenidas)
--------------------------
- No se usan labels para detectar (solo para evaluar).
- No se usan IPs concretas como reglas (solo como CLAVES de agrupación).
- No es Machine Learning.
- No se reintroducen firmas exactas (puertos/bytes concretos) como criterio.
- Evidencia interpretable por traza; limitaciones explícitas.

Salidas
-------
- data/attack_analysis/flow_level_detection_results_v3.csv
- data/attack_analysis/flow_level_detection_summary_v3.csv

Uso
---
  python scripts/02_attack_analysis/detect_attack_flows_contextual_v3.py

NOTA: no modifica las versiones anteriores ni los detectores por ventana.
"""

import csv
from pathlib import Path
from collections import Counter, defaultdict
from statistics import variance

# ---------------------------------------------------------------------------
# Configuración general
# ---------------------------------------------------------------------------

BASE_DIR = Path("data/attack_analysis")
RESULTS_FILE = BASE_DIR / "flow_level_detection_results_v3.csv"
SUMMARY_FILE = BASE_DIR / "flow_level_detection_summary_v3.csv"

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
    "flow_level_detection_results_v3.csv",
    "flow_level_detection_summary_v3.csv",
)

# ---------------------------------------------------------------------------
# Contexto local (PASE 1) - ajustable
# ---------------------------------------------------------------------------

CONTEXT_ROWS_BEFORE = 30
CONTEXT_ROWS_AFTER = 30
CONTEXT_UDP_BEFORE = 60
CONTEXT_UDP_AFTER = 60

# Bucket temporal (PASE 2)
BUCKET_SECONDS = 10

# ---------------------------------------------------------------------------
# Umbrales PASE 1 (local) - heredados de la v2
# ---------------------------------------------------------------------------

ZERO_DURATION_THRESHOLD = 0.01
LOW_PACKET_THRESHOLD = 2
SMALL_BYTES_MAX = 100
LOW_BYTES_VARIANCE = 50

CTX_VERTICAL_MIN_DST_PORTS = 8
CTX_VERTICAL_PARTIAL_DST_PORTS = 4
DOM_HIGH = 0.8
DOM_LOW = 0.6

CTX_FLOOD_MIN_GROUP = 10
FLOOD_PORT_CONCENTRATION = 0.6
FLOOD_MAX_PAIR_DST_PORTS = 3
FLOOD_BYTES_VAR_MAX = 10_000

CTX_UDP_MIN_DST_IPS = 4
CTX_UDP_MIN_DST_PORTS = 6
CTX_UDP_PARTIAL_DST_IPS = 2
CTX_UDP_BYTES_VAR_MAX = 200
DNS_PORT = 53

CTX_UNKNOWN_MIN_GROUP = 20
CTX_UNKNOWN_BYTES_VAR_MAX = 5

# ---------------------------------------------------------------------------
# Umbrales PASE 2 (global/temporal)
# ---------------------------------------------------------------------------

# Subtipo vertical (scan11 vs scan44) sobre la ventana completa
G_VERTICAL_MIN_DST_PORTS = 8

# ssh_horizontal_scan: persistencia por src_ip hacia el puerto 22
SSH_PORT = 22
G_SSH_MIN_DST_IPS = 5            # destinos distintos al 22 por origen
G_SSH_INCOMPLETE_MIN = 0.8       # ratio de flujos incompletos (1 pkt / RST)
SSH_COMPLETE_PACKETS = LOW_PACKET_THRESHOLD  # >2 paquetes = sesión "completa"
SSH_COMPLETE_DURATION = 0.5      # duración apreciable = sesión real

# coordinated_botnet: coordinación en buckets temporales
NERIS_C2_PORTS = {25, 6667, 2077}            # SUMAN confianza, no son gate duro
NERIS_SERVICE_PORTS = {25, 6667, 53, 2077}   # contexto multivector
G_NERIS_MIN_SOURCES_C2 = 4       # en puertos C2 basta coordinación moderada en 1 bucket
# Fuera de C2 se exige evidencia mucho más fuerte (anti-FP en fondo denso):
# IDENTIDAD PERSISTENTE de muchos orígenes que reaparecen en varios buckets con
# la misma firma. Aun así es un camino exploratorio de confianza baja.
G_NERIS_MIN_SOURCES_OTHER = 15
G_NERIS_MIN_BUCKETS_OTHER = 4
G_NERIS_DUR_VAR_MAX = 0.01       # baja varianza de duración (métricas homogéneas)

# udp_scan global por src_ip
G_UDP_MIN_DST_IPS = 6
G_UDP_MIN_DST_PORTS = 8

# smtp_campaign: fan-out por bloque /24 hacia el 25
SPAM_PORT = 25
G_SMTP_MIN_DST_IPS = 5
G_SMTP_REPETITION_SHARE = 0.5    # repetición de la tupla (packets,bytes) dominante
G_SMTP_BYTES_VAR_MAX = 5_000

CONFIDENCE_RANK = {"insuficiente": 0, "baja": 1, "media": 2, "alta": 3}

FAMILY_PRECEDENCE = [
    "coordinated_botnet", "udp_scan", "tcp_flood", "vertical_scan",
    "ssh_horizontal_scan", "smtp_campaign", "unknown_attack",
]

LABEL_TO_FAMILY = {
    "scan11": "vertical_scan", "scan44": "vertical_scan",
    "anomaly-udpscan": "udp_scan", "dos": "tcp_flood",
    "nerisbotnet": "coordinated_botnet", "anomaly-sshscan": "ssh_horizontal_scan",
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


def ts_bucket(ts):
    try:
        head, sec = ts.rsplit(":", 1)
        s = int(sec)
        return f"{head}:{(s // BUCKET_SECONDS) * BUCKET_SECONDS:02d}"
    except Exception:
        return ts


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


# ===========================================================================
# PASE 1 - clasificación local (familias: vertical_scan, udp_scan, tcp_flood,
#          unknown_attack). NO emite ssh/smtp/botnet (se delegan al pase 2).
# ===========================================================================

def context_vertical_scanners(rows, min_ports):
    cand = [r for r in rows
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
            "top_share": top_share, "temporal_sync": temporal_sync,
            "n_dsts": len({d for (_s, d) in vertical})}


def p1_vertical(target, context):
    if not (target["protocol"] == "TCP" and is_atomic(target) and has_flag(target["flags"], "S")):
        return None
    pair = (target["src_ip"], target["dst_ip"])
    same = [r for r in context
            if r["src_ip"] == pair[0] and r["dst_ip"] == pair[1]
            and r["protocol"] == "TCP" and is_atomic(r) and has_flag(r["flags"], "S")]
    n_dports = len({r["dst_port"] for r in same})
    if n_dports < CTX_VERTICAL_PARTIAL_DST_PORTS:
        return None
    bvals = [r["bytes"] for r in same]
    signals = {
        "verticalidad": n_dports >= CTX_VERTICAL_MIN_DST_PORTS,
        "flujos_atomicos": True,
        "bytes_pequenos": mode_value(bvals) <= SMALL_BYTES_MAX,
        "baja_entropia_bytes": safe_variance(bvals) < LOW_BYTES_VARIANCE,
    }
    core_ok = signals["verticalidad"]
    strength = sum(signals.values()) / len(signals)
    return {"family": "vertical_scan", "core_ok": core_ok, "strength": strength,
            "confidence": level_from_fraction(strength),
            "evidence": f"par {pair[0]}->{pair[1]} con {n_dports} puertos destino SYN; "
                        + signals_text(signals),
            "limitations": []}


def p1_tcp_flood(target, context):
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
    burst = ratio(Counter(r["timestamp"] for r in group).most_common(1)[0][1], len(group))
    signals = {
        "concentracion_volumen": len(group) >= CTX_FLOOD_MIN_GROUP,
        "puerto_destino_concentrado": port_share >= FLOOD_PORT_CONCENTRATION,
        "baja_diversidad_puertos": pair_dst_ports <= FLOOD_MAX_PAIR_DST_PORTS,
        "secuencial_o_rafaga": is_mostly_sequential(src_ports) or burst >= 0.5,
        "baja_varianza_bytes": safe_variance(bvals) < FLOOD_BYTES_VAR_MAX,
    }
    core_ok = (signals["concentracion_volumen"] and signals["puerto_destino_concentrado"]
               and signals["baja_diversidad_puertos"] and signals["secuencial_o_rafaga"])
    strength = sum(signals.values()) / len(signals)
    if not core_ok and strength < 0.4:
        return None
    return {"family": "tcp_flood", "core_ok": core_ok, "strength": strength,
            "confidence": level_from_fraction(strength),
            "evidence": f"inundación TCP {target['src_ip']}->{target['dst_ip']}:{target['dst_port']} "
                        f"({len(group)} flujos, cuota {port_share}, diversidad puertos={pair_dst_ports}); "
                        + signals_text(signals),
            "limitations": []}


def p1_udp_scan(target, wide_context):
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
    strength = sum(signals.values()) / len(signals)
    return {"family": "udp_scan", "core_ok": core_ok, "strength": strength,
            "confidence": level_from_fraction(strength),
            "evidence": f"dispersión UDP desde {target['src_ip']} ({n_ips} IPs / {n_ports} puertos); "
                        + signals_text(signals),
            "limitations": []}


def p1_unknown(target, context):
    if not is_atomic(target) or target["packets"] != 1:
        return None
    group = [r for r in context
             if r["src_ip"] == target["src_ip"] and r["dst_ip"] == target["dst_ip"]
             and r["protocol"] == target["protocol"] and is_atomic(r) and r["packets"] == 1]
    if len(group) < CTX_UNKNOWN_MIN_GROUP:
        return None
    bvals = [r["bytes"] for r in group]
    burst = ratio(Counter(r["timestamp"] for r in group).most_common(1)[0][1], len(group))
    signals = {
        "grupo_atomico_denso": len(group) >= CTX_UNKNOWN_MIN_GROUP,
        "entropia_casi_nula": safe_variance(bvals) < CTX_UNKNOWN_BYTES_VAR_MAX,
        "rafaga_temporal": burst >= 0.7,
    }
    if not all(signals.values()):
        return None
    strength = sum(signals.values()) / len(signals)
    return {"family": "unknown_attack", "core_ok": True, "strength": strength,
            "confidence": level_from_fraction(strength, cap="media"),
            "evidence": f"ráfaga atómica de entropía casi nula sin firma de familia "
                        f"({len(group)} flujos {target['protocol']}); " + signals_text(signals),
            "limitations": ["comportamiento anómalo no asignable a una familia conocida"]}


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


def classify_local(target, context, wide_context):
    results = []
    for r in (p1_vertical(target, context), p1_tcp_flood(target, context),
              p1_udp_scan(target, wide_context), p1_unknown(target, context)):
        if r is not None:
            results.append(r)
    confirmed = [r for r in results if r["core_ok"]]
    partial = [r for r in results if not r["core_ok"]]

    if confirmed:
        if any(r["family"] == "tcp_flood" for r in confirmed):
            confirmed = [r for r in confirmed if r["family"] != "vertical_scan"]
        winner = max(confirmed, key=lambda r: (
            CONFIDENCE_RANK[r["confidence"]], r["strength"],
            -FAMILY_PRECEDENCE.index(r["family"])))
        return {"binary": "attack", "attack_score": round(max(r["strength"] for r in confirmed), 3),
                "reason": f"miembro confirmado de {winner['family']} (local)",
                "family": winner["family"], "confidence": winner["confidence"],
                "evidence": winner["evidence"], "limitations": list(winner["limitations"])}
    if partial:
        best = max(partial, key=lambda r: r["strength"])
        return {"binary": "insufficient_evidence", "attack_score": round(best["strength"], 3),
                "reason": f"estructura parcial de {best['family']} sin núcleo (local)",
                "family": "", "confidence": "", "evidence": best["evidence"],
                "limitations": best["limitations"] or ["evidencia parcial"]}
    return {"binary": "background", "attack_score": 0.0,
            "reason": "flujo atómico aislado: sin estructura local" if is_interesting(target)
                      else "sesión completa / no atómico: tráfico normal",
            "family": "", "confidence": "", "evidence": "", "limitations": []}


# ===========================================================================
# PASE 2 - agregación global/temporal por VENTANA
# ===========================================================================

def compute_window_aggregates(rows):
    # --- subtipo vertical (scan11 vs scan44) sobre toda la ventana ---
    vg = context_vertical_scanners(rows, G_VERTICAL_MIN_DST_PORTS)
    n_src = len(vg["scanners"])
    top = vg["top_share"]
    sync = vg["temporal_sync"]
    if n_src == 0:
        v_subtype, v_conf = "undetermined", "insuficiente"
    elif n_src == 1 or (top >= DOM_HIGH):
        v_subtype, v_conf = "scan11", ("alta" if n_src == 1 else "media")
    elif n_src >= 2 and top < DOM_LOW and sync:
        v_subtype, v_conf = "scan44", "alta"
    elif n_src >= 2 and top < DOM_HIGH:
        v_subtype, v_conf = "scan44", "media"
    else:
        v_subtype, v_conf = "undetermined", "baja"
    vertical_pairs = set(vg["vertical_pairs"].keys())

    # --- ssh_horizontal_scan: persistencia por src_ip hacia el 22 ---
    ssh_by_src = defaultdict(list)
    for r in rows:
        if r["protocol"] == "TCP" and r["dst_port"] == SSH_PORT:
            ssh_by_src[r["src_ip"]].append(r)
    ssh_scanners = {}
    for src, flows in ssh_by_src.items():
        dst_ips = {r["dst_ip"] for r in flows}
        completed = any(r["packets"] > SSH_COMPLETE_PACKETS or r["duration"] > SSH_COMPLETE_DURATION
                        for r in flows)
        incomplete = ratio(sum(1 for r in flows
                               if r["packets"] <= 1 and r["duration"] <= ZERO_DURATION_THRESHOLD), len(flows))
        if len(dst_ips) >= G_SSH_MIN_DST_IPS and not completed and incomplete >= G_SSH_INCOMPLETE_MIN:
            ssh_scanners[src] = {"n_dst": len(dst_ips), "incomplete": incomplete}

    # --- coordinated_botnet: coordinación en buckets temporales ---
    # firma conductual = (dst_port, bytes, packets); por cada firma se mira en qué
    # buckets aparece coordinada (>= N orígenes, baja varianza de duración).
    #   - en puertos C2: basta 1 bucket coordinado (C2 suma confianza).
    #   - fuera de C2: se exige PERIODICIDAD (varios buckets) y más orígenes,
    #     para no confundir una ráfaga puntual de fondo con coordinación.
    sig_buckets = defaultdict(lambda: defaultdict(lambda: {"srcs": set(), "durs": []}))
    for r in rows:
        b = ts_bucket(r["timestamp"])
        e = sig_buckets[(r["dst_port"], r["bytes"], r["packets"])][b]
        e["srcs"].add(r["src_ip"])
        e["durs"].append(r["duration"])
    # C2: coordinación en un bucket (clave por bucket).
    botnet_c2_keys = {}
    # No-C2: requiere IDENTIDAD PERSISTENTE -> los MISMOS orígenes reaparecen en
    # varios buckets (beaconing). El ruido de fondo lo forman IPs cambiantes, así
    # que no cumple esta condición. Clave por (src_ip, firma).
    botnet_persistent = {}
    for sig, buckets in sig_buckets.items():
        is_c2 = sig[0] in NERIS_C2_PORTS
        if is_c2:
            for b, e in buckets.items():
                if len(e["srcs"]) >= G_NERIS_MIN_SOURCES_C2 and safe_variance(e["durs"]) <= G_NERIS_DUR_VAR_MAX:
                    botnet_c2_keys[(b, sig[0], sig[1], sig[2])] = len(e["srcs"])
        else:
            src_buckets = defaultdict(set)
            all_durs = []
            for b, e in buckets.items():
                all_durs.extend(e["durs"])
                for s in e["srcs"]:
                    src_buckets[s].add(b)
            persistent = {s for s, bs in src_buckets.items() if len(bs) >= G_NERIS_MIN_BUCKETS_OTHER}
            if len(persistent) >= G_NERIS_MIN_SOURCES_OTHER and safe_variance(all_durs) <= G_NERIS_DUR_VAR_MAX:
                for s in persistent:
                    botnet_persistent[(s, sig[0], sig[1], sig[2])] = len(persistent)

    # --- udp_scan global por src_ip ---
    udp_by_src_ips = defaultdict(set)
    udp_by_src_ports = defaultdict(set)
    for r in rows:
        if (r["protocol"] == "UDP" and r["packets"] == 1 and is_atomic(r)
                and r["src_port"] != DNS_PORT and r["dst_port"] != DNS_PORT):
            udp_by_src_ips[r["src_ip"]].add(r["dst_ip"])
            udp_by_src_ports[r["src_ip"]].add(r["dst_port"])
    udp_scanners = {s for s in udp_by_src_ips
                    if len(udp_by_src_ips[s]) >= G_UDP_MIN_DST_IPS
                    and len(udp_by_src_ports[s]) >= G_UDP_MIN_DST_PORTS}

    # --- smtp_campaign: fan-out por bloque /24 hacia el 25 ---
    smtp_by_block = defaultdict(list)
    for r in rows:
        if r["protocol"] == "TCP" and r["dst_port"] == SPAM_PORT:
            smtp_by_block[subnet_24(r["src_ip"])].append(r)
    smtp_blocks = {}
    for block, flows in smtp_by_block.items():
        dst_ips = {r["dst_ip"] for r in flows}
        tuples = Counter((r["packets"], r["bytes"]) for r in flows)
        rep_share = ratio(tuples.most_common(1)[0][1], len(flows)) if flows else 0
        bvar = safe_variance([r["bytes"] for r in flows])
        if (len(dst_ips) >= G_SMTP_MIN_DST_IPS and rep_share >= G_SMTP_REPETITION_SHARE
                and bvar < G_SMTP_BYTES_VAR_MAX):
            smtp_blocks[block] = {"fan_out": len(dst_ips), "rep": rep_share}

    return {
        "v_subtype": v_subtype, "v_conf": v_conf, "vertical_pairs": vertical_pairs,
        "v_n_src": n_src, "v_top_share": top,
        "ssh_scanners": ssh_scanners,
        "botnet_c2_keys": botnet_c2_keys, "botnet_persistent": botnet_persistent,
        "udp_scanners": udp_scanners, "smtp_blocks": smtp_blocks,
    }


def reconcile(target, p1, agg):
    """Combina la decisión local (p1) con la evidencia global (agg)."""
    candidates = []  # (family, confidence, subtype, subtype_conf, evidence, limitations)

    # ---- evidencia GLOBAL ----
    # ssh_horizontal_scan (solo por persistencia agregada)
    if (target["protocol"] == "TCP" and target["dst_port"] == SSH_PORT
            and target["src_ip"] in agg["ssh_scanners"]):
        info = agg["ssh_scanners"][target["src_ip"]]
        candidates.append(("ssh_horizontal_scan", "media", "anomaly-sshscan", "media",
                           f"origen {target['src_ip']} persistente al puerto 22: {info['n_dst']} destinos, "
                           f"incompletos {info['incomplete']} (agregación global)",
                           ["persistencia intra-ventana; confirmación entre ficheros no evaluada"]))

    # coordinated_botnet: clúster C2 en un bucket, o identidad persistente fuera de C2
    sig = (target["dst_port"], target["bytes"], target["packets"])
    c2key = (ts_bucket(target["timestamp"]),) + sig
    if c2key in agg["botnet_c2_keys"]:
        nsr = agg["botnet_c2_keys"][c2key]
        candidates.append(("coordinated_botnet", "alta", "nerisbotnet", "alta",
                           f"clúster C2 de {nsr} orígenes con métricas idénticas "
                           f"(bucket {c2key[0]}, puerto {sig[0]}, {sig[1]} bytes) [C2]", []))
    elif (target["src_ip"],) + sig in agg["botnet_persistent"]:
        nsr = agg["botnet_persistent"][(target["src_ip"],) + sig]
        candidates.append(("coordinated_botnet", "baja", "nerisbotnet", "baja",
                           f"coordinación persistente: {nsr} orígenes reaparecen en varios buckets "
                           f"con firma idéntica (puerto {sig[0]}, {sig[1]} bytes)",
                           ["coordinación fuera de puertos C2: confianza reducida"]))

    # udp_scan confirmado globalmente
    if (target["protocol"] == "UDP" and target["packets"] == 1 and is_atomic(target)
            and target["src_ip"] in agg["udp_scanners"]):
        candidates.append(("udp_scan", "alta", "anomaly-udpscan", "alta",
                           f"campaña UDP confirmada por dispersión global del origen {target['src_ip']}",
                           []))

    # smtp_campaign (solo con fan-out claro)
    if (target["protocol"] == "TCP" and target["dst_port"] == SPAM_PORT
            and subnet_24(target["src_ip"]) in agg["smtp_blocks"]):
        info = agg["smtp_blocks"][subnet_24(target["src_ip"])]
        candidates.append(("smtp_campaign", "baja", "anomaly-spam", "baja",
                           f"fan-out SMTP del bloque {subnet_24(target['src_ip'])}.x: "
                           f"{info['fan_out']} destinos, repetición {info['rep']}",
                           ["baja evidencia: difícil separar de SMTP legítimo"]))

    # ---- evidencia LOCAL (pase 1) ----
    if p1["family"] == "vertical_scan":
        st, sc = agg["v_subtype"], agg["v_conf"]
        lim = list(p1["limitations"])
        if st == "undetermined":
            lim.append("contexto global insuficiente para separar scan11/scan44")
        candidates.append(("vertical_scan", p1["confidence"], st, sc, p1["evidence"], lim))
    elif p1["family"] in ("tcp_flood", "udp_scan", "unknown_attack"):
        sub = {"tcp_flood": "dos", "udp_scan": "anomaly-udpscan", "unknown_attack": ""}[p1["family"]]
        candidates.append((p1["family"], p1["confidence"], sub, p1["confidence"],
                           p1["evidence"], list(p1["limitations"])))

    if not candidates:
        # sin familia: mantener el veredicto binario local (background/insufficient)
        return {
            "is_attack_predicted": p1["binary"], "attack_score": p1["attack_score"],
            "attack_binary_reason": p1["reason"],
            "predicted_behavior_family": "", "predicted_attack_subtype": "",
            "subtype_confidence": "", "evidence": p1["evidence"],
            "limitations": " | ".join(p1["limitations"]),
        }

    # elegir por confianza -> precedencia (especificidad)
    winner = max(candidates, key=lambda c: (
        CONFIDENCE_RANK[c[1]], -FAMILY_PRECEDENCE.index(c[0])))
    fam, conf, sub, sub_conf, ev, lim = winner
    others = [c[0] for c in candidates if c[0] != fam]
    if others:
        ev = ev + " | otras señales: " + ", ".join(sorted(set(others)))
    return {
        "is_attack_predicted": "attack", "attack_score": max(p1["attack_score"],
                                                             round(CONFIDENCE_RANK[conf] / 3, 3)),
        "attack_binary_reason": f"familia {fam} (pase 1+2)",
        "predicted_behavior_family": fam, "predicted_attack_subtype": sub,
        "subtype_confidence": sub_conf, "evidence": ev,
        "limitations": " | ".join(lim),
    }


# ===========================================================================
# Recorrido y persistencia
# ===========================================================================

def is_window_file(path):
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
    # PASE 1 (local)
    p1_results = []
    for i, target in enumerate(rows):
        if is_interesting(target):
            ctx = rows[max(0, i - CONTEXT_ROWS_BEFORE):min(n, i + CONTEXT_ROWS_AFTER + 1)]
            if target["protocol"] == "UDP":
                wide = rows[max(0, i - CONTEXT_UDP_BEFORE):min(n, i + CONTEXT_UDP_AFTER + 1)]
            else:
                wide = ctx
            p1_results.append(classify_local(target, ctx, wide))
        else:
            p1_results.append({"binary": "background", "attack_score": 0.0,
                               "reason": "sesión completa / no atómico: tráfico normal",
                               "family": "", "confidence": "", "evidence": "", "limitations": []})

    # PASE 2 (global/temporal)
    agg = compute_window_aggregates(rows)

    for i, target in enumerate(rows):
        res = reconcile(target, p1_results[i], agg)
        original_label = target["label"]
        binary = res["is_attack_predicted"]
        fam = res["predicted_behavior_family"]
        sub = res["predicted_attack_subtype"]

        stats["total"] += 1
        stats["binary"][binary] += 1
        if fam:
            stats["family_pred"][fam] += 1
        if sub and sub != "undetermined":
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

        if fam and LABEL_TO_FAMILY.get(original_label) == fam:
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
        for fam in sorted(set(stats["family_pred"]) | set(stats["orig_family"])):
            w.writerow(["FAMILIA", fam, stats["family_pred"].get(fam, 0),
                        stats["orig_family"].get(fam, 0), stats["family_correct"].get(fam, 0)])
        w.writerow(["SUBTIPO", "subtipo", "predichos", "etiq_original", "aciertos"])
        for s in sorted(set(stats["subtype_pred"]) | set(stats["orig_subtype"])):
            w.writerow(["SUBTIPO", s, stats["subtype_pred"].get(s, 0),
                        stats["orig_subtype"].get(s, 0), stats["subtype_correct"].get(s, 0)])


def print_summary(stats):
    print("\n===== RESUMEN v3 (dos pases) =====")
    print(f"Total trazas: {stats['total']}")
    for k in ("attack", "background", "insufficient_evidence"):
        print(f"  {k:<22} {stats['binary'].get(k, 0)}")
    tp, fp, fn, tn = stats["bin_tp"], stats["bin_fp"], stats["bin_fn"], stats["bin_tn"]
    prec = round(tp / (tp + fp), 3) if (tp + fp) else 0
    rec = round(tp / (tp + fn), 3) if (tp + fn) else 0
    print(f"  binaria TP/FP/FN/TN = {tp}/{fp}/{fn}/{tn}  prec={prec} recall={rec}")
    print("Familia (predichas / aciertos):")
    for fam in FAMILY_PRECEDENCE:
        p = stats["family_pred"].get(fam, 0)
        if p:
            print(f"  {fam:<22} {p}  (aciertos {stats['family_correct'].get(fam, 0)})")
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
    print(f"\n===== CLASIFICADOR CONTEXTUAL v3 - dos pases ({len(files)} ventanas) =====")
    print(f"Local: -{CONTEXT_ROWS_BEFORE}/+{CONTEXT_ROWS_AFTER} (UDP -{CONTEXT_UDP_BEFORE}/+{CONTEXT_UDP_AFTER}); "
          f"bucket temporal={BUCKET_SECONDS}s\n")
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

"""
Wrapper web SEGURO del clasificador contextual v5 para ventanas CSV pequeñas.

- Reutiliza la lógica científica real de la v3 (importada SIN modificarla) y le añade
  el override de ssh_horizontal_scan por fan-out al puerto 22 (la mejora de la v5),
  calculado dentro de la ventana subida.
- Si no se puede importar la v3 (entorno distinto), cae a un clasificador DEMO
  autocontenido con las reglas principales, dejándolo claro en la respuesta.
- No ejecuta los scripts científicos sobre datos reales ni escribe resultados
  versionados: trabaja solo en memoria sobre la ventana subida.

La validación científica completa está en los scripts de análisis (no aquí).
"""

from __future__ import annotations

import csv
import importlib.util
import io
from collections import Counter, defaultdict
from pathlib import Path

# Columnas esperadas (formato de teaching). También se acepta el formato posicional
# de UGR'16 de 13 columnas sin cabecera (timestamp,duration,src,dst,sport,dport,
# protocol,flags,fwd,tos,packets,bytes,label).
EXPECTED_COLUMNS = [
    "timestamp", "src_ip", "dst_ip", "protocol",
    "src_port", "dst_port", "packets", "bytes", "flags", "label",
]
REQUIRED_COLUMNS = ["src_ip", "dst_ip", "protocol", "dst_port", "packets", "bytes"]
LABEL_ALIASES = ["label", "true_label", "etiqueta"]
MAX_CSV_BYTES = 5 * 1024 * 1024  # 5 MB
MAX_RETURN_ROWS = 500            # filas devueltas en el JSON (el resumen usa todas)
SSH_PORT = 22
SSH_FANOUT_MIN = 50              # umbral de fan-out SSH (constante de la v5: LC_SSH_MIN_DSTS)

_V3_PATH = Path(__file__).resolve().parents[3] / "scripts" / "02_attack_analysis" / "detect_attack_flows_contextual_v3.py"

ATTACK_LABELS = {"dos", "anomaly-udpscan", "nerisbotnet", "scan11", "scan44",
                 "anomaly-sshscan"}
LABEL_TO_FAMILY = {
    "scan11": "vertical_scan", "scan44": "vertical_scan",
    "anomaly-udpscan": "udp_scan", "dos": "tcp_flood",
    "nerisbotnet": "coordinated_botnet", "anomaly-sshscan": "ssh_horizontal_scan",
}
CONF_SCORE = {"alta": 0.9, "media": 0.65, "baja": 0.4, "insuficiente": 0.2}


def _load_v3():
    try:
        spec = importlib.util.spec_from_file_location("v3_base_web", str(_V3_PATH))
        m = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(m)
        return m
    except Exception:
        return None


V3 = _load_v3()
USING_REAL_V5 = V3 is not None
ENGINE = "v5 (lógica v3 real + override SSH fan-out)" if USING_REAL_V5 else "demo (reglas principales)"


def expected_columns() -> dict:
    return {
        "expected_columns": EXPECTED_COLUMNS,
        "required": REQUIRED_COLUMNS,
        "optional": ["timestamp", "duration", "src_port", "flags", "label"],
        "label_column_aliases": LABEL_ALIASES,
        "also_accepts_positional_ugr16_13col": True,
        "max_size_mb": MAX_CSV_BYTES // (1024 * 1024),
        "engine": ENGINE,
        "notes": (
            "Sube una ventana pequeña (≤5 MB). Acepta CSV con cabecera (columnas por nombre) "
            "o el formato posicional de UGR'16 de 13 columnas sin cabecera. Si incluye la "
            "columna de etiqueta real, se calcula el acierto; si no, solo se muestra la confianza."
        ),
    }


def _to_float(v, d=0.0):
    try:
        return float(v)
    except (TypeError, ValueError):
        return d


def _to_int(v, d=0):
    try:
        return int(float(v))
    except (TypeError, ValueError):
        return d


def _row_from_named(d: dict) -> dict:
    label = ""
    for a in LABEL_ALIASES:
        if a in d and str(d[a]).strip():
            label = str(d[a]).strip()
            break
    return {
        "timestamp": str(d.get("timestamp", "")),
        "duration": _to_float(d.get("duration", 0)),
        "src_ip": str(d.get("src_ip", "")),
        "dst_ip": str(d.get("dst_ip", "")),
        "src_port": _to_int(d.get("src_port", 0)),
        "dst_port": _to_int(d.get("dst_port", 0)),
        "protocol": str(d.get("protocol", "")).upper(),
        "flags": str(d.get("flags", "")),
        "packets": _to_int(d.get("packets", 0)),
        "bytes": _to_int(d.get("bytes", 0)),
        "label": label,
    }


def _row_from_positional(cells: list) -> dict | None:
    if len(cells) != 13:
        return None
    return {
        "timestamp": cells[0], "duration": _to_float(cells[1]),
        "src_ip": cells[2], "dst_ip": cells[3],
        "src_port": _to_int(cells[4]), "dst_port": _to_int(cells[5]),
        "protocol": (cells[6] or "").upper(), "flags": cells[7],
        "packets": _to_int(cells[10]), "bytes": _to_int(cells[11]),
        "label": (cells[12] or "").strip(),
    }


def parse_csv(text: str):
    """Devuelve (rows, label_present, fmt). Soporta cabecera por nombre o posicional 13-col."""
    sample = text[:4096]
    has_header = "src_ip" in sample.lower() or "timestamp" in sample.lower()
    rows, label_present = [], False
    if has_header:
        reader = csv.DictReader(io.StringIO(text))
        cols = [c.strip().lower() for c in (reader.fieldnames or [])]
        missing = [c for c in REQUIRED_COLUMNS if c not in cols]
        if missing:
            raise ValueError(f"Faltan columnas requeridas: {missing}. Esperadas: {EXPECTED_COLUMNS}.")
        label_present = any(a in cols for a in LABEL_ALIASES)
        for raw in reader:
            d = {(k or "").strip().lower(): v for k, v in raw.items()}
            rows.append(_row_from_named(d))
        return rows, label_present, "named"
    # posicional UGR'16 (13 columnas, sin cabecera)
    for cells in csv.reader(io.StringIO(text)):
        r = _row_from_positional(cells)
        if r is not None:
            rows.append(r)
    if not rows:
        raise ValueError(
            "No se reconocieron columnas. Usa CSV con cabecera "
            f"({', '.join(EXPECTED_COLUMNS)}) o el formato posicional de UGR'16 (13 columnas)."
        )
    label_present = any(r["label"] in ATTACK_LABELS or r["label"] == "background" for r in rows)
    return rows, label_present, "positional_ugr16_13col"


# ---------------------------------------------------------------------------
# Clasificación
# ---------------------------------------------------------------------------

def _classify_real_v5(rows: list[dict]) -> list[dict]:
    n = len(rows)
    p1 = []
    for i, t in enumerate(rows):
        if V3.is_interesting(t):
            ctx = rows[max(0, i - V3.CONTEXT_ROWS_BEFORE):min(n, i + V3.CONTEXT_ROWS_AFTER + 1)]
            wide = (rows[max(0, i - V3.CONTEXT_UDP_BEFORE):min(n, i + V3.CONTEXT_UDP_AFTER + 1)]
                    if t["protocol"] == "UDP" else ctx)
            p1.append(V3.classify_local(t, ctx, wide))
        else:
            p1.append({"binary": "background", "attack_score": 0.0, "reason": "tráfico normal",
                       "family": "", "confidence": "", "evidence": "", "limitations": []})
    agg = V3.compute_window_aggregates(rows)

    # override SSH fan-out (estilo v5) dentro de la ventana
    fanout = defaultdict(set)
    for t in rows:
        if t["protocol"] == "TCP" and t["dst_port"] == SSH_PORT:
            fanout[t["src_ip"]].add(t["dst_ip"])
    ssh_scanners = {s for s, dsts in fanout.items() if len(dsts) >= SSH_FANOUT_MIN}

    results = []
    for i, t in enumerate(rows):
        res = V3.reconcile(t, p1[i], agg)
        fam = res["predicted_behavior_family"]
        binary = res["is_attack_predicted"]
        sub = res["predicted_attack_subtype"]
        conf = res["subtype_confidence"]
        score = float(res["attack_score"] or 0)
        ev = res["evidence"]
        if t["protocol"] == "TCP" and t["dst_port"] == SSH_PORT and t["src_ip"] in ssh_scanners:
            fam, binary, sub = "ssh_horizontal_scan", "attack", "anomaly-sshscan"
            conf = conf or "media"
            score = max(score, 0.9)
            ev = (f"contexto global: el origen {t['src_ip']} contacta {len(fanout[t['src_ip']])} "
                  f"destinos distintos por el puerto 22 (fan-out SSH)")
        results.append({"binary": binary, "family": fam, "subtype": sub,
                        "confidence": conf, "score": score, "evidence": ev})
    return results


def _classify_demo(rows: list[dict]) -> list[dict]:
    """Clasificador DEMO autocontenido (si no se puede importar la v3 real)."""
    n = len(rows)
    fanout22 = defaultdict(set)
    udp_by_src = defaultdict(set)
    flood = defaultdict(int)
    vert_ports = defaultdict(set)
    botnet_sig = Counter()
    for t in rows:
        if t["protocol"] == "TCP" and t["dst_port"] == 22:
            fanout22[t["src_ip"]].add(t["dst_ip"])
        if t["protocol"] == "UDP":
            udp_by_src[t["src_ip"]].add(t["dst_ip"])
        flood[(t["dst_ip"], t["dst_port"])] += 1
        vert_ports[(t["src_ip"], t["dst_ip"])].add(t["dst_port"])
        botnet_sig[(t["dst_port"], t["bytes"], t["packets"])] += 1
    results = []
    for t in rows:
        fam, sub, binary, conf, score, ev = "", "", "background", "", 0.0, "tráfico normal"
        if t["protocol"] == "TCP" and t["dst_port"] == 22 and len(fanout22[t["src_ip"]]) >= SSH_FANOUT_MIN:
            fam, sub, binary, conf, score = "ssh_horizontal_scan", "anomaly-sshscan", "attack", "media", 0.9
            ev = f"fan-out SSH: {len(fanout22[t['src_ip']])} destinos al puerto 22"
        elif len(vert_ports[(t["src_ip"], t["dst_ip"])]) >= 8 and t["protocol"] == "TCP":
            fam, sub, binary, conf, score = "vertical_scan", "scan11", "attack", "media", 0.7
            ev = f"barrido vertical: {len(vert_ports[(t['src_ip'], t['dst_ip'])])} puertos del mismo destino"
        elif flood[(t["dst_ip"], t["dst_port"])] >= 10 and t["protocol"] == "TCP":
            fam, sub, binary, conf, score = "tcp_flood", "dos", "attack", "media", 0.6
            ev = f"concentración hacia {t['dst_ip']}:{t['dst_port']} ({flood[(t['dst_ip'], t['dst_port'])]} flujos)"
        elif t["protocol"] == "UDP" and len(udp_by_src[t["src_ip"]]) >= 6 and t["dst_port"] != 53:
            fam, sub, binary, conf, score = "udp_scan", "anomaly-udpscan", "attack", "media", 0.7
            ev = f"dispersión UDP: {len(udp_by_src[t['src_ip']])} destinos"
        results.append({"binary": binary, "family": fam, "subtype": sub,
                        "confidence": conf, "score": score, "evidence": ev})
    return results


def _confidence(binary: str, conf: str, score: float):
    if binary == "attack":
        label = conf if conf in ("alta", "media", "baja") else (
            "alta" if score >= 0.7 else "media" if score >= 0.45 else "baja")
        return label, round(CONF_SCORE.get(label, score), 3)
    if binary == "insufficient_evidence":
        return "baja", round(score, 3)
    # background: confianza de que es normal
    return ("alta" if score == 0 else "media"), round(1 - score, 3)


def run(csv_text: str) -> dict:
    if csv_text is None:
        raise ValueError("No se recibió contenido CSV.")
    size = len(csv_text.encode("utf-8"))
    if size > MAX_CSV_BYTES:
        raise ValueError(f"El CSV supera el límite de {MAX_CSV_BYTES // (1024*1024)} MB ({size} bytes).")

    rows, label_present, fmt = parse_csv(csv_text)
    if not rows:
        raise ValueError("El CSV no contiene filas válidas.")

    preds = _classify_real_v5(rows) if USING_REAL_V5 else _classify_demo(rows)

    out_rows = []
    n_attack = n_bg = correct = labeled = 0
    subtypes = Counter()
    conf_scores = []
    for i, (t, p) in enumerate(zip(rows, preds), start=1):
        clabel, cscore = _confidence(p["binary"], p["confidence"], p["score"])
        conf_scores.append(cscore)
        pred_is_attack = p["binary"] == "attack"
        if pred_is_attack:
            n_attack += 1
            if p["subtype"] and p["subtype"] != "undetermined":
                subtypes[p["subtype"]] += 1
        else:
            n_bg += 1

        true_label = t["label"] if (label_present and t["label"]) else None
        is_correct = None
        if true_label is not None:
            labeled += 1
            truth_attack = true_label in ATTACK_LABELS
            is_correct = (pred_is_attack == truth_attack)
            if is_correct:
                correct += 1

        if i <= MAX_RETURN_ROWS:
            out_rows.append({
                "row": i,
                "protocol": t["protocol"],
                "dst_port": t["dst_port"],
                "prediction": p["binary"],
                "family": p["family"],
                "subtype": p["subtype"],
                "confidence": clabel,
                "confidence_score": cscore,
                "explanation": p["evidence"],
                "true_label": true_label,
                "correct": is_correct,
            })

    if labeled > 0:
        accuracy = round(correct / labeled, 4)
        accuracy_note = (
            f"Acierto binario (ataque/normal) sobre {labeled} filas con etiqueta real. "
            "Compara la predicción con la columna de etiqueta del CSV."
        )
    else:
        accuracy = None
        accuracy_note = (
            "No se puede calcular acierto porque el CSV no incluye etiqueta real. "
            "Se muestra la confianza del detector."
        )

    summary = {
        "total_rows": len(rows),
        "predicted_background": n_bg,
        "predicted_attack": n_attack,
        "dominant_attack": subtypes.most_common(1)[0][0] if subtypes else None,
        "average_confidence": round(sum(conf_scores) / len(conf_scores), 3) if conf_scores else 0.0,
        "accuracy": accuracy,
        "accuracy_note": accuracy_note,
        "engine": ENGINE,
        "input_format": fmt,
        "returned_rows": len(out_rows),
    }
    return {"summary": summary, "rows": out_rows}

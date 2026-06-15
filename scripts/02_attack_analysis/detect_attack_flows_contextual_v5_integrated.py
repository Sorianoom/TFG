"""
Script: detect_attack_flows_contextual_v5_integrated.py

Versión CANDIDATA INTEGRADA del clasificador contextual por traza.

Combina:
  - la v3 ESTABLE (importada SIN modificar) como base,
  - un TERCER PASE GLOBAL por src_ip para detectar ssh_horizontal_scan
    low-and-slow mediante FAN-OUT SSH (la mejora validada en april.week2),
  - un relabel de CONFIANZA del botnet (coordinated_botnet_high_confidence /
    coordinated_botnet_low_confidence) que NO cambia qué trazas se detectan
    (solo el nombre según la confianza ya calculada por la v3).

Garantías
---------
- NO modifica detect_attack_flows_contextual_v3.py (lo importa y reutiliza).
- La clasificación de scan11/scan44/udp_scan/tcp_flood/unknown es IDÉNTICA a la v3.
- El botnet se DETECTA igual que en la v3; solo se renombra por confianza.
- No usa IPs concretas, ni la etiqueta para detectar, ni bytes exactos como firma.
- spam NO se fuerza (se mantiene tal cual la v3).

Arquitectura (dos pasadas por el conjunto de ventanas de --input-dir)
---------------------------------------------------------------------
  PASE A (global): acumula, por src_ip, el tráfico TCP hacia el puerto 22
    (destinos distintos = fan-out, flujos, ligereza, sesiones completas, tiempos).
    Marca como escáner SSH los orígenes con FAN-OUT masivo a muchos destinos.
  PASE B (por ventana): ejecuta la v3 estándar por ventana y luego APLICA el
    override de ssh_horizontal_scan para las trazas al puerto 22 de esos orígenes.

Uso:
  python scripts/02_attack_analysis/detect_attack_flows_contextual_v5_integrated.py \
    --input-dir data/attack_analysis \
    --output-results data/attack_analysis/flow_level_detection_results_v5_integrated.csv \
    --output-summary data/attack_analysis/flow_level_detection_summary_v5_integrated.csv
"""

import argparse
import csv
import glob
import importlib.util
from collections import Counter, defaultdict
from pathlib import Path

V3_PATH = "scripts/02_attack_analysis/detect_attack_flows_contextual_v3.py"

# --- tercer pase: ssh fan-out (parámetros del experimento de contexto largo) ---
SSH_PORT = 22
LC_SSH_MIN_DSTS = 50                 # fan-out nuclear: destinos distintos al 22 por origen
LC_SSH_WINDOWS_MIN = [5, 15, 30, 60] # ventanas para la persistencia (confianza)
LC_SSH_MIN_BUCKETS = 2
LC_SSH_LIGHT_SOFT = 0.5

ATTACK_LABELS = {"dos", "anomaly-udpscan", "nerisbotnet", "scan11", "scan44",
                 "anomaly-sshscan", "anomaly-spam"}
LABEL_TO_FAMILY = {
    "scan11": "vertical_scan", "scan44": "vertical_scan",
    "anomaly-udpscan": "udp_scan", "dos": "tcp_flood",
    "nerisbotnet": "coordinated_botnet", "anomaly-sshscan": "ssh_horizontal_scan",
    "anomaly-spam": "smtp_campaign",
}
CANON = {
    "coordinated_botnet_high_confidence": "coordinated_botnet",
    "coordinated_botnet_low_confidence": "coordinated_botnet",
}


def canon(fam):
    return CANON.get(fam, fam)


def load_v3():
    spec = importlib.util.spec_from_file_location("v3_base", V3_PATH)
    m = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(m)
    return m


def ts_seconds(ts):
    try:
        d, t = ts.split(" ")
        day = int(d.split("-")[2])
        h, m, s = t.split(":")
        return day * 86400 + int(h) * 3600 + int(m) * 60 + int(s)
    except Exception:
        return 0


def is_window_file(path):
    if "descartados" in Path(path).parts:  # material retirado del análisis principal
        return False
    n = Path(path).name.lower()
    bad = ("results", "summary", "label", "audit", "extraction")
    return not any(b in n for b in bad)


def main():
    ap = argparse.ArgumentParser(description="Clasificador contextual v5 integrado (v3 + pase SSH fan-out)")
    ap.add_argument("--input-dir", default="data/attack_analysis")
    ap.add_argument("--output-results", default="data/attack_analysis/flow_level_detection_results_v5_integrated.csv")
    ap.add_argument("--output-summary", default="data/attack_analysis/flow_level_detection_summary_v5_integrated.csv")
    args = ap.parse_args()

    v3 = load_v3()
    files = sorted(p for p in glob.glob(args.input_dir + "/**/*.csv", recursive=True) if is_window_file(p))
    if not files:
        print(f"[ERROR] No hay ventanas en {args.input_dir}")
        return

    # ----------------------------------------------------------------------
    # PASE A: fan-out SSH global por src_ip
    # ----------------------------------------------------------------------
    print(f"[v5] PASE A (fan-out SSH global) sobre {len(files)} ventanas ...")
    ssh_by_src = defaultdict(lambda: {"dsts": set(), "n": 0, "secs": [], "light": 0})
    for fp in files:
        for t in v3.load_window(fp):
            if t["protocol"] == "TCP" and t["dst_port"] == SSH_PORT:
                e = ssh_by_src[t["src_ip"]]
                e["dsts"].add(t["dst_ip"]); e["n"] += 1
                e["secs"].append(ts_seconds(t["timestamp"]))
                if t["packets"] <= 2 and t["duration"] <= 0.01:
                    e["light"] += 1
    ssh_scanners = {s: e for s, e in ssh_by_src.items() if len(e["dsts"]) >= LC_SSH_MIN_DSTS}
    print(f"[v5] Orígenes SSH con fan-out >= {LC_SSH_MIN_DSTS}: {len(ssh_scanners)} "
          f"({[ (s, len(e['dsts'])) for s, e in list(ssh_scanners.items())[:5] ]})")

    def ssh_conf(e):
        light = e["light"] / e["n"] if e["n"] else 0
        persist = max((len({x // (w * 60) for x in e["secs"]}) for w in LC_SSH_WINDOWS_MIN), default=0)
        if len(e["dsts"]) >= 1000 and persist >= LC_SSH_MIN_BUCKETS:
            return "alta"
        if persist >= LC_SSH_MIN_BUCKETS or light >= LC_SSH_LIGHT_SOFT:
            return "media"
        return "baja"

    # ----------------------------------------------------------------------
    # PASE B: v3 por ventana + override SSH + relabel botnet
    # ----------------------------------------------------------------------
    OUT_FIELDS = ["source_file", "row_index", "original_label", "is_attack_predicted",
                  "attack_score", "attack_binary_reason", "predicted_behavior_family",
                  "predicted_attack_subtype", "subtype_confidence", "evidence", "limitations"]
    Path(args.output_results).parent.mkdir(parents=True, exist_ok=True)
    Path(args.output_summary).parent.mkdir(parents=True, exist_ok=True)

    st = {"total": 0, "binary": Counter(), "tp": 0, "fp": 0, "fn": 0, "tn": 0,
          "fam_pred": Counter(), "canon_pred": Counter(), "canon_correct": Counter(),
          "orig_family": Counter(), "subtype_pred": Counter(), "subtype_correct": Counter(),
          "orig_subtype": Counter(), "ssh_override": 0, "ssh_override_fp": 0}

    print("[v5] PASE B (v3 por ventana + override SSH) ...")
    with open(args.output_results, "w", encoding="utf-8", newline="") as out:
        w = csv.DictWriter(out, fieldnames=OUT_FIELDS, extrasaction="ignore")
        w.writeheader()
        for fp in files:
            rows = v3.load_window(fp)
            sf = fp.replace("\\", "/")
            n = len(rows)
            p1 = []
            for i, t in enumerate(rows):
                if v3.is_interesting(t):
                    ctx = rows[max(0, i - v3.CONTEXT_ROWS_BEFORE):min(n, i + v3.CONTEXT_ROWS_AFTER + 1)]
                    wide = (rows[max(0, i - v3.CONTEXT_UDP_BEFORE):min(n, i + v3.CONTEXT_UDP_AFTER + 1)]
                            if t["protocol"] == "UDP" else ctx)
                    p1.append(v3.classify_local(t, ctx, wide))
                else:
                    p1.append({"binary": "background", "attack_score": 0.0, "reason": "",
                               "family": "", "confidence": "", "evidence": "", "limitations": []})
            agg = v3.compute_window_aggregates(rows)
            for i, t in enumerate(rows):
                res = v3.reconcile(t, p1[i], agg)
                fam = res["predicted_behavior_family"]
                binary = res["is_attack_predicted"]
                sub = res["predicted_attack_subtype"]
                conf = res["subtype_confidence"]
                score = res["attack_score"]
                reason = res["attack_binary_reason"]
                ev = res["evidence"]
                lim = res["limitations"]

                # --- TERCER PASE: override ssh_horizontal_scan por fan-out global ---
                if t["protocol"] == "TCP" and t["dst_port"] == SSH_PORT and t["src_ip"] in ssh_scanners:
                    e = ssh_scanners[t["src_ip"]]
                    fam, binary, sub = "ssh_horizontal_scan", "attack", "anomaly-sshscan"
                    conf = ssh_conf(e)
                    score = max(score, 0.9)
                    reason = "ssh_horizontal_scan (pase 3 global por fan-out)"
                    ev = (f"contexto largo: origen {t['src_ip']} con fan-out {len(e['dsts'])} destinos "
                          f"distintos al puerto 22 ({e['n']} flujos)")
                    lim = "detección por agregación global por origen (no contexto local)"
                    st["ssh_override"] += 1
                    if t["label"] != "anomaly-sshscan":
                        st["ssh_override_fp"] += 1
                # --- relabel de confianza del botnet (sin cambiar la detección) ---
                elif fam == "coordinated_botnet":
                    if conf in ("alta", "media"):
                        fam = "coordinated_botnet_high_confidence"
                    else:
                        fam = "coordinated_botnet_low_confidence"

                # --- métricas ---
                orig = t["label"]
                cf = canon(fam) if fam else ""
                st["total"] += 1
                st["binary"][binary] += 1
                if fam:
                    st["fam_pred"][fam] += 1
                    st["canon_pred"][cf] += 1
                if sub and sub != "undetermined":
                    st["subtype_pred"][sub] += 1
                oatk = orig in ATTACK_LABELS
                patk = binary == "attack"
                if oatk and patk: st["tp"] += 1
                elif oatk and not patk: st["fn"] += 1
                elif (not oatk) and patk: st["fp"] += 1
                else: st["tn"] += 1
                if cf and LABEL_TO_FAMILY.get(orig) == cf: st["canon_correct"][cf] += 1
                if sub and sub == orig: st["subtype_correct"][sub] += 1
                if oatk:
                    st["orig_family"][LABEL_TO_FAMILY[orig]] += 1
                    st["orig_subtype"][orig] += 1

                w.writerow({"source_file": sf, "row_index": i, "original_label": orig,
                            "is_attack_predicted": binary, "attack_score": score,
                            "attack_binary_reason": reason, "predicted_behavior_family": fam,
                            "predicted_attack_subtype": sub, "subtype_confidence": conf,
                            "evidence": ev, "limitations": lim})

    # ----------------------------------------------------------------------
    # Resumen
    # ----------------------------------------------------------------------
    tp, fp, fn, tn = st["tp"], st["fp"], st["fn"], st["tn"]
    prec = round(tp / (tp + fp), 4) if (tp + fp) else 0
    rec = round(tp / (tp + fn), 4) if (tp + fn) else 0
    f1 = round(2 * prec * rec / (prec + rec), 4) if (prec + rec) else 0

    with open(args.output_summary, "w", encoding="utf-8", newline="") as f:
        wr = csv.writer(f)
        wr.writerow(["seccion", "clave", "valor1", "valor2", "valor3"])
        wr.writerow(["TOTALES", "trazas", st["total"], "", ""])
        for k in ("attack", "background", "insufficient_evidence"):
            wr.writerow(["ETAPA1_binaria", k, st["binary"].get(k, 0), "", ""])
        wr.writerow(["ETAPA1_eval", "TP/FP/FN/TN", f"{tp}/{fp}/{fn}/{tn}", "", ""])
        wr.writerow(["ETAPA1_eval", "precision_ataque", prec, "recall_ataque", rec])
        wr.writerow(["ETAPA1_eval", "f1_ataque", f1, "", ""])
        wr.writerow(["SSH_PASE3", "override/override_fp", st["ssh_override"], st["ssh_override_fp"], ""])
        wr.writerow(["FAMILIA", "familia(canonica)", "predichas", "etiq_original", "aciertos"])
        for fam in sorted(set(st["canon_pred"]) | set(st["orig_family"])):
            wr.writerow(["FAMILIA", fam, st["canon_pred"].get(fam, 0),
                         st["orig_family"].get(fam, 0), st["canon_correct"].get(fam, 0)])
        wr.writerow(["GRANULAR", "familia_v5", "predichas", "", ""])
        for fam in sorted(st["fam_pred"]):
            wr.writerow(["GRANULAR", fam, st["fam_pred"].get(fam, 0), "", ""])
        wr.writerow(["SUBTIPO", "subtipo", "predichos", "etiq_original", "aciertos"])
        for s in sorted(set(st["subtype_pred"]) | set(st["orig_subtype"])):
            wr.writerow(["SUBTIPO", s, st["subtype_pred"].get(s, 0),
                         st["orig_subtype"].get(s, 0), st["subtype_correct"].get(s, 0)])

    print("\n===== RESUMEN v5 INTEGRADO =====")
    print(f"Total trazas: {st['total']:,}")
    print(f"BINARIO TP/FP/FN/TN = {tp}/{fp}/{fn}/{tn}  prec={prec} recall={rec} F1={f1}")
    print(f"Pase 3 SSH: {st['ssh_override']} trazas marcadas (FP override: {st['ssh_override_fp']})")
    print("Familia canónica (pred / orig / aciertos):")
    for fam in sorted(set(st["canon_pred"]) | set(st["orig_family"])):
        print(f"  {fam:<22} {st['canon_pred'].get(fam,0):>8} {st['orig_family'].get(fam,0):>8} {st['canon_correct'].get(fam,0):>8}")
    print(f"\nResultados: {args.output_results}")
    print(f"Resumen:    {args.output_summary}")
    print("\nNOTA: versión CANDIDATA. La v3 estándar sigue vigente hasta validar que v5 no degrada.")


if __name__ == "__main__":
    main()

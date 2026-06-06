"""
Script: detect_attack_flows_contextual_v3_long_context_experimental.py

VARIANTE EXPERIMENTAL de contexto LARGO para anomaly-sshscan (y señal débil de
spam), evaluada sobre april.week2. NO sustituye a la v3.

Motivación
----------
La v3 evalúa el contexto LOCAL (±30 filas). En april.week2 el sshscan es
low-and-slow y se diluye localmente: la v3 obtuvo recall 0 sobre 29.298 trazas.
El análisis de los datos muestra que el sshscan de april es un ÚNICO origen
(42.219.156.231) con un FAN-OUT enorme (26.231 destinos distintos al puerto 22),
pero con ~87 % de flujos "completos" (multipaquete). Por eso la regla de la v3
("incompletos + sin sesión completa") lo excluye.

Idea experimental
-----------------
Añadir un pase de CONTEXTO LARGO que agrega el comportamiento POR src_ip sobre un
horizonte temporal amplio y detecta sshscan por FAN-OUT (un origen que sondea
muchísimos destinos distintos en el puerto 22), con la persistencia temporal como
señal de confianza (se prueban ventanas de 5/15/30/60 min). NO se usa la IP
concreta, ni la etiqueta, ni bytes exactos: solo conteos relacionales por origen.

Restricciones
-------------
- NO modifica detect_attack_flows_contextual_v3.py (lo IMPORTA y reutiliza).
- NO cambia reglas/umbrales de la v3 para scan/dos/udp/vertical.
- NO usa IPs concretas, ni la etiqueta para detectar, ni firmas de bytes exactos.
- Variante EXPERIMENTAL; la v3 estándar sigue siendo la principal.

Entrada (por defecto): ventanas de april.week2 ya extraídas
  data/generalization/windows/april_week2/
(Se aprovecha como pool de agregación por origen: la unión de bloques contiguos
con timestamps reales; el contexto "largo" es la vista global por src_ip.)

Salidas:
  data/generalization/results/generalization_results_v3_long_context_april_week2.csv
  data/generalization/summaries/generalization_summary_v3_long_context_april_week2.csv
"""

import csv
import glob
import importlib.util
import statistics
from collections import defaultdict, Counter
from pathlib import Path

V3_PATH = "scripts/02_attack_analysis/detect_attack_flows_contextual_v3.py"

WINDOWS_DIR = "data/generalization/windows/april_week2"
RESULTS_FILE = Path("data/generalization/results/generalization_results_v3_long_context_april_week2.csv")
SUMMARY_FILE = Path("data/generalization/summaries/generalization_summary_v3_long_context_april_week2.csv")

# --- umbrales experimentales (contexto largo) ---
SSH_PORT = 22
SPAM_PORT = 25
# Fan-out: nº de destinos distintos al puerto 22 por origen (señal NUCLEAR).
LC_SSH_MIN_DSTS = 50
LC_SSH_DSTS_GRID = [20, 50, 100]        # sensibilidad a reportar
# Persistencia temporal (confianza): ventanas a probar (minutos) y buckets mínimos.
LC_SSH_WINDOWS_MIN = [5, 15, 30, 60]
LC_SSH_MIN_BUCKETS = 2
LC_SSH_LIGHT_SOFT = 0.5                  # ratio de flujos ligeros -> sube confianza

# spam (señal débil, low_confidence)
LC_SPAM_MIN_DSTS = 5
LC_SPAM_MIN_TEMPORAL_CONC = 0.3
LC_SPAM_BYTES_VAR_MAX = 5_000

ATTACK_LABELS = {"dos", "anomaly-udpscan", "nerisbotnet", "scan11", "scan44",
                 "anomaly-sshscan", "anomaly-spam"}


def load_v3():
    spec = importlib.util.spec_from_file_location("v3_lc", V3_PATH)
    m = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(m)
    return m


def ts_seconds(ts):
    try:
        d, t = ts.split(" ")
        # día del mes * 86400 + hora para distinguir días dentro de la semana
        day = int(d.split("-")[2])
        h, m, s = t.split(":")
        return day * 86400 + int(h) * 3600 + int(m) * 60 + int(s)
    except Exception:
        return 0


def main():
    v3 = load_v3()
    files = sorted(glob.glob(WINDOWS_DIR + "/*.csv"))
    if not files:
        print(f"[ERROR] No hay ventanas en {WINDOWS_DIR}")
        return

    # ----------------------------------------------------------------------
    # 1) Cargar todas las ventanas: features por fila + baseline v3 por fila
    #    (la v3 se ejecuta por ventana, exactamente igual que en la evaluación)
    # ----------------------------------------------------------------------
    all_rows = []          # (source_file, row_index, row_dict, baseline_family, baseline_binary)
    ssh_by_src = defaultdict(lambda: {"dsts": set(), "n": 0, "secs": [], "light": 0, "completed": 0})
    spam_by_block = defaultdict(list)

    print(f"[lc] Procesando {len(files)} ventanas de april.week2 ...")
    for fp in files:
        rows = v3.load_window(fp)
        sf = fp.replace("\\", "/")
        n = len(rows)
        # baseline v3 por ventana (idéntico a la v3 estándar)
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
            all_rows.append([sf, i, t, res["predicted_behavior_family"], res["is_attack_predicted"]])
            # --- agregación global por origen para ssh ---
            if t["protocol"] == "TCP" and t["dst_port"] == SSH_PORT:
                e = ssh_by_src[t["src_ip"]]
                e["dsts"].add(t["dst_ip"]); e["n"] += 1
                e["secs"].append(ts_seconds(t["timestamp"]))
                if t["packets"] <= 2 and t["duration"] <= 0.01:
                    e["light"] += 1
                if t["packets"] > 2 or t["duration"] > 0.5:
                    e["completed"] += 1
            # --- agregación global por bloque /24 para spam ---
            if t["protocol"] == "TCP" and t["dst_port"] == SPAM_PORT:
                spam_by_block[v3.subnet_24(t["src_ip"])].append(t)

    total = len(all_rows)
    print(f"[lc] Trazas totales: {total:,}")

    # ----------------------------------------------------------------------
    # 2) Detección de escáneres SSH por contexto largo (fan-out) + persistencia
    # ----------------------------------------------------------------------
    def buckets_at(secs_list, w_min):
        w = w_min * 60
        return len({s // w for s in secs_list})

    def ssh_scanners_for(min_dsts, min_buckets=None, w_min=None):
        out = {}
        for src, e in ssh_by_src.items():
            if len(e["dsts"]) < min_dsts:
                continue
            if min_buckets is not None and w_min is not None:
                if buckets_at(e["secs"], w_min) < min_buckets:
                    continue
            out[src] = e
        return out

    # --- sensibilidad por umbral de fan-out (solo fan-out, sin gate de persistencia) ---
    grid_rows = []
    for md in LC_SSH_DSTS_GRID:
        srcs = ssh_scanners_for(md)
        flagged_flows = sum(e["n"] for e in srcs.values())
        grid_rows.append((md, len(srcs), flagged_flows))

    # --- persistencia por ventana temporal (gate) con fan-out fijo = LC_SSH_MIN_DSTS ---
    perwindow_rows = []
    for w in LC_SSH_WINDOWS_MIN:
        srcs = ssh_scanners_for(LC_SSH_MIN_DSTS, LC_SSH_MIN_BUCKETS, w)
        flows = sum(e["n"] for e in srcs.values())
        perwindow_rows.append((w, len(srcs), flows))

    # Detección final: fan-out nuclear (independiente de la ventana). La persistencia
    # se usa como CONFIANZA (no como gate), porque el muestreo limita su cobertura.
    ssh_scanners = ssh_scanners_for(LC_SSH_MIN_DSTS)

    def ssh_confidence(e):
        light_ratio = e["light"] / e["n"] if e["n"] else 0
        persist = max(buckets_at(e["secs"], w) for w in LC_SSH_WINDOWS_MIN)
        if len(e["dsts"]) >= 1000 and persist >= LC_SSH_MIN_BUCKETS:
            return "alta"
        if len(e["dsts"]) >= LC_SSH_MIN_DSTS and (persist >= LC_SSH_MIN_BUCKETS or light_ratio >= LC_SSH_LIGHT_SOFT):
            return "media"
        return "baja"

    # ----------------------------------------------------------------------
    # 3) Señal débil de spam (low_confidence) por bloque /24
    # ----------------------------------------------------------------------
    spam_blocks = {}
    for block, flows in spam_by_block.items():
        dsts = {r["dst_ip"] for r in flows}
        bvar = v3.safe_variance([r["bytes"] for r in flows])
        bk = Counter(v3.ts_bucket(r["timestamp"]) for r in flows)
        conc = bk.most_common(1)[0][1] / len(flows) if flows else 0
        rep = Counter(r["packets"] for r in flows).most_common(1)[0][1] / len(flows) if flows else 0
        if (len(dsts) >= LC_SPAM_MIN_DSTS and conc >= LC_SPAM_MIN_TEMPORAL_CONC
                and bvar < LC_SPAM_BYTES_VAR_MAX and rep >= 0.3):
            spam_blocks[block] = {"fan_out": len(dsts), "conc": round(conc, 3)}

    # ----------------------------------------------------------------------
    # 4) Etiqueta final por traza (override de contexto largo sobre baseline v3)
    # ----------------------------------------------------------------------
    OUT_FIELDS = ["source_file", "row_index", "original_label", "is_attack_predicted",
                  "predicted_behavior_family", "predicted_attack_subtype", "confidence",
                  "evidence", "limitations"]
    RESULTS_FILE.parent.mkdir(parents=True, exist_ok=True)
    SUMMARY_FILE.parent.mkdir(parents=True, exist_ok=True)

    stats = {"tp": 0, "fp": 0, "fn": 0, "tn": 0,
             "ssh_pred": 0, "ssh_correct": 0, "ssh_orig": 0,
             "spam_pred": 0, "spam_correct": 0, "spam_orig": 0,
             "fam_pred": Counter()}

    with open(RESULTS_FILE, "w", encoding="utf-8", newline="") as out:
        w = csv.DictWriter(out, fieldnames=OUT_FIELDS, extrasaction="ignore")
        w.writeheader()
        for sf, idx, t, base_fam, base_bin in all_rows:
            fam, binary, conf, ev, lim = base_fam, base_bin, "", "", ""
            # override SSH (contexto largo, fan-out)
            if t["protocol"] == "TCP" and t["dst_port"] == SSH_PORT and t["src_ip"] in ssh_scanners:
                e = ssh_scanners[t["src_ip"]]
                conf = ssh_confidence(e)
                fam, binary = "ssh_horizontal_scan", "attack"
                ev = (f"contexto largo: origen {t['src_ip']} con fan-out {len(e['dsts'])} destinos "
                      f"distintos al puerto 22 ({e['n']} flujos)")
                lim = "detección por agregación global por origen (no contexto local)"
            # override SPAM débil (solo si no es ya ataque)
            elif (t["protocol"] == "TCP" and t["dst_port"] == SPAM_PORT
                  and v3.subnet_24(t["src_ip"]) in spam_blocks and base_bin != "attack"):
                info = spam_blocks[v3.subnet_24(t["src_ip"])]
                fam, binary, conf = "smtp_campaign_low_confidence", "attack", "baja"
                ev = f"señal débil: fan-out SMTP {info['fan_out']} destinos, concentración {info['conc']}"
                lim = "exploratorio: difícil separar de SMTP legítimo"

            sub = {"ssh_horizontal_scan": "anomaly-sshscan",
                   "smtp_campaign_low_confidence": "anomaly-spam"}.get(fam, "")
            orig = t["label"]
            # métricas
            oatk = orig in ATTACK_LABELS
            patk = binary == "attack"
            if oatk and patk: stats["tp"] += 1
            elif oatk and not patk: stats["fn"] += 1
            elif (not oatk) and patk: stats["fp"] += 1
            else: stats["tn"] += 1
            if fam: stats["fam_pred"][fam] += 1
            if fam == "ssh_horizontal_scan":
                stats["ssh_pred"] += 1
                if orig == "anomaly-sshscan": stats["ssh_correct"] += 1
            if fam == "smtp_campaign_low_confidence":
                stats["spam_pred"] += 1
                if orig == "anomaly-spam": stats["spam_correct"] += 1
            if orig == "anomaly-sshscan": stats["ssh_orig"] += 1
            if orig == "anomaly-spam": stats["spam_orig"] += 1

            w.writerow({"source_file": sf, "row_index": idx, "original_label": orig,
                        "is_attack_predicted": binary, "predicted_behavior_family": fam,
                        "predicted_attack_subtype": sub, "confidence": conf,
                        "evidence": ev, "limitations": lim})

    # ----------------------------------------------------------------------
    # 5) Resumen
    # ----------------------------------------------------------------------
    def prf(correct, pred, orig):
        p = correct / pred if pred else 0.0
        r = correct / orig if orig else 0.0
        f = 2 * p * r / (p + r) if (p + r) else 0.0
        return round(p, 4), round(r, 4), round(f, 4)

    tp, fp, fn, tn = stats["tp"], stats["fp"], stats["fn"], stats["tn"]
    bprec = round(tp / (tp + fp), 4) if (tp + fp) else 0
    brec = round(tp / (tp + fn), 4) if (tp + fn) else 0
    bf1 = round(2 * bprec * brec / (bprec + brec), 4) if (bprec + brec) else 0
    sshp, sshr, sshf = prf(stats["ssh_correct"], stats["ssh_pred"], stats["ssh_orig"])
    spp, spr, spf = prf(stats["spam_correct"], stats["spam_pred"], stats["spam_orig"])

    with open(SUMMARY_FILE, "w", encoding="utf-8", newline="") as f:
        wr = csv.writer(f)
        wr.writerow(["seccion", "clave", "v1", "v2", "v3"])
        wr.writerow(["TOTALES", "trazas", total, "", ""])
        wr.writerow(["BINARIO", "TP/FP/FN/TN", f"{tp}/{fp}/{fn}/{tn}", "", ""])
        wr.writerow(["BINARIO", "precision/recall/F1", bprec, brec, bf1])
        wr.writerow(["SSHSCAN", "precision/recall/F1", sshp, sshr, sshf])
        wr.writerow(["SSHSCAN", "pred/correct/orig", stats["ssh_pred"], stats["ssh_correct"], stats["ssh_orig"]])
        wr.writerow(["SPAM", "precision/recall/F1", spp, spr, spf])
        wr.writerow(["SPAM", "pred/correct/orig", stats["spam_pred"], stats["spam_correct"], stats["spam_orig"]])
        wr.writerow(["SENSIBILIDAD_FANOUT", "min_dsts/n_srcs/flujos", "", "", ""])
        for md, ns, fl in grid_rows:
            wr.writerow(["SENSIBILIDAD_FANOUT", f"min_dsts={md}", ns, fl, ""])
        wr.writerow(["PERSISTENCIA_VENTANA", "min/n_srcs/flujos (gate persistencia)", "", "", ""])
        for wm, ns, fl in perwindow_rows:
            wr.writerow(["PERSISTENCIA_VENTANA", f"{wm}min", ns, fl, ""])

    print("\n===== RESUMEN LONG-CONTEXT (april.week2) =====")
    print(f"Total trazas: {total:,}")
    print(f"BINARIO  TP/FP/FN/TN = {tp}/{fp}/{fn}/{tn}  prec={bprec} recall={brec} F1={bf1}")
    print(f"SSHSCAN  prec={sshp} recall={sshr} F1={sshf}  (pred {stats['ssh_pred']}, correct {stats['ssh_correct']}, orig {stats['ssh_orig']})")
    print(f"SPAM     prec={spp} recall={spr} F1={spf}  (pred {stats['spam_pred']}, correct {stats['spam_correct']}, orig {stats['spam_orig']})")
    print("Sensibilidad fan-out (min_dsts -> nº orígenes / flujos marcados):")
    for md, ns, fl in grid_rows:
        print(f"  min_dsts={md:<4} -> {ns} orígenes, {fl} flujos")
    print("Persistencia por ventana (gate, fan-out fijo=50):")
    for wm, ns, fl in perwindow_rows:
        print(f"  {wm:>2} min -> {ns} orígenes, {fl} flujos")
    print(f"\nResultados: {RESULTS_FILE}")
    print(f"Resumen:    {SUMMARY_FILE}")
    print("\nNOTA: variante EXPERIMENTAL. La v3 estándar sigue siendo el clasificador principal.")


if __name__ == "__main__":
    main()

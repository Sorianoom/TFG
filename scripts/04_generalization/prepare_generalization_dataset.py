"""
Script: prepare_generalization_dataset.py

Prepara datos de GENERALIZACIÓN para evaluar la v3 sobre una semana de UGR'16 no
usada para formular reglas (por defecto august.week2).

Por qué VENTANAS CONTIGUAS y no un muestreo de filas sueltas
------------------------------------------------------------
La v3 usa contexto LOCAL (±30 filas) que asume adyacencia temporal real. Un
muestreo de filas dispersas rompería esa localidad y haría inservible la
detección (los flujos de un mismo barrido/ráfaga quedarían separados). Por eso
se extraen BLOQUES CONTIGUOS (preservando el orden original), idénticos en forma
a las ventanas `rows_2000` con las que se evaluó la v3.

Las etiquetas se usan SOLO para LOCALIZAR ventanas (extracción), nunca para
detectar (la v3 no usa la etiqueta para clasificar).

El formato del raw `.uniqblacklistremoved` ya coincide con el de 13 columnas que
espera la v3, así que "limpiar" = validar filas (13 columnas, no vacías,
timestamp del periodo).

Salidas:
  - data/generalization/windows/<dataset>/window_XXXXX.csv   (ventanas para la v3)
  - data/generalization/samples/<dataset>_generalization_sample_1M.csv (concatenado)
  - data/generalization/summaries/<dataset>_label_counts.csv (conteo de etiquetas)

Uso:
  python scripts/04_generalization/prepare_generalization_dataset.py
  python scripts/04_generalization/prepare_generalization_dataset.py --max-scan-rows 5000000
"""

import argparse
import csv
from collections import Counter, defaultdict
from pathlib import Path

EXPECTED_COLUMNS = 13
ATTACK_LABELS = {
    "dos", "anomaly-udpscan", "nerisbotnet", "scan11", "scan44",
    "anomaly-sshscan", "anomaly-spam",
}
NON_ATTACK = {"background", "blacklist", ""}

# ---------------------------------------------------------------------------
# Configuración por defecto
# ---------------------------------------------------------------------------

DEFAULTS = {
    "input": "data/raw/august.week2.csv.uniqblacklistremoved",
    "dataset": "august_week2",
    "ts_prefix": "2016-08-",
    "block_size": 2000,                 # como las ventanas rows_2000
    "max_windows_per_attack": 60,       # tope de ventanas por clase de ataque
    "background_every": 400,            # 1 bloque de background cada N bloques
    "max_background_windows": 80,
    "sample_target_rows": 1_000_000,
}

GEN_DIR = Path("data/generalization")


def is_valid(parts, ts_prefix):
    return (len(parts) == EXPECTED_COLUMNS
            and parts[0].startswith(ts_prefix)
            and not all(p.strip() == "" for p in parts))


def main():
    ap = argparse.ArgumentParser(description="Prepara dataset de generalización (ventanas contiguas)")
    ap.add_argument("--input", default=DEFAULTS["input"])
    ap.add_argument("--dataset", default=DEFAULTS["dataset"])
    ap.add_argument("--ts-prefix", default=DEFAULTS["ts_prefix"])
    ap.add_argument("--block-size", type=int, default=DEFAULTS["block_size"])
    ap.add_argument("--max-windows-per-attack", type=int, default=DEFAULTS["max_windows_per_attack"])
    ap.add_argument("--background-every", type=int, default=DEFAULTS["background_every"])
    ap.add_argument("--max-background-windows", type=int, default=DEFAULTS["max_background_windows"])
    ap.add_argument("--sample-target-rows", type=int, default=DEFAULTS["sample_target_rows"])
    ap.add_argument("--max-scan-rows", type=int, default=None,
                    help="Tope de filas a leer (None = todo el fichero). Para limitar tiempo.")
    args = ap.parse_args()

    inp = Path(args.input)
    if not inp.exists():
        print(f"[ERROR] No existe el fichero de entrada: {inp}")
        return

    windows_dir = GEN_DIR / "windows" / args.dataset
    windows_dir.mkdir(parents=True, exist_ok=True)
    (GEN_DIR / "samples").mkdir(parents=True, exist_ok=True)
    (GEN_DIR / "summaries").mkdir(parents=True, exist_ok=True)
    (GEN_DIR / "clean").mkdir(parents=True, exist_ok=True)
    (GEN_DIR / "results").mkdir(parents=True, exist_ok=True)

    label_counts = Counter()           # conteo sobre TODO lo escaneado
    attack_window_counts = Counter()   # ventanas guardadas por clase de ataque
    bg_windows = 0
    kept_windows = 0
    kept_rows = 0
    sample_lines = []                  # concatenado (solo si cabe en memoria razonable)
    sample_cap = args.sample_target_rows

    block = []
    block_labels = set()
    block_idx = 0
    total = 0
    valid = 0
    capture_done = False

    print(f"[prep] Leyendo {inp} ...")
    print(f"[prep] dataset={args.dataset} block_size={args.block_size}")

    def flush_block():
        nonlocal kept_windows, kept_rows, bg_windows, block, block_labels
        if not block:
            return
        attacks_here = block_labels & ATTACK_LABELS
        keep = False
        if attacks_here:
            # guardar si alguna clase de ataque del bloque no ha llegado a su tope
            if any(attack_window_counts[a] < args.max_windows_per_attack for a in attacks_here):
                keep = True
                for a in attacks_here:
                    attack_window_counts[a] += 1
        else:
            # bloque solo background/blacklist: muestreo periódico
            if (block_idx % args.background_every == 0) and bg_windows < args.max_background_windows:
                keep = True
                bg_windows += 1
        if keep:
            kept_windows += 1
            kept_rows += len(block)
            wpath = windows_dir / f"window_{kept_windows:05d}.csv"
            with open(wpath, "w", encoding="utf-8", newline="") as wf:
                wf.write("\n".join(block) + "\n")
            if len(sample_lines) < sample_cap:
                sample_lines.extend(block)
        block = []
        block_labels = set()

    with open(inp, "r", encoding="utf-8", errors="ignore", newline="") as f:
        reader = csv.reader(f)
        for row in reader:
            total += 1
            if not is_valid(row, args.ts_prefix):
                continue
            valid += 1
            label = row[12].strip()
            label_counts[label] += 1
            block.append(",".join(row))
            block_labels.add(label)
            if len(block) >= args.block_size:
                block_idx += 1
                flush_block()

            if total % 5_000_000 == 0:
                print(f"  [prep] leidas {total:,} | validas {valid:,} | ventanas {kept_windows} | "
                      f"filas guardadas {kept_rows:,}")

            # condición de parada de CAPTURA (se sigue contando si no hay tope de scan)
            if not capture_done:
                attacks_full = all(attack_window_counts[a] >= args.max_windows_per_attack
                                   for a in ATTACK_LABELS if label_counts.get(a, 0) > 0)
                if (kept_rows >= sample_cap and bg_windows >= args.max_background_windows
                        and attacks_full and len(label_counts) > 1):
                    capture_done = True
                    print(f"  [prep] objetivos de captura alcanzados a {total:,} filas; "
                          f"se detiene el escaneo.")
                    break

            if args.max_scan_rows and total >= args.max_scan_rows:
                print(f"  [prep] alcanzado --max-scan-rows={args.max_scan_rows:,}; se detiene.")
                break

    flush_block()  # último bloque parcial si contiene ataque

    # --- guardar muestra concatenada ---
    sample_path = GEN_DIR / "samples" / f"{args.dataset}_generalization_sample_1M.csv"
    with open(sample_path, "w", encoding="utf-8", newline="") as sf:
        sf.write("\n".join(sample_lines) + ("\n" if sample_lines else ""))

    # --- guardar conteo de etiquetas ---
    counts_path = GEN_DIR / "summaries" / f"{args.dataset}_label_counts.csv"
    with open(counts_path, "w", encoding="utf-8", newline="") as cf:
        w = csv.writer(cf)
        w.writerow(["label", "count", "es_ataque"])
        for lbl, cnt in label_counts.most_common():
            w.writerow([lbl, cnt, lbl in ATTACK_LABELS])

    print("\n===== RESUMEN PREPARACIÓN =====")
    print(f"Filas leídas (escaneadas): {total:,} | válidas: {valid:,}")
    print(f"Ventanas guardadas: {kept_windows} | filas en muestra: {kept_rows:,}")
    print("Ventanas por clase de ataque:")
    for a in sorted(ATTACK_LABELS):
        print(f"  {a:<18} {attack_window_counts.get(a, 0)} ventanas  (filas etiqueta: {label_counts.get(a, 0):,})")
    print(f"Ventanas de background: {bg_windows}")
    print(f"\nVentanas:        {windows_dir}")
    print(f"Muestra:         {sample_path}")
    print(f"Conteo etiquetas:{counts_path}")


if __name__ == "__main__":
    main()

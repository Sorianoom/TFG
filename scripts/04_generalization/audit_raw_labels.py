"""
Script: audit_raw_labels.py

Auditoría de etiquetas de los ficheros RAW de UGR'16 disponibles en data/raw/,
para localizar en qué semanas/meses aparece cada familia de ataque (en especial
`anomaly-udpscan`).

NO ejecuta la v3, NO extrae ventanas, NO crea muestras, NO borra nada.

Eficiencia
----------
- Conteo por `line.split(',')` (los campos NetFlow no contienen comas), mucho
  más rápido que csv.reader.
- Si ya existe un conteo previo (`*_label_counts.csv` de fases anteriores), se
  REUTILIZA en lugar de reescanear (evita re-leer 50-75 GB).
- Solo se escanean los ficheros sin conteo previo, con progreso por chunks.

Salida:
  data/generalization/summaries/raw_dataset_label_audit.csv
"""

import csv
import os
from collections import Counter
from pathlib import Path

EXPECTED_COLUMNS = 13
ATTACK_FAMILIES = [
    "anomaly-udpscan", "dos", "scan11", "scan44",
    "nerisbotnet", "anomaly-sshscan", "anomaly-spam",
]
OUT = Path("data/generalization/summaries/raw_dataset_label_audit.csv")

# Ficheros raw y, si existe, su conteo ya calculado en fases previas (reutilizar).
RAW_FILES = [
    ("data/raw/august.week1.csv", None),
    ("data/raw/august.week2.csv.uniqblacklistremoved",
     "data/generalization/summaries/august_week2_label_counts.csv"),
    ("data/raw/april.week2.csv.uniqblacklistremoved",
     "data/generalization/summaries/april_week2_label_counts.csv"),
]


def load_precomputed(path):
    counts = Counter()
    with open(path, encoding="utf-8") as f:
        r = csv.reader(f)
        next(r, None)  # cabecera label,count,es_ataque
        for row in r:
            if len(row) >= 2:
                counts[row[0]] = int(row[1])
    return counts


def scan_file(path):
    """Conteo rápido de etiquetas por split. Devuelve (counts, valid_rows)."""
    counts = Counter()
    valid = 0
    total = 0
    print(f"[scan] {path} ...")
    with open(path, "r", encoding="utf-8", errors="ignore", newline="") as f:
        for line in f:
            total += 1
            parts = line.rstrip("\n").split(",")
            if len(parts) != EXPECTED_COLUMNS:
                continue
            valid += 1
            counts[parts[12].strip()] += 1
            if total % 20_000_000 == 0:
                print(f"  [scan] leidas {total:,} | validas {valid:,}")
    print(f"  [scan] FIN {path}: validas {valid:,}")
    return counts, valid


def main():
    OUT.parent.mkdir(parents=True, exist_ok=True)
    rows = []
    for raw_path, precomputed in RAW_FILES:
        p = Path(raw_path)
        if not p.exists():
            print(f"[aviso] no existe {raw_path}; se omite.")
            continue
        size_gb = round(p.stat().st_size / (1024 ** 3), 2)
        if precomputed and Path(precomputed).exists():
            counts = load_precomputed(precomputed)
            valid = sum(counts.values())
            origen = f"conteo reutilizado ({Path(precomputed).name})"
        else:
            counts, valid = scan_file(raw_path)
            origen = "escaneo completo"
        labels_found = "; ".join(f"{k}:{v}" for k, v in counts.most_common())
        row = {
            "file": p.name,
            "size_gb": size_gb,
            "valid_rows": valid,
            "origen_conteo": origen,
            "labels_found": labels_found,
        }
        for fam in ATTACK_FAMILIES:
            row[fam] = counts.get(fam, 0)
        rows.append(row)
        print(f"  -> {p.name}: udpscan={counts.get('anomaly-udpscan',0):,} | validas={valid:,}")

    # nota informativa sobre los comprimidos (duplicados, no se cuentan)
    fields = ["file", "size_gb", "valid_rows", "origen_conteo", "labels_found"] + ATTACK_FAMILIES
    with open(OUT, "w", encoding="utf-8", newline="") as f:
        w = csv.DictWriter(f, fieldnames=fields)
        w.writeheader()
        for r in rows:
            w.writerow(r)

    print(f"\n===== AUDITORÍA GUARDADA: {OUT} =====")
    print(f"{'fichero':<48} {'validas':>14} {'udpscan':>12}")
    for r in rows:
        print(f"{r['file']:<48} {r['valid_rows']:>14,} {r['anomaly-udpscan']:>12,}")
    print("\nNota: data/raw/compressed_raw/*.tar.gz son copias COMPRIMIDAS de estas mismas "
          "3 semanas (no son datos nuevos); no se cuentan.")


if __name__ == "__main__":
    main()

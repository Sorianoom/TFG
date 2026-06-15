"""
Script: recompute_baseline_no_spam.py

Corrige el baseline de ML clásico para que NO incluya clases que no forman parte
del análisis principal del TFG, de forma coherente con las decisiones
metodológicas tomadas.

NO reentrena los modelos. El F1 macro es, por definición, la media aritmética
del F1 por clase; recomputarlo excluyendo clases equivale a promediar solo las
clases que permanecen. Trabajar a partir del resumen por clase ya calculado
(`ml_baseline_summary.csv`) AISLA exactamente el efecto de excluir esas clases,
sin alterar el resto del experimento (mismo muestreo, mismos modelos, mismas
predicciones). Reentrenar cambiaría el tope por clase y haría la comparación no
homogénea.

Entrada:  data/attack_analysis/ml_baseline_summary.csv  (por clase y modelo)
Salidas:  data/attack_analysis/ml_baseline_summary_<tag>.csv   (por clase, filtrado)
          data/attack_analysis/ml_baseline_results_<tag>.csv   (macro por modelo)

No modifica los ficheros originales.

Uso:
    # baseline sin la clase descartada (por defecto)
    python scripts/03_ml_baselines/recompute_baseline_no_spam.py

    # baseline sobre las familias activas (excluye spam y blacklist)
    python scripts/03_ml_baselines/recompute_baseline_no_spam.py \
        --exclude anomaly-spam blacklist --tag active_families
"""

import argparse
import csv
import collections
from pathlib import Path

SRC = Path("data/attack_analysis/ml_baseline_summary.csv")


def macro(rows, field):
    vals = [float(r[field]) for r in rows]
    return round(sum(vals) / len(vals), 4)


def main():
    ap = argparse.ArgumentParser(description="Recalcula el F1 macro del baseline ML excluyendo clases.")
    ap.add_argument("--exclude", nargs="+", default=["anomaly-spam"],
                    help="Clases a excluir del cálculo (por defecto: anomaly-spam).")
    ap.add_argument("--tag", default="no_spam",
                    help="Sufijo de los ficheros de salida (por defecto: no_spam).")
    args = ap.parse_args()

    exclude = set(args.exclude)
    out_summary = Path(f"data/attack_analysis/ml_baseline_summary_{args.tag}.csv")
    out_results = Path(f"data/attack_analysis/ml_baseline_results_{args.tag}.csv")

    rows = list(csv.DictReader(SRC.open(encoding="utf-8")))
    kept = [r for r in rows if r["class"] not in exclude]

    # 1) resumen por clase filtrado (copia verbatim de las filas que permanecen)
    with out_summary.open("w", newline="", encoding="utf-8") as f:
        w = csv.DictWriter(f, fieldnames=rows[0].keys())
        w.writeheader()
        w.writerows(kept)

    # 2) macro por modelo recomputado sobre las clases que permanecen
    by_model = collections.defaultdict(list)
    for r in kept:
        by_model[r["model"]].append(r)
    by_model_all = collections.defaultdict(list)
    for r in rows:
        by_model_all[r["model"]].append(r)

    results = []
    for model, rs in by_model.items():
        results.append({
            "model": model,
            "n_classes": len(rs),
            "precision_macro": macro(rs, "precision"),
            "recall_macro": macro(rs, "recall"),
            "f1_macro": macro(rs, "f1"),
        })
    results.sort(key=lambda x: x["f1_macro"], reverse=True)
    with out_results.open("w", newline="", encoding="utf-8") as f:
        w = csv.DictWriter(f, fieldnames=results[0].keys())
        w.writeheader()
        w.writerows(results)

    # 3) comparación por consola
    print("Clases excluidas:", sorted({r["class"] for r in rows} - {r["class"] for r in kept}))
    print("Clases que permanecen:", sorted({r["class"] for r in kept}))
    print()
    print(f"{'model':<20} {'f1_macro_original':>18} {'f1_macro_'+args.tag:>22}")
    for model in by_model_all:
        f_all = macro(by_model_all[model], "f1")
        f_no = macro(by_model[model], "f1")
        print(f"{model:<20} {f_all:>18} {f_no:>22}")
    print(f"\nEscritos:\n  {out_summary}\n  {out_results}")


if __name__ == "__main__":
    main()

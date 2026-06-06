"""
Script: run_v3_on_generalization.py

Ejecuta el clasificador contextual v3 SOBRE DATOS DE GENERALIZACIÓN
(p. ej. ventanas de august.week2) SIN MODIFICAR la v3.

Cómo respeta "no tocar la v3"
-----------------------------
No edita `detect_attack_flows_contextual_v3.py`. Lo IMPORTA como módulo y solo
reapunta sus variables de entrada/salida (`BASE_DIR`, `RESULTS_FILE`,
`SUMMARY_FILE`) antes de llamar a su `main()`. Toda la lógica de clasificación,
reglas y umbrales se ejecuta EXACTAMENTE igual que en la versión principal.

Uso:
  python scripts/04_generalization/run_v3_on_generalization.py
  python scripts/04_generalization/run_v3_on_generalization.py \
      --input-dir data/generalization/windows/august_week2 \
      --output-results data/generalization/results/generalization_results_v3_august_week2.csv \
      --output-summary data/generalization/summaries/generalization_summary_v3_august_week2.csv
"""

import argparse
import importlib.util
from pathlib import Path

V3_PATH = "scripts/02_attack_analysis/detect_attack_flows_contextual_v3.py"


def load_v3():
    spec = importlib.util.spec_from_file_location("v3_main", V3_PATH)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


def main():
    ap = argparse.ArgumentParser(description="Ejecuta la v3 (sin modificarla) sobre datos de generalización")
    ap.add_argument("--input-dir", default="data/generalization/windows/august_week2")
    ap.add_argument("--output-results",
                    default="data/generalization/results/generalization_results_v3_august_week2.csv")
    ap.add_argument("--output-summary",
                    default="data/generalization/summaries/generalization_summary_v3_august_week2.csv")
    args = ap.parse_args()

    v3 = load_v3()

    # Solo se reapuntan rutas; la lógica de clasificación de la v3 NO se altera.
    v3.BASE_DIR = Path(args.input_dir)
    v3.RESULTS_FILE = Path(args.output_results)
    v3.SUMMARY_FILE = Path(args.output_summary)

    print("===== v3 SOBRE DATOS DE GENERALIZACIÓN (lógica intacta) =====")
    print(f"input_dir       = {args.input_dir}")
    print(f"output_results  = {args.output_results}")
    print(f"output_summary  = {args.output_summary}\n")

    Path(args.output_results).parent.mkdir(parents=True, exist_ok=True)
    Path(args.output_summary).parent.mkdir(parents=True, exist_ok=True)

    v3.main()


if __name__ == "__main__":
    main()

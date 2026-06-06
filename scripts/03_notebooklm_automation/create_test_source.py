"""
Crea una fuente pequeña centrada en trazas de ataque para probar NotebookLM.

Entrada:
data/attack_analysis/scan11/rows_2000/scan11_rows_2000_window_01.csv

Salida:
data/notebooklm_outputs/scan11/test_scan11_source.csv

La fuente resultante contiene contexto antes y después de la primera fila
etiquetada como scan11.
"""

from pathlib import Path
import csv

INPUT_FILE = Path("data/attack_analysis/scan11/rows_2000/scan11_rows_2000_window_01.csv")
OUTPUT_FILE = Path("data/notebooklm_outputs/scan11/test_scan11_source.csv")

TARGET_LABEL = "scan11"

ROWS_BEFORE = 150
ROWS_AFTER = 150

EXPECTED_COLUMNS = 13
LABEL_COL = 12


def main() -> None:
    if not INPUT_FILE.exists():
        print(f"[ERROR] No existe: {INPUT_FILE}")
        return

    rows = []

    with open(INPUT_FILE, "r", encoding="utf-8", errors="ignore", newline="") as fin:
        reader = csv.reader(fin)

        for row in reader:
            if len(row) == EXPECTED_COLUMNS:
                rows.append(row)

    if not rows:
        print("[ERROR] No se han leído filas válidas.")
        return

    attack_indexes = [
        idx for idx, row in enumerate(rows)
        if row[LABEL_COL].strip().lower() == TARGET_LABEL
    ]

    if not attack_indexes:
        print(f"[ERROR] No se han encontrado filas con label {TARGET_LABEL}.")
        return

    center_idx = attack_indexes[0]

    start_idx = max(0, center_idx - ROWS_BEFORE)
    end_idx = min(len(rows), center_idx + ROWS_AFTER + 1)

    selected_rows = rows[start_idx:end_idx]

    OUTPUT_FILE.parent.mkdir(parents=True, exist_ok=True)

    with open(OUTPUT_FILE, "w", encoding="utf-8", newline="") as fout:
        writer = csv.writer(fout)
        writer.writerows(selected_rows)

    attack_count = sum(
        1 for row in selected_rows
        if row[LABEL_COL].strip().lower() == TARGET_LABEL
    )

    print(f"[OK] Fuente reducida creada: {OUTPUT_FILE}")
    print(f"[INFO] Filas totales copiadas: {len(selected_rows)}")
    print(f"[INFO] Filas {TARGET_LABEL}: {attack_count}")
    print(f"[INFO] Índice central de ataque en ventana original: {center_idx}")
    print(f"[INFO] Rango copiado: {start_idx} - {end_idx}")


if __name__ == "__main__":
    main()
"""
Script: extract_multiple_time_windows.py

Descripción:
Extrae varias ventanas temporales alrededor de eventos de ataque.

Este script:
- Busca ocurrencias de un ataque concreto
- Extrae N filas anteriores y N posteriores
- Mantiene el contexto completo, incluyendo background
- Genera varios CSV independientes

Entrada:
- data/clean/base/august_week1_clean.csv

Salida:
- data/attack_analysis/<ataque>/<ataque>_window_1.csv
- data/attack_analysis/<ataque>/<ataque>_window_2.csv
- data/attack_analysis/<ataque>/<ataque>_window_3.csv

Uso:
python scripts/02_attack_analysis/extract_multiple_time_windows.py
"""

import csv
from pathlib import Path
from collections import deque

INPUT_FILE = Path("data/clean/base/august_week1_clean.csv")

TARGET_ATTACK = "anomaly-sshscan"
WINDOW_SIZE = 1000          # filas antes y después
NUM_WINDOWS = 3             # número de ventanas a extraer
MIN_GAP_ROWS = 50_000       # separación mínima entre ventanas

OUTPUT_DIR = Path(f"data/attack_analysis/{TARGET_ATTACK}")


def save_window(output_file: Path, before_rows: list[list[str]], attack_row: list[str], after_rows: list[list[str]]) -> None:
    """
    Guarda una ventana temporal en CSV.
    """
    with open(output_file, "w", encoding="utf-8", newline="") as outfile:
        writer = csv.writer(outfile)

        for row in before_rows:
            writer.writerow(row)

        writer.writerow(attack_row)

        for row in after_rows:
            writer.writerow(row)


def extract_multiple_windows() -> None:
    """
    Extrae varias ventanas temporales alrededor de ocurrencias del ataque objetivo.
    """
    OUTPUT_DIR.mkdir(parents=True, exist_ok=True)

    buffer = deque(maxlen=WINDOW_SIZE)
    windows_extracted = 0
    rows_since_last_window = MIN_GAP_ROWS

    collecting_after = False
    current_before_rows = []
    current_attack_row = []
    current_after_rows = []

    total = 0

    try:
        with open(INPUT_FILE, "r", encoding="utf-8", errors="ignore", newline="") as infile:
            reader = csv.reader(infile)

            for row in reader:
                total += 1

                if len(row) < 1:
                    continue

                label = row[-1].strip()

                if collecting_after:
                    current_after_rows.append(row)

                    if len(current_after_rows) >= WINDOW_SIZE:
                        windows_extracted += 1
                        output_file = OUTPUT_DIR / f"{TARGET_ATTACK}_window_{windows_extracted}.csv"

                        save_window(
                            output_file=output_file,
                            before_rows=current_before_rows,
                            attack_row=current_attack_row,
                            after_rows=current_after_rows,
                        )

                        print(f"[OK] Ventana {windows_extracted} generada: {output_file}")

                        collecting_after = False
                        current_before_rows = []
                        current_attack_row = []
                        current_after_rows = []
                        rows_since_last_window = 0

                        if windows_extracted >= NUM_WINDOWS:
                            break

                    continue

                if label == TARGET_ATTACK and rows_since_last_window >= MIN_GAP_ROWS:
                    print(f"[INFO] Ataque encontrado en fila {total}")

                    current_before_rows = list(buffer)
                    current_attack_row = row
                    current_after_rows = []
                    collecting_after = True

                    continue

                buffer.append(row)
                rows_since_last_window += 1

                if total % 10_000_000 == 0:
                    print(f"[INFO] Procesadas: {total} | Ventanas extraídas: {windows_extracted}")

        print("\n===== RESUMEN =====")
        print(f"Filas procesadas: {total}")
        print(f"Ventanas extraídas: {windows_extracted}")
        print(f"Carpeta de salida: {OUTPUT_DIR}")

        if windows_extracted < NUM_WINDOWS:
            print(f"[AVISO] Solo se pudieron extraer {windows_extracted} ventanas.")

    except FileNotFoundError:
        print(f"[ERROR] No se encontró el archivo: {INPUT_FILE}")
    except Exception as e:
        print(f"[ERROR] Error inesperado: {e}")


if __name__ == "__main__":
    extract_multiple_windows()
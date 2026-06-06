"""
Script: extract_time_window.py

Descripción:
Extrae una ventana temporal alrededor de un evento de ataque.

Este script:
- Busca la primera ocurrencia de un ataque (ej: "dos")
- Extrae N filas anteriores y N posteriores
- Mantiene el contexto completo (incluye background)

Entrada:
- data/clean/base/august_week1_clean.csv

Salida:
- data/attack_analysis/time_window_<attack>.csv

Uso:
python scripts/02_attack_analysis/extract_time_window.py
"""

import csv
from pathlib import Path
from collections import deque

INPUT_FILE = Path("data/clean/base/august_week1_clean.csv")
OUTPUT_FILE = Path("data/attack_analysis/time_window_dos.csv")

TARGET_ATTACK = "dos"
WINDOW_SIZE = 1000  # filas antes y después


def extract_time_window():
    buffer = deque(maxlen=WINDOW_SIZE)
    after_rows = []
    found = False

    try:
        OUTPUT_FILE.parent.mkdir(parents=True, exist_ok=True)

        with open(INPUT_FILE, "r", encoding="utf-8", errors="ignore") as infile:
            reader = csv.reader(infile)

            for row in reader:
                label = row[-1].strip()

                if not found:
                    buffer.append(row)

                    if label == TARGET_ATTACK:
                        print("[INFO] Ataque encontrado")
                        found = True

                        # Guardar el punto del ataque
                        attack_row = row

                else:
                    after_rows.append(row)

                    if len(after_rows) >= WINDOW_SIZE:
                        break

        if not found:
            print("[ERROR] No se encontró el ataque")
            return

        # Escribir resultado
        with open(OUTPUT_FILE, "w", encoding="utf-8", newline="") as outfile:
            writer = csv.writer(outfile)

            # Antes
            for r in buffer:
                writer.writerow(r)

            # Ataque
            writer.writerow(attack_row)

            # Después
            for r in after_rows:
                writer.writerow(r)

        print("\n===== RESULTADO =====")
        print(f"Ventana generada: {OUTPUT_FILE}")
        print(f"Filas antes: {len(buffer)}")
        print(f"Filas después: {len(after_rows)}")

    except Exception as e:
        print(f"[ERROR] {e}")


if __name__ == "__main__":
    extract_time_window()
"""
Script: extract_background_70_30.py

Descripción:
Extrae una muestra exacta de tráfico normal (background) a partir del dataset limpio,
con el objetivo de construir un dataset balanceado con proporción 70% tráfico normal
y 30% tráfico malicioso.

Entrada:
- data/clean/base/august_week1_clean.csv

Salida:
- data/clean/balanced_70_30/background_sample_70_30.csv

Uso:
python scripts/balancing/extract_background_70_30.py

Notas:
- El número de filas a extraer se basa en el total de tráfico malicioso previamente calculado.
- Procesamiento en streaming (no carga el dataset completo en memoria).
- Se detiene automáticamente al alcanzar el número objetivo de filas.
"""

import csv
from pathlib import Path

INPUT_FILE = Path("data/clean/base/august_week1_clean.csv")
OUTPUT_FILE = Path("data/clean/balanced_70_30/background_sample_70_30.csv")

TARGET_BACKGROUND = 4_632_376


def extract_background() -> None:
    """
    Extrae filas de tipo 'background' hasta alcanzar el objetivo definido.
    """
    total = 0
    extracted = 0

    try:
        OUTPUT_FILE.parent.mkdir(parents=True, exist_ok=True)

        with open(INPUT_FILE, "r", encoding="utf-8", errors="ignore", newline="") as infile, \
             open(OUTPUT_FILE, "w", encoding="utf-8", newline="") as outfile:

            reader = csv.reader(infile)
            writer = csv.writer(outfile)

            for row in reader:
                total += 1

                label = row[-1].strip()

                if label == "background":
                    writer.writerow(row)
                    extracted += 1

                if extracted >= TARGET_BACKGROUND:
                    break

                if total % 10_000_000 == 0:
                    print(f"[INFO] Procesadas: {total} | Extraídas: {extracted}")

        print("\n===== RESULTADO =====")
        print(f"Filas background extraídas: {extracted}")
        print(f"Archivo generado: {OUTPUT_FILE}")

    except FileNotFoundError:
        print(f"[ERROR] No se encontró el archivo: {INPUT_FILE}")
    except Exception as e:
        print(f"[ERROR] Error inesperado: {e}")


if __name__ == "__main__":
    extract_background()
"""
Script: merge_balanced_dataset_70_30.py

Descripción:
Combina el tráfico malicioso y la muestra de tráfico normal
para generar un dataset final con proporción 70% tráfico normal
y 30% tráfico malicioso.

Entrada:
- data/clean/base/malicious_only.csv
- data/clean/balanced_70_30/background_sample_70_30.csv

Salida:
- data/clean/balanced_70_30/balanced_dataset_70_30.csv

Uso:
python scripts/balancing/merge_balanced_dataset_70_30.py

Notas:
- Procesamiento secuencial (no carga los archivos completos en memoria)
- Mantiene la estructura original de las filas
- Se utiliza para generar un escenario más cercano a condiciones reales
"""

import csv
from pathlib import Path

MALICIOUS_FILE = Path("data/clean/base/malicious_only.csv")
BACKGROUND_FILE = Path("data/clean/balanced_70_30/background_sample_70_30.csv")
OUTPUT_FILE = Path("data/clean/balanced_70_30/balanced_dataset_70_30.csv")


def append_csv(input_file: Path, writer: csv.writer) -> int:
    """
    Copia todas las filas de un archivo CSV al archivo de salida.
    """
    count = 0

    with open(input_file, "r", encoding="utf-8", errors="ignore", newline="") as infile:
        reader = csv.reader(infile)

        for row in reader:
            writer.writerow(row)
            count += 1

    return count


def merge_datasets() -> None:
    """
    Genera el dataset final combinando tráfico malicioso y tráfico background.
    """
    try:
        OUTPUT_FILE.parent.mkdir(parents=True, exist_ok=True)

        with open(OUTPUT_FILE, "w", encoding="utf-8", newline="") as outfile:
            writer = csv.writer(outfile)

            malicious_count = append_csv(MALICIOUS_FILE, writer)
            print(f"[INFO] Filas maliciosas añadidas: {malicious_count}")

            background_count = append_csv(BACKGROUND_FILE, writer)
            print(f"[INFO] Filas background añadidas: {background_count}")

        total = malicious_count + background_count

        print("\n===== RESULTADO =====")
        print(f"Filas maliciosas: {malicious_count}")
        print(f"Filas background: {background_count}")
        print(f"Total filas: {total}")
        print(f"Archivo generado: {OUTPUT_FILE}")

    except FileNotFoundError as e:
        print(f"[ERROR] Archivo no encontrado: {e.filename}")
    except Exception as e:
        print(f"[ERROR] Error inesperado: {e}")


if __name__ == "__main__":
    merge_datasets()
"""
Script: extract_malicious.py

Descripción:
Extrae todas las filas correspondientes a tráfico malicioso a partir del dataset limpio.

Este script:
- Recorre el CSV limpio en streaming
- Filtra filas donde label != "background"
- Genera un nuevo dataset solo con tráfico malicioso

Entrada:
- data/clean/base/august_week1_clean.csv

Salida:
- data/clean/base/malicious_only.csv

Uso:
python scripts/pipeline/extract_malicious.py

Notas:
- No carga el dataset completo en memoria
- Diseñado para datasets grandes (~100M filas)
- Paso clave para la posterior generación de datasets balanceados
"""

import csv
from pathlib import Path

INPUT_FILE = Path("data/clean/base/august_week1_clean.csv")
OUTPUT_FILE = Path("data/clean/base/malicious_only.csv")


def is_malicious(label: str) -> bool:
    """
    Determina si una etiqueta corresponde a tráfico malicioso.
    """
    return label != "background"


def extract_malicious(input_file: Path, output_file: Path) -> None:
    """
    Recorre el dataset limpio y extrae únicamente las filas maliciosas.
    """
    total = 0
    malicious = 0

    try:
        output_file.parent.mkdir(parents=True, exist_ok=True)

        with open(input_file, "r", encoding="utf-8", errors="ignore", newline="") as infile, \
             open(output_file, "w", encoding="utf-8", newline="") as outfile:

            reader = csv.reader(infile)
            writer = csv.writer(outfile)

            for row in reader:
                total += 1

                label = row[-1].strip()

                if is_malicious(label):
                    writer.writerow(row)
                    malicious += 1

                if total % 10_000_000 == 0:
                    print(f"[INFO] Procesadas: {total} | Maliciosas: {malicious}")

        print("\n===== RESULTADO =====")
        print(f"Total procesadas: {total}")
        print(f"Filas maliciosas: {malicious}")
        print(f"Archivo generado: {output_file}")

    except FileNotFoundError:
        print(f"[ERROR] No se encontró el archivo: {input_file}")
    except Exception as e:
        print(f"[ERROR] Error inesperado: {e}")


if __name__ == "__main__":
    extract_malicious(INPUT_FILE, OUTPUT_FILE)
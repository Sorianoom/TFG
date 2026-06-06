"""
Script: clean_large_csv.py

Descripción:
Limpia el dataset original de tráfico de red eliminando filas inválidas
antes de cualquier análisis posterior.

Este script:
- Lee el archivo CSV original en streaming
- Descarta filas vacías
- Descarta filas con número incorrecto de columnas
- Descarta filas con timestamp mal formado
- Guarda un nuevo CSV limpio
- Muestra estadísticas del proceso

Entrada:
- data/raw/august.week1.csv

Salida:
- data/clean/base/august_week1_clean.csv

Uso:
python scripts/pipeline/clean_large_csv.py

Notas:
- Diseñado para archivos muy grandes
- No carga el dataset completo en memoria
- Ideal para el preprocesado inicial del proyecto
- En este proyecto, la ejecución fue detenida manualmente (~100 millones de filas)
  mediante interrupción (Ctrl + C) para trabajar con un subconjunto representativo
  del dataset completo
"""

import csv
from pathlib import Path

INPUT_FILE = Path("data/raw/august.week1.csv")
OUTPUT_FILE = Path("data/clean/base/august_week1_clean.csv")

EXPECTED_COLUMNS = 13
EXPECTED_TIMESTAMP_PREFIX = "2016-08-"


def is_valid_row(row: list[str]) -> bool:
    """
    Valida una fila del dataset.

    Reglas:
    1. Debe tener exactamente 13 columnas
    2. No debe estar vacía
    3. La primera columna debe parecer un timestamp válido del dataset
    """
    if len(row) != EXPECTED_COLUMNS:
        return False

    if all(cell.strip() == "" for cell in row):
        return False

    if not row[0].startswith(EXPECTED_TIMESTAMP_PREFIX):
        return False

    return True


def clean_large_csv(input_file: Path, output_file: Path) -> None:
    """
    Limpia el CSV de entrada y genera un CSV limpio de salida.

    Además, muestra:
    - total de filas procesadas
    - filas válidas
    - filas descartadas
    """
    total = 0
    valid = 0
    invalid = 0

    try:
        output_file.parent.mkdir(parents=True, exist_ok=True)

        with open(input_file, "r", encoding="utf-8", errors="ignore", newline="") as infile, \
             open(output_file, "w", encoding="utf-8", newline="") as outfile:

            reader = csv.reader(infile)
            writer = csv.writer(outfile)

            for row in reader:
                total += 1

                if is_valid_row(row):
                    writer.writerow(row)
                    valid += 1
                else:
                    invalid += 1

                if total % 1_000_000 == 0:
                    print(
                        f"[INFO] Procesadas: {total} filas | "
                        f"Válidas: {valid} | "
                        f"Descartadas: {invalid}"
                    )

        print("\n===== RESUMEN FINAL =====")
        print(f"Total de filas: {total}")
        print(f"Filas válidas: {valid}")
        print(f"Filas descartadas: {invalid}")
        print(f"Archivo limpio generado: {output_file}")

    except FileNotFoundError:
        print(f"[ERROR] No se encontró el archivo: {input_file}")
    except PermissionError:
        print("[ERROR] Problema de permisos al leer o escribir archivos.")
    except Exception as e:
        print(f"[ERROR] Error inesperado: {e}")


if __name__ == "__main__":
    clean_large_csv(INPUT_FILE, OUTPUT_FILE)
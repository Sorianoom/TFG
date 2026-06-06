"""
Script: inspect_csv_sample.py

Descripción:
Genera una muestra pequeña del dataset original y permite inspeccionarla
tanto en formato CSV como en Excel.

Este script:
- Muestra una vista previa de las primeras líneas del dataset
- Extrae las primeras N filas (por defecto 1000)
- Convierte la muestra a Excel de forma robusta
- Maneja filas con diferente número de columnas

Entrada:
- data/raw/august.week1.csv

Salida:
- data/samples/sample_1000.csv
- data/samples/sample_1000.xlsx

Uso:
python scripts/samples/inspect_csv_sample.py

Notas:
- Pensado para la inspección inicial del dataset
- No debe utilizarse con datasets completos, solo con muestras pequeñas
- Permite detectar problemas de formato, filas corruptas o inconsistencias estructurales
- Fue útil para identificar errores presentes en el dataset original
"""

import csv
from pathlib import Path
from openpyxl import Workbook

INPUT_FILE = Path("data/raw/august.week1.csv")
OUTPUT_CSV = Path("data/samples/sample_1000.csv")
OUTPUT_XLSX = Path("data/samples/sample_1000.xlsx")

NUM_LINES = 1000
DELIMITER = ","


def extract_first_lines(input_file: Path, output_file: Path, num_lines: int) -> None:
    """
    Extrae las primeras N líneas del dataset original.
    """
    output_file.parent.mkdir(parents=True, exist_ok=True)

    with open(input_file, "r", encoding="utf-8", errors="ignore") as infile, \
         open(output_file, "w", encoding="utf-8", errors="ignore", newline="") as outfile:

        for i in range(num_lines):
            line = infile.readline()
            if not line:
                print(f"El archivo terminó en la línea {i}.")
                break
            outfile.write(line)

    print(f"[OK] Sample CSV generado: {output_file}")


def csv_to_excel_robust(input_csv: Path, output_xlsx: Path, delimiter: str = ",") -> None:
    """
    Convierte un CSV a Excel manejando filas con distinto número de columnas.
    """
    rows = []

    with open(input_csv, "r", encoding="utf-8", errors="ignore", newline="") as f:
        reader = csv.reader(f, delimiter=delimiter)
        for row in reader:
            rows.append(row)

    if not rows:
        raise ValueError("No se han podido leer filas del CSV.")

    max_cols = max(len(r) for r in rows)

    print(f"[INFO] Filas leídas: {len(rows)}")
    print(f"[INFO] Número máximo de columnas detectadas: {max_cols}")

    wb = Workbook()
    ws = wb.active
    ws.title = "sample_1000"

    for row in rows:
        padded_row = row + [""] * (max_cols - len(row))
        ws.append(padded_row)

    output_xlsx.parent.mkdir(parents=True, exist_ok=True)
    wb.save(output_xlsx)

    print(f"[OK] Excel generado: {output_xlsx}")


def preview_lines(input_file: Path, n: int = 10) -> None:
    """
    Muestra por consola las primeras líneas del dataset.
    """
    print("\n--- Vista previa de líneas originales ---")

    with open(input_file, "r", encoding="utf-8", errors="ignore") as f:
        for i in range(n):
            line = f.readline()
            if not line:
                break
            print(f"Línea {i+1}: {line.rstrip()}")


def main() -> None:
    """
    Ejecuta el flujo completo de inspección de muestra.
    """
    if not INPUT_FILE.exists():
        print(f"[ERROR] No existe el archivo: {INPUT_FILE}")
        return

    try:
        preview_lines(INPUT_FILE, 10)
        extract_first_lines(INPUT_FILE, OUTPUT_CSV, NUM_LINES)
        csv_to_excel_robust(OUTPUT_CSV, OUTPUT_XLSX, delimiter=DELIMITER)
    except Exception as e:
        print(f"[ERROR] {e}")


if __name__ == "__main__":
    main()
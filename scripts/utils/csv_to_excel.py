"""
Script: csv_to_excel.py

Descripción:
Convierte un archivo CSV pequeño a formato Excel (.xlsx) para facilitar
su inspección manual.

Este script:
- Lee un CSV (normalmente una muestra pequeña)
- Lo convierte a Excel
- Permite abrirlo fácilmente con herramientas como Excel

Entrada:
- data/samples/sample_1000.csv

Salida:
- data/samples/sample_1000.xlsx

Uso:
python scripts/utils/csv_to_excel.py

Notas:
- Pensado solo para archivos pequeños (ej: 1000 filas)
- No utilizar con datasets grandes (puede consumir mucha memoria)
- Utilizado en este proyecto para la inspección inicial de los datos
"""

import pandas as pd
from pathlib import Path

INPUT_CSV = Path("data/samples/sample_1000.csv")
OUTPUT_XLSX = Path("data/samples/sample_1000.xlsx")


def convert_csv_to_excel(input_csv: Path, output_xlsx: Path) -> None:
    """
    Convierte un archivo CSV en un archivo Excel.
    """
    try:
        df = pd.read_csv(input_csv, header=None, encoding="utf-8")

        output_xlsx.parent.mkdir(parents=True, exist_ok=True)
        df.to_excel(output_xlsx, index=False, header=False)

        print(f"[OK] Archivo Excel generado: {output_xlsx}")

    except FileNotFoundError:
        print(f"[ERROR] No se encontró el archivo: {input_csv}")
    except Exception as e:
        print(f"[ERROR] Error inesperado: {e}")


if __name__ == "__main__":
    convert_csv_to_excel(INPUT_CSV, OUTPUT_XLSX)
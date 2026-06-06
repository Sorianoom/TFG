"""
Script: count_lines.py

Descripción:
Cuenta el número total de líneas (filas) en un archivo CSV.

Este script:
- Recorre el archivo línea a línea
- Cuenta el número total de registros
- Evita cargar el archivo completo en memoria

Entrada:
- data/clean/base/august_week1_clean.csv

Salida:
- Número total de líneas por consola

Uso:
python scripts/utils/count_lines.py

Notas:
- Diseñado para archivos grandes
- Alternativa eficiente a métodos como Get-Content en PowerShell
- En este proyecto se utilizó para verificar que el dataset limpio
  contiene aproximadamente 100 millones de filas
"""

from pathlib import Path

INPUT_FILE = Path("data/clean/base/august_week1_clean.csv")


def count_lines(file_path: Path) -> None:
    """
    Cuenta el número total de líneas de un archivo.
    """
    count = 0

    try:
        with open(file_path, "r", encoding="utf-8", errors="ignore") as f:
            for _ in f:
                count += 1

        print(f"Total de líneas: {count}")

    except FileNotFoundError:
        print(f"[ERROR] No se encontró el archivo: {file_path}")
    except Exception as e:
        print(f"[ERROR] Error inesperado: {e}")


if __name__ == "__main__":
    count_lines(INPUT_FILE)
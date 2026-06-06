"""
Script: count_labels.py

Descripción:
Analiza el dataset limpio y calcula la distribución de etiquetas (label),
permitiendo conocer la proporción de tráfico normal y malicioso.

Este script:
- Recorre el CSV limpio en streaming
- Cuenta el número de ocurrencias de cada label
- Calcula el porcentaje de cada tipo de tráfico
- Muestra resultados ordenados por frecuencia

Entrada:
- data/clean/base/august_week1_clean.csv

Salida:
- Estadísticas por consola (no genera archivo)

Uso:
python scripts/pipeline/count_labels.py

Notas:
- No carga el dataset completo en memoria
- Diseñado para datasets grandes (100M+ filas)
- En este proyecto se ejecutó sobre ~100 millones de filas limpias
  (subconjunto representativo del dataset original)
"""

import csv
from collections import defaultdict
from pathlib import Path

INPUT_FILE = Path("data/clean/base/august_week1_clean.csv")


def count_labels(file_path: Path) -> None:
    """
    Cuenta las etiquetas del dataset y muestra su distribución.
    """
    label_counts = defaultdict(int)
    total = 0

    try:
        with open(file_path, "r", encoding="utf-8", errors="ignore") as f:
            reader = csv.reader(f)

            for row in reader:
                total += 1

                label = row[-1].strip()
                label_counts[label] += 1

                if total % 10_000_000 == 0:
                    print(f"[INFO] Procesadas: {total}")

        print("\n===== RESULTADO =====")
        print(f"Total filas: {total}\n")

        for label, count in sorted(label_counts.items(), key=lambda x: x[1], reverse=True):
            porcentaje = (count / total) * 100
            print(f"{label}: {count} ({porcentaje:.4f}%)")

    except FileNotFoundError:
        print(f"[ERROR] No se encontró el archivo: {file_path}")
    except Exception as e:
        print(f"[ERROR] Error inesperado: {e}")


if __name__ == "__main__":
    count_labels(INPUT_FILE)
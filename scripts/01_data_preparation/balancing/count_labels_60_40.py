"""
Script: count_labels_60_40.py

Descripción:
Calcula la distribución de etiquetas del dataset balanceado 60/40,
permitiendo verificar que la proporción entre tráfico normal y malicioso
es correcta.

Entrada:
- data/clean/balanced_60_40/balanced_dataset_60_40.csv

Salida:
- Estadísticas por consola (conteo y porcentaje por etiqueta)

Uso:
python scripts/balancing/count_labels_60_40.py

Notas:
- Procesamiento en streaming (no carga el archivo completo en memoria)
- Diseñado para datasets de varios millones de filas
- Se utiliza como validación del proceso de balanceo
"""

import csv
from collections import defaultdict
from pathlib import Path

INPUT_FILE = Path("data/clean/balanced_60_40/balanced_dataset_60_40.csv")


def count_labels(file_path: Path) -> None:
    """
    Recorre el dataset y calcula la distribución de etiquetas.
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

                if total % 1_000_000 == 0:
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
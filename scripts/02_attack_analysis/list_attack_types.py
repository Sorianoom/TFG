"""
Script: list_attack_types.py

Descripción:
Obtiene todos los tipos de ataques presentes en el dataset limpio.

Este script:
- Recorre el CSV en streaming
- Cuenta las ocurrencias de cada etiqueta
- Excluye tráfico normal (background) y blacklist
- Muestra los tipos de ataque ordenados por frecuencia

Entrada:
- data/clean/base/august_week1_clean.csv

Salida:
- Lista de ataques y número de ocurrencias

Uso:
python scripts/pipeline/list_attack_types.py

Notas:
- No carga el dataset completo en memoria
- Paso previo al análisis temporal de ataques
"""

import csv
from collections import defaultdict
from pathlib import Path

INPUT_FILE = Path("data/clean/base/august_week1_clean.csv")

# Labels que NO queremos considerar como ataques
EXCLUDED_LABELS = {"background", "blacklist"}


def list_attack_types(file_path: Path) -> None:
    attack_counts = defaultdict(int)
    total = 0

    try:
        with open(file_path, "r", encoding="utf-8", errors="ignore") as f:
            reader = csv.reader(f)

            for row in reader:
                total += 1

                label = row[-1].strip()

                # Solo contar ataques reales
                if label not in EXCLUDED_LABELS:
                    attack_counts[label] += 1

                # Log de progreso
                if total % 10_000_000 == 0:
                    print(f"[INFO] Procesadas: {total}")

        print("\n===== TIPOS DE ATAQUE =====\n")

        # Ordenar por frecuencia
        for attack, count in sorted(attack_counts.items(), key=lambda x: x[1], reverse=True):
            print(f"{attack}: {count}")

        print("\nTotal tipos de ataque:", len(attack_counts))

    except FileNotFoundError:
        print(f"[ERROR] No se encontró el archivo: {file_path}")
    except Exception as e:
        print(f"[ERROR] Error inesperado: {e}")


if __name__ == "__main__":
    list_attack_types(INPUT_FILE)
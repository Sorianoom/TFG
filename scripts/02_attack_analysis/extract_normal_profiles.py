"""
Script: extract_normal_profiles.py

Descripción:
Extrae muestras de tráfico normal (background) del dataset de calibración.

Genera 3 perfiles:
- tráfico laboral
- tráfico nocturno
- transición tarde-noche

Entrada:
- data/raw/april.week2.csv.uniqblacklistremoved

Salida:
- data/attack_analysis/normal/*.csv

Uso:
python scripts/02_attack_analysis/extract_normal_profiles.py
"""

import csv
from pathlib import Path

INPUT_FILE = Path("data/raw/april.week2.csv.uniqblacklistremoved")
OUTPUT_DIR = Path("data/attack_analysis/normal")

SAMPLE_SIZE = 50_000
EXPECTED_COLUMNS = 13


def is_valid_row(row: list[str]) -> bool:
    if len(row) != EXPECTED_COLUMNS:
        return False

    if all(cell.strip() == "" for cell in row):
        return False

    if " " not in row[0]:
        return False

    return True


def get_hour(timestamp: str) -> int | None:
    try:
        return int(timestamp.split(" ")[1].split(":")[0])
    except Exception:
        return None


def extract_samples() -> None:
    OUTPUT_DIR.mkdir(parents=True, exist_ok=True)

    samples = {
        "normal_laboral.csv": [],
        "normal_nocturno.csv": [],
        "normal_transicion.csv": [],
    }

    total = 0
    valid = 0
    skipped = 0

    try:
        with open(INPUT_FILE, "r", encoding="utf-8", errors="ignore", newline="") as f:
            reader = csv.reader(f)

            for row in reader:
                total += 1

                if not is_valid_row(row):
                    skipped += 1
                    continue

                valid += 1

                timestamp = row[0].strip()
                label = row[-1].strip()

                if label != "background":
                    continue

                hour = get_hour(timestamp)

                if hour is None:
                    skipped += 1
                    continue

                if 9 <= hour <= 14 and len(samples["normal_laboral.csv"]) < SAMPLE_SIZE:
                    samples["normal_laboral.csv"].append(row)

                elif 1 <= hour <= 5 and len(samples["normal_nocturno.csv"]) < SAMPLE_SIZE:
                    samples["normal_nocturno.csv"].append(row)

                elif 18 <= hour <= 22 and len(samples["normal_transicion.csv"]) < SAMPLE_SIZE:
                    samples["normal_transicion.csv"].append(row)

                if total % 1_000_000 == 0:
                    print(
                        f"[INFO] Procesadas: {total} | "
                        f"Válidas: {valid} | "
                        f"Descartadas: {skipped} | "
                        f"Laboral: {len(samples['normal_laboral.csv'])} | "
                        f"Nocturno: {len(samples['normal_nocturno.csv'])} | "
                        f"Transición: {len(samples['normal_transicion.csv'])}"
                    )

                if all(len(rows) >= SAMPLE_SIZE for rows in samples.values()):
                    break

        for filename, rows in samples.items():
            output_file = OUTPUT_DIR / filename

            with open(output_file, "w", encoding="utf-8", newline="") as out:
                writer = csv.writer(out)
                writer.writerows(rows)

            print(f"[OK] Generado: {output_file} ({len(rows)} filas)")

        print("\n===== RESUMEN =====")
        print(f"Filas procesadas: {total}")
        print(f"Filas válidas: {valid}")
        print(f"Filas descartadas: {skipped}")

    except FileNotFoundError:
        print(f"[ERROR] No se encontró el archivo: {INPUT_FILE}")
    except KeyboardInterrupt:
        print("\n[INFO] Ejecución interrumpida manualmente.")
    except Exception as e:
        print(f"[ERROR] Error inesperado: {e}")


if __name__ == "__main__":
    extract_samples()
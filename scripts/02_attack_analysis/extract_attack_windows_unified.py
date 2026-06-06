"""
Script: extract_attack_windows_unified.py

Descripción:
Extractor único de ventanas para el análisis de ataques del dataset UGR'16.

Extrae, para cada etiqueta de ataque configurada:
1. Ventanas por número de filas:
   - 2000 trazas centradas en una traza de ataque.
2. Ventanas temporales:
   - 10 segundos antes y 10 segundos después del ataque.
   - 60 segundos antes y 60 segundos después del ataque.

Salida:
data/attack_analysis/<attack_label>/
├── rows_2000/
├── time_10s/
├── time_60s/
└── <attack_label>_extraction_summary.csv

También genera un resumen global:
data/attack_analysis/window_extraction_summary.csv

Uso:
python scripts/02_attack_analysis/extract_attack_windows_unified.py

Notas:
- Pensado para ficheros grandes.
- No carga el CSV completo en memoria.
- Primero localiza ocurrencias de ataques.
- Después extrae ventanas mediante lectura secuencial.
- Las ventanas temporales tienen límite máximo de filas.
"""

import csv
from pathlib import Path
from datetime import datetime, timedelta
from collections import defaultdict
from typing import Optional


# ============================================================
# CONFIGURACIÓN PRINCIPAL
# ============================================================

RAW_FILE = Path("data/clean/base/august_week1_clean.csv")

OUTPUT_BASE_DIR = Path("data/attack_analysis")

ATTACK_LABELS = [
    "dos",
    "anomaly-udpscan",
    "nerisbotnet",
    "scan11",
    "scan44",
    "anomaly-sshscan",
    "anomaly-spam",
]

EXPECTED_COLUMNS = 13

# Índices de columnas según el esquema que estás usando:
# timestamp, duration, src_ip, dst_ip, src_port, dst_port,
# protocol, flags/state, src_tos, dst_tos, packets, bytes, label
TIMESTAMP_COL = 0
LABEL_COL = 12

WINDOW_CONFIG = {
    "rows_2000": {
        "enabled": True,
        "num_windows": 10,
        "rows_before": 1000,
        "rows_after": 1000,
    },
    "time_10s": {
        "enabled": True,
        "num_windows": 10,
        "seconds_before": 10,
        "seconds_after": 10,
        "max_rows": 100_000,
    },
    "time_60s": {
        "enabled": True,
        "num_windows": 5,
        "seconds_before": 60,
        "seconds_after": 60,
        "max_rows": 100_000,
    },
}

PROGRESS_EVERY = 10_000_000


# ============================================================
# FUNCIONES AUXILIARES
# ============================================================

def normalize_label(label: str) -> str:
    return label.strip().lower()


def parse_timestamp(value: str) -> Optional[datetime]:
    """
    Convierte el timestamp del CSV en datetime.

    Soporta formatos habituales:
    - 2016-08-01 09:00:15
    - 2016-08-01 09:00:15.003
    - 2016-08-01T09:00:15
    """

    value = value.strip()

    if not value:
        return None

    value = value.replace("T", " ")

    try:
        return datetime.fromisoformat(value)
    except ValueError:
        pass

    formats = [
        "%Y-%m-%d %H:%M:%S",
        "%Y-%m-%d %H:%M:%S.%f",
    ]

    for fmt in formats:
        try:
            return datetime.strptime(value, fmt)
        except ValueError:
            continue

    return None


def is_valid_row(row: list[str]) -> bool:
    return len(row) == EXPECTED_COLUMNS


def safe_filename(label: str) -> str:
    return label.replace("/", "_").replace("\\", "_").replace(" ", "_")


def select_evenly_distributed_occurrences(
    occurrences: list[dict],
    num_windows: int
) -> list[dict]:
    """
    Selecciona ocurrencias repartidas a lo largo del fichero.

    Si hay menos ocurrencias que ventanas solicitadas,
    devuelve todas las ocurrencias disponibles.
    """

    if not occurrences:
        return []

    if len(occurrences) <= num_windows:
        return occurrences

    selected = []

    if num_windows == 1:
        return [occurrences[len(occurrences) // 2]]

    step = (len(occurrences) - 1) / (num_windows - 1)

    used_indexes = set()

    for i in range(num_windows):
        idx = round(i * step)

        if idx not in used_indexes:
            selected.append(occurrences[idx])
            used_indexes.add(idx)

    return selected


def create_output_dirs() -> None:
    OUTPUT_BASE_DIR.mkdir(parents=True, exist_ok=True)

    for attack_label in ATTACK_LABELS:
        attack_dir = OUTPUT_BASE_DIR / safe_filename(attack_label)
        attack_dir.mkdir(parents=True, exist_ok=True)

        for window_type, cfg in WINDOW_CONFIG.items():
            if cfg.get("enabled", False):
                (attack_dir / window_type).mkdir(parents=True, exist_ok=True)


# ============================================================
# PASO 1: LOCALIZAR OCURRENCIAS DE ATAQUES
# ============================================================

def find_attack_occurrences(raw_file: Path) -> tuple[dict[str, list[dict]], int]:
    """
    Recorre el CSV una vez y guarda las posiciones de las filas
    cuyo label coincide con alguno de los ataques configurados.
    """

    occurrences = defaultdict(list)
    total_rows = 0

    target_labels = {normalize_label(label) for label in ATTACK_LABELS}

    print("\n===== PASO 1: LOCALIZANDO ATAQUES =====\n")

    with open(raw_file, "r", encoding="utf-8", errors="ignore", newline="") as f:
        reader = csv.reader(f)

        for row_number, row in enumerate(reader, start=1):
            total_rows = row_number

            if not is_valid_row(row):
                continue

            label = normalize_label(row[LABEL_COL])

            if label in target_labels:
                timestamp = parse_timestamp(row[TIMESTAMP_COL])

                occurrences[label].append(
                    {
                        "row_number": row_number,
                        "timestamp": timestamp,
                        "raw_timestamp": row[TIMESTAMP_COL],
                    }
                )

            if row_number % PROGRESS_EVERY == 0:
                print(f"[INFO] Filas procesadas: {row_number:,}")

    print("\n===== ATAQUES ENCONTRADOS =====\n")

    for attack_label in ATTACK_LABELS:
        label = normalize_label(attack_label)
        count = len(occurrences[label])
        print(f"{attack_label}: {count:,} ocurrencias")

    print(f"\n[INFO] Total de filas procesadas: {total_rows:,}")

    return occurrences, total_rows


# ============================================================
# PLANIFICACIÓN DE VENTANAS
# ============================================================

def build_window_plan(
    occurrences: dict[str, list[dict]],
    total_rows: int
) -> list[dict]:
    """
    Construye una lista con todas las ventanas que deben extraerse.
    """

    window_plan = []

    for attack_label in ATTACK_LABELS:
        label = normalize_label(attack_label)
        attack_occurrences = occurrences.get(label, [])

        if not attack_occurrences:
            print(f"[AVISO] No hay ocurrencias para {attack_label}.")
            continue

        # -------------------------
        # Ventanas por filas
        # -------------------------
        rows_cfg = WINDOW_CONFIG["rows_2000"]

        if rows_cfg.get("enabled", False):
            selected = select_evenly_distributed_occurrences(
                attack_occurrences,
                rows_cfg["num_windows"],
            )

            for idx, center in enumerate(selected, start=1):
                center_row = center["row_number"]

                start_row = max(1, center_row - rows_cfg["rows_before"])
                end_row = min(total_rows, center_row + rows_cfg["rows_after"])

                output_file = (
                    OUTPUT_BASE_DIR
                    / safe_filename(attack_label)
                    / "rows_2000"
                    / f"{safe_filename(attack_label)}_rows_2000_window_{idx:02d}.csv"
                )

                window_plan.append(
                    {
                        "attack_label": attack_label,
                        "window_type": "rows_2000",
                        "window_id": idx,
                        "center_row": center_row,
                        "center_timestamp": center["raw_timestamp"],
                        "start_row": start_row,
                        "end_row": end_row,
                        "start_time": None,
                        "end_time": None,
                        "max_rows": None,
                        "output_file": output_file,
                    }
                )

        # -------------------------
        # Ventanas temporales
        # -------------------------
        for window_type in ["time_10s", "time_60s"]:
            cfg = WINDOW_CONFIG[window_type]

            if not cfg.get("enabled", False):
                continue

            valid_time_occurrences = [
                occ for occ in attack_occurrences
                if occ["timestamp"] is not None
            ]

            if not valid_time_occurrences:
                print(
                    f"[AVISO] {attack_label}: no hay timestamps válidos "
                    f"para {window_type}."
                )
                continue

            selected = select_evenly_distributed_occurrences(
                valid_time_occurrences,
                cfg["num_windows"],
            )

            for idx, center in enumerate(selected, start=1):
                center_time = center["timestamp"]

                start_time = center_time - timedelta(seconds=cfg["seconds_before"])
                end_time = center_time + timedelta(seconds=cfg["seconds_after"])

                output_file = (
                    OUTPUT_BASE_DIR
                    / safe_filename(attack_label)
                    / window_type
                    / f"{safe_filename(attack_label)}_{window_type}_window_{idx:02d}.csv"
                )

                window_plan.append(
                    {
                        "attack_label": attack_label,
                        "window_type": window_type,
                        "window_id": idx,
                        "center_row": center["row_number"],
                        "center_timestamp": center["raw_timestamp"],
                        "start_row": None,
                        "end_row": None,
                        "start_time": start_time,
                        "end_time": end_time,
                        "max_rows": cfg["max_rows"],
                        "output_file": output_file,
                    }
                )

    print("\n===== PLAN DE EXTRACCIÓN =====\n")
    print(f"Ventanas planificadas: {len(window_plan)}")

    by_attack = defaultdict(int)
    by_type = defaultdict(int)

    for window in window_plan:
        by_attack[window["attack_label"]] += 1
        by_type[window["window_type"]] += 1

    print("\nPor ataque:")
    for attack_label, count in sorted(by_attack.items()):
        print(f"  {attack_label}: {count}")

    print("\nPor tipo:")
    for window_type, count in sorted(by_type.items()):
        print(f"  {window_type}: {count}")

    return window_plan


# ============================================================
# PASO 2: EXTRAER VENTANAS
# ============================================================

def row_in_row_window(row_number: int, window: dict) -> bool:
    return window["start_row"] <= row_number <= window["end_row"]


def row_in_time_window(timestamp: Optional[datetime], window: dict) -> bool:
    if timestamp is None:
        return False

    return window["start_time"] <= timestamp <= window["end_time"]


def extract_windows(raw_file: Path, window_plan: list[dict]) -> list[dict]:
    """
    Extrae todas las ventanas planificadas en una pasada secuencial.

    Para evitar mantener demasiados ficheros abiertos, se abren y cierran
    bajo demanda.
    """

    print("\n===== PASO 2: EXTRAYENDO VENTANAS =====\n")

    writers = {}
    file_handles = {}
    summaries = {}

    for window in window_plan:
        key = str(window["output_file"])

        summaries[key] = {
            "attack_label": window["attack_label"],
            "window_type": window["window_type"],
            "window_id": window["window_id"],
            "file_path": str(window["output_file"]),
            "center_row": window["center_row"],
            "center_timestamp": window["center_timestamp"],
            "rows_total": 0,
            "attack_rows": 0,
            "background_rows": 0,
            "other_labels": defaultdict(int),
            "status": "created",
            "truncated": False,
        }

    def open_writer(window: dict):
        key = str(window["output_file"])

        if key in writers:
            return writers[key]

        window["output_file"].parent.mkdir(parents=True, exist_ok=True)

        f = open(
            window["output_file"],
            "w",
            encoding="utf-8",
            newline="",
        )

        writer = csv.writer(f)

        writers[key] = writer
        file_handles[key] = f

        return writer

    total_rows = 0

    with open(raw_file, "r", encoding="utf-8", errors="ignore", newline="") as f:
        reader = csv.reader(f)

        for row_number, row in enumerate(reader, start=1):
            total_rows = row_number

            if not is_valid_row(row):
                continue

            timestamp = parse_timestamp(row[TIMESTAMP_COL])
            label = normalize_label(row[LABEL_COL])

            for window in window_plan:
                key = str(window["output_file"])
                summary = summaries[key]

                # Si ya se alcanzó el límite de filas en ventana temporal, no escribir más
                if (
                    window["max_rows"] is not None
                    and summary["rows_total"] >= window["max_rows"]
                ):
                    summary["truncated"] = True
                    continue

                include_row = False

                if window["window_type"] == "rows_2000":
                    include_row = row_in_row_window(row_number, window)
                else:
                    include_row = row_in_time_window(timestamp, window)

                if not include_row:
                    continue

                writer = open_writer(window)
                writer.writerow(row)

                summary["rows_total"] += 1

                if label == normalize_label(window["attack_label"]):
                    summary["attack_rows"] += 1
                elif label == "background":
                    summary["background_rows"] += 1
                else:
                    summary["other_labels"][label] += 1

            if row_number % PROGRESS_EVERY == 0:
                print(f"[INFO] Filas procesadas: {row_number:,}")

    for f in file_handles.values():
        f.close()

    print(f"\n[INFO] Total de filas recorridas en extracción: {total_rows:,}")

    final_summaries = []

    for summary in summaries.values():
        if summary["rows_total"] == 0:
            summary["status"] = "empty"
        elif summary["truncated"]:
            summary["status"] = "created_truncated"
        else:
            summary["status"] = "created"

        summary["other_labels"] = dict(summary["other_labels"])
        final_summaries.append(summary)

    return final_summaries


# ============================================================
# GUARDAR RESÚMENES
# ============================================================

def save_summary_files(summaries: list[dict]) -> None:
    """
    Guarda:
    - resumen global
    - resumen por ataque
    """

    if not summaries:
        print("[AVISO] No hay resúmenes que guardar.")
        return

    global_summary_file = OUTPUT_BASE_DIR / "window_extraction_summary.csv"

    fieldnames = [
        "attack_label",
        "window_type",
        "window_id",
        "file_path",
        "center_row",
        "center_timestamp",
        "rows_total",
        "attack_rows",
        "background_rows",
        "other_labels",
        "status",
        "truncated",
    ]

    OUTPUT_BASE_DIR.mkdir(parents=True, exist_ok=True)

    with open(global_summary_file, "w", encoding="utf-8", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=fieldnames)
        writer.writeheader()

        for summary in summaries:
            row = summary.copy()
            row["other_labels"] = str(row["other_labels"])
            writer.writerow(row)

    print(f"[OK] Resumen global guardado en: {global_summary_file}")

    summaries_by_attack = defaultdict(list)

    for summary in summaries:
        summaries_by_attack[summary["attack_label"]].append(summary)

    for attack_label, attack_summaries in summaries_by_attack.items():
        attack_dir = OUTPUT_BASE_DIR / safe_filename(attack_label)
        attack_summary_file = attack_dir / f"{safe_filename(attack_label)}_extraction_summary.csv"

        with open(attack_summary_file, "w", encoding="utf-8", newline="") as f:
            writer = csv.DictWriter(f, fieldnames=fieldnames)
            writer.writeheader()

            for summary in attack_summaries:
                row = summary.copy()
                row["other_labels"] = str(row["other_labels"])
                writer.writerow(row)

        print(f"[OK] Resumen de {attack_label} guardado en: {attack_summary_file}")


# ============================================================
# FUNCIÓN PRINCIPAL
# ============================================================

def main() -> None:
    print("\n========================================")
    print(" EXTRACTOR ÚNICO DE VENTANAS UGR'16")
    print("========================================\n")

    if not RAW_FILE.exists():
        print(f"[ERROR] No existe el fichero RAW_FILE: {RAW_FILE}")
        print("Edita la variable RAW_FILE al inicio del script.")
        return

    create_output_dirs()

    occurrences, total_rows = find_attack_occurrences(RAW_FILE)

    window_plan = build_window_plan(occurrences, total_rows)

    if not window_plan:
        print("[ERROR] No se ha generado ningún plan de extracción.")
        return

    summaries = extract_windows(RAW_FILE, window_plan)

    save_summary_files(summaries)

    print("\n===== RESUMEN FINAL =====\n")

    total_created = sum(1 for s in summaries if s["status"] == "created")
    total_truncated = sum(1 for s in summaries if s["status"] == "created_truncated")
    total_empty = sum(1 for s in summaries if s["status"] == "empty")

    print(f"Ventanas creadas: {total_created}")
    print(f"Ventanas truncadas por límite de filas: {total_truncated}")
    print(f"Ventanas vacías: {total_empty}")
    print(f"Resumen global: {OUTPUT_BASE_DIR / 'window_extraction_summary.csv'}")

    print("\n[OK] Extracción finalizada.")


if __name__ == "__main__":
    main()
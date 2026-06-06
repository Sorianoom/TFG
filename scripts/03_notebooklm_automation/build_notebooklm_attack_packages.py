"""
Script: build_notebooklm_attack_packages.py

Descripción:
Construye paquetes de fuentes por ataque para subir a NotebookLM.

Cada paquete combina:
1. Fuentes centradas en trazas de ataque.
2. Ventanas rows_2000 completas.
3. Ventanas time_10s completas.
4. Resúmenes estadísticos de ventanas time_60s.
5. Contexto metodológico para NotebookLM.

Entrada esperada:
data/attack_analysis/<attack>/
├── rows_2000/
├── time_10s/
└── time_60s/

Salida generada:
data/notebooklm_attack_packages/<attack>/
├── 01_centered_sources/
├── 02_rows_2000_full/
├── 03_time_10s_full/
├── 04_time_60s_summaries/
├── 05_context/
├── README.md
└── package_summary.csv

Uso:
python scripts/03_notebooklm_automation/build_notebooklm_attack_packages.py
"""

import csv
import shutil
from pathlib import Path
from collections import Counter
from statistics import mean, variance


# ============================================================
# CONFIGURACIÓN
# ============================================================

ATTACK_ANALYSIS_DIR = Path("data/attack_analysis")
OUTPUT_DIR = Path("data/notebooklm_attack_packages")
DOCS_DIR = Path("Docs/NotebookLLM")

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

COL_TIMESTAMP = 0
COL_DURATION = 1
COL_SRC_IP = 2
COL_DST_IP = 3
COL_SRC_PORT = 4
COL_DST_PORT = 5
COL_PROTOCOL = 6
COL_FLAGS = 7
COL_PACKETS = 10
COL_BYTES = 11
COL_LABEL = 12

CENTER_ROWS_BEFORE = 300
CENTER_ROWS_AFTER = 300

# Si quieres limitar cuántas fuentes centradas se crean por ataque, pon un número.
# Si quieres todas, déjalo en None.
MAX_CENTERED_SOURCES_PER_ATTACK = None

COPY_ROWS_2000_FULL = True
COPY_TIME_10S_FULL = True

# Por ahora las time_60s se resumen, no se copian completas.
COPY_TIME_60S_FULL = False

CONTEXT_DOCS = [
    "10_modelo_comportamiento_sintetico.md",
    "11_validacion_modelo_comportamiento.md",
    "12_validacion_hipotesis_llm.md",
    "05_prompts_llm.md",
]


# ============================================================
# UTILIDADES
# ============================================================

def safe_name(value: str) -> str:
    return value.replace("\\", "_").replace("/", "_").replace(" ", "_")


def normalize_label(value: str) -> str:
    return value.strip().lower()


def safe_int(value: str, default: int = 0) -> int:
    try:
        return int(float(value))
    except Exception:
        return default


def safe_float(value: str, default: float = 0.0) -> float:
    try:
        return float(value)
    except Exception:
        return default


def read_valid_rows(file_path: Path) -> list[list[str]]:
    rows = []

    with open(file_path, "r", encoding="utf-8", errors="ignore", newline="") as f:
        reader = csv.reader(f)

        for row in reader:
            if len(row) == EXPECTED_COLUMNS:
                rows.append(row)

    return rows


def write_rows(file_path: Path, rows: list[list[str]]) -> None:
    file_path.parent.mkdir(parents=True, exist_ok=True)

    with open(file_path, "w", encoding="utf-8", newline="") as f:
        writer = csv.writer(f)
        writer.writerows(rows)


def copy_csv_files(input_dir: Path, output_dir: Path) -> list[Path]:
    copied = []

    if not input_dir.exists():
        return copied

    output_dir.mkdir(parents=True, exist_ok=True)

    for file_path in sorted(input_dir.glob("*.csv")):
        destination = output_dir / file_path.name
        shutil.copy2(file_path, destination)
        copied.append(destination)

    return copied


def top_counter(values: list[str], n: int = 10) -> list[tuple[str, int]]:
    return Counter(values).most_common(n)


# ============================================================
# FUENTES CENTRADAS
# ============================================================

def create_centered_source(
    input_file: Path,
    output_file: Path,
    attack_label: str,
    rows_before: int,
    rows_after: int,
) -> dict:
    rows = read_valid_rows(input_file)

    result = {
        "source_type": "centered_source",
        "input_file": str(input_file),
        "output_file": str(output_file),
        "rows_total": 0,
        "attack_rows": 0,
        "background_rows": 0,
        "other_labels": {},
        "status": "not_created",
    }

    if not rows:
        result["status"] = "empty_input"
        return result

    attack_indexes = [
        idx for idx, row in enumerate(rows)
        if normalize_label(row[COL_LABEL]) == normalize_label(attack_label)
    ]

    if not attack_indexes:
        result["status"] = "no_attack_rows"
        return result

    # Usamos la primera ocurrencia de ataque dentro de la ventana.
    center_idx = attack_indexes[0]

    start_idx = max(0, center_idx - rows_before)
    end_idx = min(len(rows), center_idx + rows_after + 1)

    selected_rows = rows[start_idx:end_idx]

    write_rows(output_file, selected_rows)

    label_counts = Counter(normalize_label(row[COL_LABEL]) for row in selected_rows)

    result.update(
        {
            "rows_total": len(selected_rows),
            "attack_rows": label_counts.get(normalize_label(attack_label), 0),
            "background_rows": label_counts.get("background", 0),
            "other_labels": dict(
                (label, count)
                for label, count in label_counts.items()
                if label not in {normalize_label(attack_label), "background"}
            ),
            "status": "created",
        }
    )

    return result


def build_centered_sources(
    attack_label: str,
    attack_dir: Path,
    package_dir: Path,
) -> list[dict]:
    rows_dir = attack_dir / "rows_2000"
    output_dir = package_dir / "01_centered_sources"

    summaries = []

    if not rows_dir.exists():
        return summaries

    csv_files = sorted(rows_dir.glob("*.csv"))

    if MAX_CENTERED_SOURCES_PER_ATTACK is not None:
        csv_files = csv_files[:MAX_CENTERED_SOURCES_PER_ATTACK]

    for idx, file_path in enumerate(csv_files, start=1):
        output_file = output_dir / f"{safe_name(attack_label)}_centered_{idx:02d}.csv"

        summary = create_centered_source(
            input_file=file_path,
            output_file=output_file,
            attack_label=attack_label,
            rows_before=CENTER_ROWS_BEFORE,
            rows_after=CENTER_ROWS_AFTER,
        )

        summaries.append(summary)

    return summaries


# ============================================================
# MÉTRICAS Y RESÚMENES
# ============================================================

def compute_window_metrics(rows: list[list[str]], attack_label: str) -> dict:
    if not rows:
        return {
            "rows_total": 0,
            "attack_rows": 0,
            "background_rows": 0,
            "other_labels": {},
            "unique_src_ips": 0,
            "unique_dst_ips": 0,
            "unique_src_ports": 0,
            "unique_dst_ports": 0,
            "avg_duration": 0,
            "avg_packets": 0,
            "avg_bytes": 0,
            "duration_variance": 0,
            "bytes_variance": 0,
            "zero_duration_ratio": 0,
            "low_packet_ratio": 0,
            "top_src_ips": [],
            "top_dst_ips": [],
            "top_src_ports": [],
            "top_dst_ports": [],
            "top_protocols": [],
            "top_flags": [],
            "top_timestamps": [],
        }

    labels = [normalize_label(row[COL_LABEL]) for row in rows]
    durations = [safe_float(row[COL_DURATION]) for row in rows]
    packets = [safe_int(row[COL_PACKETS]) for row in rows]
    bytes_values = [safe_int(row[COL_BYTES]) for row in rows]

    src_ips = [row[COL_SRC_IP] for row in rows]
    dst_ips = [row[COL_DST_IP] for row in rows]
    src_ports = [row[COL_SRC_PORT] for row in rows]
    dst_ports = [row[COL_DST_PORT] for row in rows]
    protocols = [row[COL_PROTOCOL] for row in rows]
    flags = [row[COL_FLAGS] for row in rows]
    timestamps = [row[COL_TIMESTAMP] for row in rows]

    label_counts = Counter(labels)
    attack_norm = normalize_label(attack_label)

    metrics = {
        "rows_total": len(rows),
        "attack_rows": label_counts.get(attack_norm, 0),
        "background_rows": label_counts.get("background", 0),
        "other_labels": dict(
            (label, count)
            for label, count in label_counts.items()
            if label not in {attack_norm, "background"}
        ),
        "unique_src_ips": len(set(src_ips)),
        "unique_dst_ips": len(set(dst_ips)),
        "unique_src_ports": len(set(src_ports)),
        "unique_dst_ports": len(set(dst_ports)),
        "avg_duration": round(mean(durations), 6) if durations else 0.0,
        "avg_packets": round(mean(packets), 3) if packets else 0.0,
        "avg_bytes": round(mean(bytes_values), 3) if bytes_values else 0.0,
        "duration_variance": round(variance(durations), 6) if len(durations) > 1 else 0.0,
        "bytes_variance": round(variance(bytes_values), 3) if len(bytes_values) > 1 else 0.0,
        "zero_duration_ratio": round(sum(1 for d in durations if d <= 0.001) / len(rows), 4),
        "low_packet_ratio": round(sum(1 for p in packets if p <= 3) / len(rows), 4),
        "top_src_ips": top_counter(src_ips),
        "top_dst_ips": top_counter(dst_ips),
        "top_src_ports": top_counter(src_ports),
        "top_dst_ports": top_counter(dst_ports),
        "top_protocols": top_counter(protocols),
        "top_flags": top_counter(flags),
        "top_timestamps": top_counter(timestamps),
    }

    return metrics


def write_time_60s_summary(
    input_file: Path,
    output_file: Path,
    attack_label: str,
) -> dict:
    rows = read_valid_rows(input_file)
    metrics = compute_window_metrics(rows, attack_label)

    output_file.parent.mkdir(parents=True, exist_ok=True)

    attack_ratio = (
        metrics["attack_rows"] / metrics["rows_total"]
        if metrics["rows_total"] > 0
        else 0
    )

    content = []

    content.append(f"# Resumen de ventana time_60s: `{input_file.name}`")
    content.append("")
    content.append("## 1. Identificación")
    content.append("")
    content.append(f"- Ataque objetivo: `{attack_label}`")
    content.append(f"- Archivo original: `{input_file}`")
    content.append(f"- Filas totales: `{metrics['rows_total']}`")
    content.append(f"- Filas del ataque: `{metrics['attack_rows']}`")
    content.append(f"- Ratio de ataque: `{attack_ratio:.4f}`")
    content.append(f"- Filas background: `{metrics['background_rows']}`")
    content.append(f"- Otras etiquetas: `{metrics['other_labels']}`")
    content.append("")
    content.append("## 2. Diversidad")
    content.append("")
    content.append(f"- IPs origen únicas: `{metrics.get('unique_src_ips', 0)}`")
    content.append(f"- IPs destino únicas: `{metrics.get('unique_dst_ips', 0)}`")
    content.append(f"- Puertos origen únicos: `{metrics.get('unique_src_ports', 0)}`")
    content.append(f"- Puertos destino únicos: `{metrics.get('unique_dst_ports', 0)}`")
    content.append("")
    content.append("## 3. Métricas agregadas")
    content.append("")
    content.append(f"- Duración media: `{metrics.get('avg_duration', 0)}`")
    content.append(f"- Paquetes medios: `{metrics.get('avg_packets', 0)}`")
    content.append(f"- Bytes medios: `{metrics.get('avg_bytes', 0)}`")
    content.append(f"- Varianza duración: `{metrics.get('duration_variance', 0)}`")
    content.append(f"- Varianza bytes: `{metrics.get('bytes_variance', 0)}`")
    content.append(f"- Ratio duración cero: `{metrics.get('zero_duration_ratio', 0)}`")
    content.append(f"- Ratio pocos paquetes: `{metrics.get('low_packet_ratio', 0)}`")
    content.append("")
    content.append("## 4. Elementos dominantes")
    content.append("")
    content.append(f"- Top IPs origen: `{metrics.get('top_src_ips', [])}`")
    content.append(f"- Top IPs destino: `{metrics.get('top_dst_ips', [])}`")
    content.append(f"- Top puertos origen: `{metrics.get('top_src_ports', [])}`")
    content.append(f"- Top puertos destino: `{metrics.get('top_dst_ports', [])}`")
    content.append(f"- Top protocolos: `{metrics.get('top_protocols', [])}`")
    content.append(f"- Top flags: `{metrics.get('top_flags', [])}`")
    content.append(f"- Top timestamps: `{metrics.get('top_timestamps', [])}`")
    content.append("")
    content.append("## 5. Nota metodológica")
    content.append("")
    content.append(
        "Este archivo es un resumen estadístico de una ventana temporal amplia. "
        "Su objetivo es proporcionar contexto a NotebookLM sin cargar necesariamente "
        "la ventana completa, que puede contener mucho tráfico de fondo en redes ISP."
    )
    content.append("")

    output_file.write_text("\n".join(content), encoding="utf-8")

    return {
        "source_type": "time_60s_summary",
        "input_file": str(input_file),
        "output_file": str(output_file),
        "rows_total": metrics["rows_total"],
        "attack_rows": metrics["attack_rows"],
        "background_rows": metrics["background_rows"],
        "other_labels": metrics["other_labels"],
        "status": "created",
    }


def build_time_60s_summaries(
    attack_label: str,
    attack_dir: Path,
    package_dir: Path,
) -> list[dict]:
    input_dir = attack_dir / "time_60s"
    output_dir = package_dir / "04_time_60s_summaries"

    summaries = []

    if not input_dir.exists():
        return summaries

    for idx, file_path in enumerate(sorted(input_dir.glob("*.csv")), start=1):
        output_file = output_dir / f"{safe_name(attack_label)}_time_60s_summary_{idx:02d}.md"

        summary = write_time_60s_summary(
            input_file=file_path,
            output_file=output_file,
            attack_label=attack_label,
        )

        summaries.append(summary)

    return summaries


# ============================================================
# CONTEXTO
# ============================================================

def create_attack_context_file(attack_label: str, package_dir: Path) -> Path:
    context_dir = package_dir / "05_context"
    context_dir.mkdir(parents=True, exist_ok=True)

    output_file = context_dir / f"{safe_name(attack_label)}_notebook_context.md"

    prompt = f"""# Contexto para NotebookLM: {attack_label}

## Objetivo del cuaderno

Este cuaderno contiene fuentes relacionadas con el ataque `{attack_label}` del dataset UGR'16.

El objetivo es analizar el comportamiento estructural del ataque a partir de varias escalas de contexto:

1. Fuentes centradas en trazas del ataque.
2. Ventanas completas `rows_2000`.
3. Ventanas temporales `time_10s`.
4. Resúmenes estadísticos de ventanas `time_60s`.
5. Contexto del modelo de comportamiento sintético.

## Instrucciones de análisis

Al analizar estas fuentes, no se debe describir línea por línea.

El análisis debe centrarse en:

- patrón estructural común
- invariantes entre ventanas
- variaciones según el tipo de fuente
- diferencias entre ataque y background
- topología de comunicación
- protocolo predominante
- puertos origen y destino relevantes
- duración, paquetes y bytes
- señales de automatización
- reglas candidatas de detección
- limitaciones de la evidencia

## Precaución metodológica

Las fuentes centradas están diseñadas para resaltar el patrón del ataque.

Las ventanas completas y temporales contienen más background y pueden incluir ruido real de ISP.

Por tanto, las conclusiones deben diferenciar:

- observaciones directamente visibles
- interpretaciones técnicas
- hipótesis pendientes de validación programática
"""

    output_file.write_text(prompt, encoding="utf-8")
    return output_file


def copy_context_docs(package_dir: Path) -> list[Path]:
    context_dir = package_dir / "05_context"
    context_dir.mkdir(parents=True, exist_ok=True)

    copied = []

    for doc_name in CONTEXT_DOCS:
        source = DOCS_DIR / doc_name

        if source.exists():
            destination = context_dir / doc_name
            shutil.copy2(source, destination)
            copied.append(destination)

    return copied


# ============================================================
# README Y PACKAGE SUMMARY
# ============================================================

def save_package_summary(package_dir: Path, summaries: list[dict]) -> None:
    output_file = package_dir / "package_summary.csv"

    fieldnames = [
        "source_type",
        "input_file",
        "output_file",
        "rows_total",
        "attack_rows",
        "background_rows",
        "other_labels",
        "status",
    ]

    with open(output_file, "w", encoding="utf-8", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=fieldnames)
        writer.writeheader()

        for summary in summaries:
            row = summary.copy()
            row["other_labels"] = str(row.get("other_labels", {}))
            writer.writerow(row)


def create_package_readme(attack_label: str, package_dir: Path) -> None:
    output_file = package_dir / "README.md"

    content = f"""# Paquete NotebookLM: `{attack_label}`

Este paquete contiene fuentes preparadas para analizar el ataque `{attack_label}` con NotebookLM.

## Estructura

```text
01_centered_sources/
02_rows_2000_full/
03_time_10s_full/
04_time_60s_summaries/
05_context/
package_summary.csv
README.md
```

## Uso previsto

Este paquete debe subirse a un cuaderno específico de NotebookLM para el ataque `{attack_label}`.

El objetivo es proporcionar suficiente contexto real, pero de forma estructurada:

- las fuentes centradas ayudan a identificar el patrón del ataque
- las ventanas rows_2000 aportan contexto local
- las ventanas time_10s aportan contexto temporal corto
- los resúmenes time_60s aportan contexto amplio sin cargar demasiado ruido
- los documentos de contexto explican el modelo de comportamiento sintético

## Nota metodológica

Estas fuentes proceden de ventanas reales del dataset UGR'16.

No deben confundirse con los datasets sintéticos ilustrativos generados por LLM.

La validación empírica del modelo debe realizarse sobre datos reales, no sobre simulaciones generadas.
"""

    output_file.write_text(content, encoding="utf-8")


# ============================================================
# CONSTRUCCIÓN DEL PAQUETE
# ============================================================

def build_attack_package(attack_label: str) -> None:
    print(f"\n===== Construyendo paquete: {attack_label} =====")

    attack_dir = ATTACK_ANALYSIS_DIR / safe_name(attack_label)
    package_dir = OUTPUT_DIR / safe_name(attack_label)

    if not attack_dir.exists():
        print(f"[AVISO] No existe carpeta de ataque: {attack_dir}")
        return

    package_dir.mkdir(parents=True, exist_ok=True)

    all_summaries = []

    # 1. Fuentes centradas
    centered_summaries = build_centered_sources(
        attack_label=attack_label,
        attack_dir=attack_dir,
        package_dir=package_dir,
    )
    all_summaries.extend(centered_summaries)
    print(f"[OK] Fuentes centradas: {len(centered_summaries)}")

    # 2. Copiar rows_2000 completas
    if COPY_ROWS_2000_FULL:
        copied_rows = copy_csv_files(
            input_dir=attack_dir / "rows_2000",
            output_dir=package_dir / "02_rows_2000_full",
        )

        for file_path in copied_rows:
            rows = read_valid_rows(file_path)
            metrics = compute_window_metrics(rows, attack_label)

            all_summaries.append(
                {
                    "source_type": "rows_2000_full",
                    "input_file": str(file_path),
                    "output_file": str(file_path),
                    "rows_total": metrics["rows_total"],
                    "attack_rows": metrics["attack_rows"],
                    "background_rows": metrics["background_rows"],
                    "other_labels": metrics["other_labels"],
                    "status": "copied",
                }
            )

        print(f"[OK] rows_2000 copiadas: {len(copied_rows)}")

    # 3. Copiar time_10s completas
    if COPY_TIME_10S_FULL:
        copied_time_10s = copy_csv_files(
            input_dir=attack_dir / "time_10s",
            output_dir=package_dir / "03_time_10s_full",
        )

        for file_path in copied_time_10s:
            rows = read_valid_rows(file_path)
            metrics = compute_window_metrics(rows, attack_label)

            all_summaries.append(
                {
                    "source_type": "time_10s_full",
                    "input_file": str(file_path),
                    "output_file": str(file_path),
                    "rows_total": metrics["rows_total"],
                    "attack_rows": metrics["attack_rows"],
                    "background_rows": metrics["background_rows"],
                    "other_labels": metrics["other_labels"],
                    "status": "copied",
                }
            )

        print(f"[OK] time_10s copiadas: {len(copied_time_10s)}")

    # 4. Resúmenes time_60s
    time_60s_summaries = build_time_60s_summaries(
        attack_label=attack_label,
        attack_dir=attack_dir,
        package_dir=package_dir,
    )
    all_summaries.extend(time_60s_summaries)
    print(f"[OK] resúmenes time_60s: {len(time_60s_summaries)}")

    # 5. Contexto
    attack_context = create_attack_context_file(attack_label, package_dir)
    copied_context = copy_context_docs(package_dir)

    all_summaries.append(
        {
            "source_type": "context",
            "input_file": "",
            "output_file": str(attack_context),
            "rows_total": 0,
            "attack_rows": 0,
            "background_rows": 0,
            "other_labels": {},
            "status": "created",
        }
    )

    for context_file in copied_context:
        all_summaries.append(
            {
                "source_type": "context_doc",
                "input_file": str(DOCS_DIR / context_file.name),
                "output_file": str(context_file),
                "rows_total": 0,
                "attack_rows": 0,
                "background_rows": 0,
                "other_labels": {},
                "status": "copied",
            }
        )

    print(f"[OK] documentos de contexto: {1 + len(copied_context)}")

    create_package_readme(attack_label, package_dir)
    save_package_summary(package_dir, all_summaries)

    print(f"[OK] Paquete creado en: {package_dir}")
    print(f"[OK] Fuentes totales registradas: {len(all_summaries)}")


def main() -> None:
    print("\n==============================================")
    print(" BUILD NOTEBOOKLM ATTACK PACKAGES - UGR'16")
    print("==============================================\n")

    OUTPUT_DIR.mkdir(parents=True, exist_ok=True)

    for attack_label in ATTACK_LABELS:
        build_attack_package(attack_label)

    print("\n[OK] Todos los paquetes han sido generados.")
    print(f"Salida: {OUTPUT_DIR}")


if __name__ == "__main__":
    main()
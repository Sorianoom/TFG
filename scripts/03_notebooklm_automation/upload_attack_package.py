"""
Script: upload_attack_package.py

Sube a NotebookLM todas las fuentes de un paquete de ataque.

Uso:
python scripts/03_notebooklm_automation/upload_attack_package.py scan11

Requisitos:
- Haber iniciado sesión con notebooklm login.
- Haber seleccionado un notebook con notebooklm use <ID>,
  o pasar el notebook con --notebook <ID>.
"""

from __future__ import annotations

import argparse
import subprocess
from pathlib import Path


BASE_PACKAGE_DIR = Path("data/notebooklm_attack_packages")

UPLOAD_ORDER = [
    "05_context",
    "package_summary.csv",
    "README.md",
    "01_centered_sources",
    "02_rows_2000_full",
    "03_time_10s_full",
    "04_time_60s_summaries",
]


def collect_files(package_dir: Path) -> list[Path]:
    files: list[Path] = []

    for item in UPLOAD_ORDER:
        path = package_dir / item

        if not path.exists():
            continue

        if path.is_file():
            files.append(path)
            continue

        if path.is_dir():
            for ext in ("*.md", "*.csv", "*.txt"):
                files.extend(sorted(path.glob(ext)))

    return files


def run_command(command: list[str]) -> tuple[int, str, str]:
    process = subprocess.run(
        command,
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="ignore",
    )

    return process.returncode, process.stdout, process.stderr


def upload_file(file_path: Path, notebook_id: str | None = None) -> bool:
    command = [
        "notebooklm",
        "source",
        "add",
        str(file_path),
        "--title",
        file_path.name,
        "--timeout",
        "120",
    ]

    if notebook_id:
        command.extend(["--notebook", notebook_id])

    code, stdout, stderr = run_command(command)

    if code == 0:
        print(f"[OK] Subida: {file_path}")
        if stdout.strip():
            print(stdout.strip())
        return True

    print(f"[ERROR] No se pudo subir: {file_path}")
    if stdout.strip():
        print(stdout.strip())
    if stderr.strip():
        print(stderr.strip())

    return False


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("attack", help="Nombre del ataque. Ejemplo: scan11")
    parser.add_argument(
        "--notebook",
        help="ID del notebook. Si se omite, usa el notebook activo.",
        default=None,
    )
    parser.add_argument(
        "--dry-run",
        action="store_true",
        help="Muestra los archivos que se subirían, pero no los sube.",
    )

    args = parser.parse_args()

    package_dir = BASE_PACKAGE_DIR / args.attack

    if not package_dir.exists():
        print(f"[ERROR] No existe el paquete: {package_dir}")
        return

    files = collect_files(package_dir)

    if not files:
        print(f"[ERROR] No se han encontrado fuentes en: {package_dir}")
        return

    print("\n======================================")
    print(" UPLOAD ATTACK PACKAGE TO NOTEBOOKLM")
    print("======================================\n")

    print(f"Ataque: {args.attack}")
    print(f"Paquete: {package_dir}")
    print(f"Fuentes encontradas: {len(files)}")

    if args.notebook:
        print(f"Notebook destino: {args.notebook}")
    else:
        print("Notebook destino: notebook activo")

    print("\nFuentes:")

    for file_path in files:
        print(f"- {file_path}")

    if args.dry_run:
        print("\n[DRY-RUN] No se ha subido ningún archivo.")
        return

    print("\n===== SUBIENDO FUENTES =====\n")

    ok_count = 0
    error_count = 0

    for file_path in files:
        success = upload_file(file_path, args.notebook)

        if success:
            ok_count += 1
        else:
            error_count += 1

    print("\n===== RESUMEN =====\n")
    print(f"Subidas correctas: {ok_count}")
    print(f"Errores: {error_count}")

    if error_count == 0:
        print("\n[OK] Paquete subido correctamente.")
    else:
        print("\n[AVISO] Hubo errores durante la subida.")


if __name__ == "__main__":
    main()
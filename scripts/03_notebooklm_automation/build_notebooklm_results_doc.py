"""
Script: build_notebooklm_results_doc.py

Genera un documento consolidado con los resultados multifuente obtenidos
desde NotebookLM para cada ataque.

Entrada:
data/notebooklm_outputs/<attack>/
├── 01_analisis_estructural.md
├── 02_comparacion_background.md
└── 03_sintesis_validacion.md

Salida:
docs/17_resultados_notebooklm_multifuente.md

Uso:
python scripts/03_notebooklm_automation/build_notebooklm_results_doc.py
"""

from pathlib import Path
from datetime import datetime


OUTPUTS_DIR = Path("data/notebooklm_outputs")
DOCS_DIR = Path("Docs/NotebookLLM")
OUTPUT_FILE = DOCS_DIR / "17_resultados_notebooklm_multifuente.md"

ATTACKS = [
    "scan11",
    "scan44",
    "anomaly-sshscan",
    "dos",
    "anomaly-udpscan",
    "nerisbotnet",
    "anomaly-spam",
]

FILES = {
    "01_analisis_estructural.md": "Análisis estructural",
    "02_comparacion_background.md": "Comparación con background",
    "03_sintesis_validacion.md": "Síntesis para validación",
}


def read_file(path: Path) -> str:
    if not path.exists():
        return f"> [AVISO] No se encontró el archivo `{path}`.\n"

    return path.read_text(encoding="utf-8", errors="ignore").strip()


def clean_notebooklm_title(content: str) -> str:
    """
    Elimina encabezados repetidos generados por el script anterior si existen.
    """
    lines = content.splitlines()

    cleaned = []
    skip_next = False

    for line in lines:
        if line.startswith("# 01 ") or line.startswith("# 02 ") or line.startswith("# 03 "):
            continue

        if line.strip() == "## Ataque analizado":
            skip_next = True
            continue

        if skip_next:
            skip_next = False
            continue

        if line.strip() == "## Respuesta de NotebookLM":
            continue

        cleaned.append(line)

    return "\n".join(cleaned).strip()


def build_attack_section(attack: str) -> str:
    attack_dir = OUTPUTS_DIR / attack

    section = []
    section.append(f"# {attack}")
    section.append("")
    section.append(f"Directorio de resultados:")
    section.append("")
    section.append(f"```text")
    section.append(str(attack_dir))
    section.append(f"```")
    section.append("")

    for filename, title in FILES.items():
        path = attack_dir / filename
        content = read_file(path)
        content = clean_notebooklm_title(content)

        section.append(f"## {title}")
        section.append("")
        section.append(content)
        section.append("")
        section.append("---")
        section.append("")

    return "\n".join(section)


def main() -> None:
    DOCS_DIR.mkdir(parents=True, exist_ok=True)

    content = []

    content.append("# Resultados multifuente obtenidos con NotebookLM")
    content.append("")
    content.append("## 1. Objetivo")
    content.append("")
    content.append(
        "Este documento consolida los resultados obtenidos mediante NotebookLM "
        "tras cargar paquetes completos de fuentes por ataque. Cada paquete incluye "
        "fuentes centradas en trazas del ataque, ventanas completas por filas, "
        "ventanas temporales de 10 segundos, resúmenes de ventanas de 60 segundos "
        "y contexto metodológico."
    )
    content.append("")
    content.append(
        "El objetivo de esta fase no es generar código ni construir directamente "
        "un detector, sino extraer conocimiento técnico estructurado que pueda "
        "utilizarse posteriormente como especificación para la validación "
        "programática con Python."
    )
    content.append("")
    content.append("## 2. Metodología")
    content.append("")
    content.append("Para cada ataque se ejecutaron tres prompts principales:")
    content.append("")
    content.append("1. Análisis estructural completo.")
    content.append("2. Comparación con background y tráfico normal.")
    content.append("3. Síntesis técnica para validación posterior.")
    content.append("")
    content.append("Los ataques analizados fueron:")
    content.append("")
    for attack in ATTACKS:
        content.append(f"- `{attack}`")
    content.append("")
    content.append("## 3. Nota metodológica")
    content.append("")
    content.append(
        "Las respuestas de NotebookLM se consideran hipótesis técnicas y análisis "
        "asistidos por LLM. No deben aceptarse como validación empírica final. "
        "Las afirmaciones relevantes deben contrastarse posteriormente mediante "
        "scripts Python sobre las ventanas reales."
    )
    content.append("")
    content.append(
        "En particular, se debe diferenciar entre observaciones directamente "
        "presentes en las fuentes, interpretaciones técnicas razonables e hipótesis "
        "pendientes de validación."
    )
    content.append("")
    content.append("---")
    content.append("")

    for attack in ATTACKS:
        content.append(build_attack_section(attack))
        content.append("")

    content.append("# Conclusión general")
    content.append("")
    content.append(
        "La fase multifuente con NotebookLM permitió obtener una caracterización "
        "más amplia de cada ataque. Los resultados consolidados en este documento "
        "servirán como entrada para la siguiente fase del trabajo: transformar las "
        "hipótesis estructurales en reglas medibles mediante Python."
    )
    content.append("")
    content.append(f"Documento generado automáticamente el {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}.")
    content.append("")

    OUTPUT_FILE.write_text("\n".join(content), encoding="utf-8")

    print(f"[OK] Documento generado: {OUTPUT_FILE}")


if __name__ == "__main__":
    main()
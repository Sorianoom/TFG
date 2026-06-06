"""
Script: run_attack_prompts.py

Ejecuta automáticamente los prompts principales de análisis sobre un cuaderno NotebookLM.

Uso:
python scripts/03_notebooklm_automation/run_attack_prompts.py scan11

Opcional:
python scripts/03_notebooklm_automation/run_attack_prompts.py scan11 --notebook <ID>

Salida:
data/notebooklm_outputs/<attack>/
├── 01_analisis_estructural.md
├── 02_comparacion_background.md
├── 03_sintesis_validacion.md
└── raw/
"""

from __future__ import annotations

import argparse
import subprocess
import time
from pathlib import Path


OUTPUT_BASE_DIR = Path("data/notebooklm_outputs")


# ============================================================
# PROMPTS
# ============================================================

def prompt_analisis_estructural(attack: str) -> str:
    return f"""
Analiza todas las fuentes cargadas sobre {attack}.

Ten en cuenta que el cuaderno contiene varias escalas de información:

1. fuentes centradas en trazas del ataque
2. ventanas completas rows_2000
3. ventanas temporales time_10s
4. resúmenes estadísticos de ventanas time_60s
5. contexto metodológico del modelo de comportamiento sintético

No describas línea por línea ni fuente por fuente.

Quiero un análisis técnico profundo centrado en comportamiento de red.

Estructura la respuesta así:

1. Resumen ejecutivo del patrón observado.
2. Topología de comunicación:
   - número de IPs origen relevantes
   - número de IPs destino relevantes
   - si el patrón es 1→1, 1→muchos, muchos→1 o muchos→muchos
   - si existe concentración o dispersión

3. Actores principales:
   - IPs origen dominantes
   - IPs destino dominantes
   - papel probable de cada una
   - si el origen parece interno o externo respecto al ISP

4. Protocolos y puertos:
   - protocolo predominante
   - puertos origen relevantes
   - puertos destino relevantes
   - si hay puerto fijo, puerto secuencial o barrido
   - si el patrón es horizontal, vertical, híbrido o distribuido

5. Métricas de flujo:
   - duración
   - paquetes
   - bytes
   - varianza o uniformidad
   - flags TCP si aparecen
   - señales de baja entropía

6. Comportamiento temporal:
   - ráfagas
   - timestamps dominantes
   - simultaneidad
   - periodicidad
   - sincronización entre flujos o nodos

7. Señales de automatización:
   - qué elementos parecen generados por herramienta
   - dónde se localiza la automatización
   - origen, destino, puertos, servicio concreto o red distribuida

8. Variaciones entre fuentes:
   - qué se observa en fuentes centradas
   - qué se observa en rows_2000
   - qué se observa en time_10s
   - qué aportan los resúmenes time_60s
   - si el patrón cambia al ampliar la ventana

9. Invariantes robustos:
   - rasgos que aparecen de forma repetida
   - rasgos que se mantienen en varias ventanas
   - rasgos que podrían usarse como evidencia fuerte

10. Rasgos débiles o no constantes:
   - señales que aparecen solo en algunas ventanas
   - elementos que podrían depender del contexto
   - elementos que no deberían generalizarse sin validación

11. Interpretación técnica:
   - qué tipo de comportamiento representa
   - qué objetivo parece tener
   - por qué no debe interpretarse solo por la etiqueta

12. Limitaciones:
   - limitaciones de las fuentes cargadas
   - posibles sesgos por selección de ventanas
   - riesgo de confundir background con ataque
   - qué necesitaría validación posterior con código

13. Conclusión:
   - define el patrón final del ataque
   - indica si encaja en el modelo de comportamiento sintético actual
   - indica si modifica o amplía el modelo

Diferencia claramente entre:

- observaciones apoyadas por las fuentes
- interpretaciones técnicas razonables
- hipótesis que deberían validarse después con código

No propongas todavía código Python.
No diseñes todavía el detector.
Céntrate en extraer conocimiento técnico del ataque.
""".strip()


def prompt_comparacion_background(attack: str) -> str:
    return f"""
Compara el comportamiento observado en {attack} con el tráfico background presente en las ventanas cargadas y con el concepto de tráfico normal descrito en el contexto metodológico.

No describas línea por línea.

Quiero que identifiques:

1. Qué rasgos del ataque se diferencian claramente del background.
2. Qué rasgos podrían aparecer también en tráfico normal y por tanto no bastan por sí solos.
3. Qué métricas muestran mayor desviación:
   - IPs origen
   - IPs destino
   - puertos origen
   - puertos destino
   - protocolo
   - flags
   - duración
   - paquetes
   - bytes
   - timestamps

4. Cómo cambia la diversidad:
   - diversidad de IPs
   - diversidad de puertos
   - diversidad de protocolos
   - diversidad de tamaños
   - diversidad temporal

5. Si el ataque rompe la cicloestacionariedad o la diversidad normal de una red ISP.
6. Si el patrón podría confundirse con:
   - tráfico legítimo
   - automatización normal
   - DNS
   - HTTP/HTTPS
   - SSH legítimo
   - escaneo benigno
   - ruido de red
   - otra anomalía

7. Qué señales permiten separarlo del background de forma más fiable.
8. Qué señales serían demasiado débiles si se usan de forma aislada.
9. Qué tipo de ventana aporta mejor evidencia:
   - centered_sources
   - rows_2000
   - time_10s
   - time_60s summaries

10. Qué limitaciones tiene esta comparación.

La respuesta debe ser técnica y crítica.

No digas simplemente que es ataque porque tiene una etiqueta.
No propongas todavía código Python.
El objetivo es entender qué diferencia realmente este comportamiento del tráfico normal.
""".strip()


def prompt_sintesis_validacion(attack: str) -> str:
    return f"""
Genera una síntesis técnica final del ataque {attack} para usarla posteriormente como entrada en una fase de validación programática con Python.

No escribas código.

Quiero una salida estructurada y precisa con este formato:

1. Nombre del ataque analizado.
2. Categoría técnica propuesta.
3. Descripción breve del patrón.
4. Topología:
   - patrón 1→1, 1→muchos, muchos→1 o muchos→muchos
   - concentración o dispersión
   - rol de IPs origen y destino

5. Métricas principales observadas:
   - protocolo
   - puertos origen
   - puertos destino
   - duración
   - paquetes
   - bytes
   - flags
   - timestamps

6. Invariantes fuertes:
   - lista de rasgos que aparecen de forma consistente
   - explica por qué son robustos

7. Invariantes secundarios:
   - rasgos útiles pero no suficientes por sí solos

8. Señales de automatización:
   - dónde aparece la automatización
   - qué estructura parece generada por herramienta

9. Diferencias con background:
   - qué lo separa del tráfico normal
   - qué señales reducen riesgo de falso positivo

10. Posibles confusiones:
   - con qué tráfico legítimo o anomalías podría confundirse
   - cómo evitar sobreinterpretar

11. Evidencia suficiente:
   - qué afirmaciones están bien apoyadas por las fuentes

12. Evidencia insuficiente:
   - qué afirmaciones no deberían darse por definitivas

13. Requisitos para validación posterior:
   - qué debería medir un script Python
   - qué agregaciones serían necesarias
   - qué aspectos necesitan umbrales
   - qué aspectos requieren análisis temporal

14. Encaje en el modelo de comportamiento sintético:
   - si encaja en una categoría existente
   - si requiere categoría nueva
   - si modifica alguna categoría previa

15. Conclusión final:
   - una definición técnica breve y defendible del ataque

Importante:
No escribas código Python.
No inventes valores que no estén apoyados por las fuentes.
Diferencia observación, interpretación e hipótesis.
La respuesta debe servir como especificación técnica para que otra herramienta genere posteriormente reglas de validación.
""".strip()


PROMPTS = [
    {
        "name": "01_analisis_estructural",
        "builder": prompt_analisis_estructural,
    },
    {
        "name": "02_comparacion_background",
        "builder": prompt_comparacion_background,
    },
    {
        "name": "03_sintesis_validacion",
        "builder": prompt_sintesis_validacion,
    },
]


# ============================================================
# NOTEBOOKLM CLI
# ============================================================

def run_notebooklm_ask(prompt: str, notebook_id: str | None = None) -> tuple[int, str, str]:
    command = ["notebooklm", "ask", prompt]

    if notebook_id:
        command.extend(["--notebook", notebook_id])

    process = subprocess.run(
        command,
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="ignore",
    )

    return process.returncode, process.stdout, process.stderr


def extract_answer(raw_output: str) -> str:
    """
    Limpia parcialmente la salida de notebooklm ask.

    La CLI suele devolver:
    Continuing conversation...
    Answer:
    ...
    Resumed conversation...
    """

    text = raw_output.strip()

    if "Answer:" in text:
        text = text.split("Answer:", 1)[1].strip()

    if "Resumed conversation:" in text:
        text = text.split("Resumed conversation:", 1)[0].strip()

    return text.strip()


def save_text(path: Path, content: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(content, encoding="utf-8")


# ============================================================
# MAIN
# ============================================================

def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("attack", help="Nombre del ataque. Ejemplo: scan11")
    parser.add_argument(
        "--notebook",
        default=None,
        help="ID del notebook. Si se omite, usa el notebook activo.",
    )
    parser.add_argument(
        "--delay",
        type=int,
        default=10,
        help="Segundos de espera entre prompts.",
    )

    args = parser.parse_args()

    attack = args.attack

    output_dir = OUTPUT_BASE_DIR / attack
    raw_dir = output_dir / "raw"

    output_dir.mkdir(parents=True, exist_ok=True)
    raw_dir.mkdir(parents=True, exist_ok=True)

    print("\n===================================")
    print(" RUN NOTEBOOKLM ATTACK PROMPTS")
    print("===================================\n")

    print(f"Ataque: {attack}")

    if args.notebook:
        print(f"Notebook: {args.notebook}")
    else:
        print("Notebook: activo")

    for idx, prompt_info in enumerate(PROMPTS, start=1):
        name = prompt_info["name"]
        prompt = prompt_info["builder"](attack)

        print(f"\n===== Ejecutando prompt {idx}/3: {name} =====")

        prompt_file = raw_dir / f"{name}_prompt.txt"
        raw_output_file = raw_dir / f"{name}_raw_output.txt"
        clean_output_file = output_dir / f"{name}.md"

        save_text(prompt_file, prompt)

        code, stdout, stderr = run_notebooklm_ask(prompt, args.notebook)

        save_text(raw_output_file, stdout + "\n\nSTDERR:\n" + stderr)

        if code != 0:
            print(f"[ERROR] Falló el prompt: {name}")
            print(stderr.strip())
            continue

        answer = extract_answer(stdout)

        md_content = f"""# {name.replace("_", " ").title()}

## Ataque analizado

`{attack}`

## Respuesta de NotebookLM

{answer}
"""

        save_text(clean_output_file, md_content)

        print(f"[OK] Respuesta guardada en: {clean_output_file}")

        if idx < len(PROMPTS):
            print(f"[INFO] Esperando {args.delay} segundos antes del siguiente prompt...")
            time.sleep(args.delay)

    print("\n[OK] Prompts finalizados.")
    print(f"Salida: {output_dir}")


if __name__ == "__main__":
    main()
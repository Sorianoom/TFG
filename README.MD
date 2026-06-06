# TFG - Análisis explicativo de tráfico NetFlow con LLMs

## Descripción

Este proyecto corresponde al desarrollo de un Trabajo de Fin de Grado centrado en el análisis explicativo de anomalías en tráfico NetFlow mediante modelos de lenguaje grandes (LLMs).

El trabajo utiliza el dataset UGR'16, un conjunto de tráfico de red capturado en un ISP real, con tráfico normal, ataques sintéticos y anomalías reales. El objetivo principal no es construir un IDS completo ni entrenar un modelo de Machine Learning propio, sino estudiar cómo los LLMs pueden ayudar a interpretar patrones de tráfico, generar hipótesis técnicas y apoyar la validación programática de dichas hipótesis.

La metodología seguida combina:

* preparación y limpieza de datos NetFlow
* extracción de perfiles normales y ventanas de ataque
* análisis asistido por LLMs mediante NotebookLM
* generación de hipótesis estructurales por ataque
* formalización de un modelo de comportamiento sintético
* implementación de detectores heurísticos en Python
* validación programática sobre ventanas reales

---

## Objetivo del proyecto

El objetivo general del proyecto es estudiar el uso de modelos de lenguaje grandes como apoyo al análisis explicativo de anomalías en tráfico NetFlow.

Los objetivos específicos son:

1. Estudiar la estructura del dataset UGR'16.
2. Limpiar y preparar un subconjunto de gran tamaño del dataset.
3. Extraer tráfico malicioso y perfiles normales de calibración.
4. Generar ventanas temporales y ventanas centradas por ataque.
5. Analizar el tráfico normal y anómalo con ayuda de LLMs.
6. Identificar invariantes estructurales en distintos ataques.
7. Formalizar un modelo de comportamiento sintético basado en la localización de la automatización.
8. Validar programáticamente las hipótesis generadas mediante detectores heurísticos.
9. Documentar las ventajas, limitaciones y posibilidades del uso de LLMs en este contexto.

---

## Dataset utilizado

El trabajo se basa en el dataset UGR'16.

En el proyecto se ha trabajado principalmente con la primera semana de agosto, procesando un fichero de aproximadamente 80 GB.

Resultado principal de limpieza:

```text
data/clean/august_week1_clean.csv
```

El fichero limpio contiene aproximadamente:

```text
100,155,976 filas válidas
```

Distribución aproximada de etiquetas principales:

| Etiqueta        |      Filas |
| --------------- | ---------: |
| background      | 98,170,672 |
| anomaly-udpscan |    989,872 |
| dos             |    391,599 |
| blacklist       |    225,525 |
| scan44          |    190,584 |
| nerisbotnet     |    151,525 |
| scan11          |     36,144 |
| anomaly-spam    |         47 |
| anomaly-sshscan |          8 |

---

## Ataques analizados

Durante el trabajo se han estudiado las siguientes familias de tráfico:

| Etiqueta              | Interpretación en el proyecto                         |
| --------------------- | ----------------------------------------------------- |
| `dos`                 | Distributed TCP Flood / TCP DoS                       |
| `anomaly-udpscan`     | UDP Hybrid Scan / UDP Low-Entropy Scan                |
| `nerisbotnet`         | Botnet multivector / Distributed C2                   |
| `scan11`              | Single-Source Vertical Scan                           |
| `scan44`              | Distributed Vertical Scan                             |
| `anomaly-sshscan`     | Low-and-Slow SSH Horizontal Scan                      |
| `anomaly-spam`        | SMTP Spam Burst / caso exploratorio de baja evidencia |
| `background` / `none` | Tráfico normal o ruido de fondo                       |

La etiqueta `blacklist` no se utiliza como criterio principal de detección, ya que el enfoque del proyecto se basa en comportamiento y no en listas negras.

---

## Estructura del proyecto

```text
data/
├── raw/
│   └── ficheros originales del dataset
│
├── clean/
│   ├── august_week1_clean.csv
│   ├── malicious_only.csv
│   ├── background_sample.csv
│   ├── balanced_50_50/
│   ├── balanced_60_40/
│   └── balanced_70_30/
│
├── attack_analysis/
│   ├── dos/
│   ├── anomaly-udpscan/
│   ├── nerisbotnet/
│   ├── scan11/
│   ├── scan44/
│   ├── anomaly-sshscan/
│   ├── anomaly-spam/
│   ├── normal/
│   ├── behavior_detection_results.csv
│   ├── behavior_detection_results_extended.csv
│   ├── flow_level_detection_results_v3.csv
│   └── flow_level_detection_summary_v3.csv
│
├── notebooklm_attack_packages/
│   ├── dos/
│   ├── anomaly-udpscan/
│   ├── nerisbotnet/
│   ├── scan11/
│   ├── scan44/
│   ├── anomaly-sshscan/
│   └── anomaly-spam/
│
└── notebooklm_outputs/
    ├── dos/
    ├── anomaly-udpscan/
    ├── nerisbotnet/
    ├── scan11/
    ├── scan44/
    ├── anomaly-sshscan/
    └── anomaly-spam/
```

```text
scripts/
├── pipeline/
│   ├── clean_large_csv.py
│   ├── count_labels.py
│   ├── extract_malicious.py
│   └── merge/otros scripts de preparación
│
├── balancing/
│   ├── balance_50_50.py
│   ├── balance_60_40.py
│   └── balance_70_30.py
│
├── samples/
│   └── scripts para generación de muestras
│
├── utils/
│   └── utilidades auxiliares
│
├── experiments/
│   └── pruebas experimentales
│
├── 02_attack_analysis/
│   ├── extract_multiple_time_windows.py
│   ├── extract_attack_windows_unified.py
│   ├── detect_synthetic_behavior.py
│   └── detect_synthetic_behavior_extended.py
│
└── 03_notebooklm_automation/
    ├── build_notebooklm_attack_packages.py
    ├── upload_attack_package.py
    ├── run_attack_prompts.py
    └── build_notebooklm_results_doc.py
```

```text
Docs/NotebookLLM/
├── 00_indice_documentacion.md
├── 01_contexto_y_objetivo.md
├── 02_dataset_ugr16.md
├── 03_notas_reunion_profesor.md
├── 04_metodologia_uso_llm.md
├── 05_prompts_llm.md
├── 06_analisis_trafico_normal.md
├── 07_analisis_dos.md
├── 08_analisis_udp_scan.md
├── 09_analisis_nerisbotnet.md
├── 10_modelo_comportamiento_sintetico.md
├── 11_validacion_modelo_comportamiento.md
├── 12_validacion_hipotesis_llm.md
├── 13_limitaciones_y_trabajo_futuro.md
├── 14_analisis_scan11.md
├── 15_analisis_scan44.md
├── 16_analisis_anomaly_sshscan.md
├── 17_resultados_notebooklm_multifuente.md
├── 18_especificacion_detector_claude_code.md
├── 19_validacion_detector_ampliado.md
├── 20_estado_actual_proyecto.md
├── 21_revision_generalizacion_detector.md
├── 22_clasificacion_contextual_por_traza.md
├── 23_analisis_errores_clasificador_contextual.md
├── 24_validacion_clasificador_contextual_v2.md
├── 26_validacion_clasificador_contextual_v3.md
├── 27_recomendacion_version_clasificador.md
├── 99_borrador_memoria.md
├── contexto_modelo_actual.md
└── diario_decisiones_tecnicas.md
```

---

## Flujo de trabajo

El flujo general del proyecto es:

```text
Dataset UGR'16
→ limpieza y preparación
→ extracción de tráfico malicioso y background
→ generación de ventanas de ataque
→ análisis asistido por LLM
→ generación de hipótesis técnicas
→ formalización del modelo de comportamiento
→ validación heurística con Python
→ documentación de resultados
```

En la fase ampliada, el flujo seguido fue:

```text
Ventanas por ataque
→ paquetes multifuente para NotebookLM
→ prompts automatizados
→ respuestas por ataque
→ consolidación de resultados
→ especificación para Claude Code
→ detector heurístico ampliado
→ validación sobre 194 ventanas
```

---

## Scripts principales

### Limpieza y preparación

| Script                                  | Función                                  |
| --------------------------------------- | ---------------------------------------- |
| `scripts/pipeline/clean_large_csv.py`   | Limpieza del CSV original de gran tamaño |
| `scripts/pipeline/count_labels.py`      | Conteo de etiquetas                      |
| `scripts/pipeline/extract_malicious.py` | Extracción de tráfico malicioso          |
| `scripts/balancing/`                    | Generación de datasets balanceados       |

### Análisis de ataques

| Script                                                             | Función                                                |
| ------------------------------------------------------------------ | ------------------------------------------------------ |
| `scripts/02_attack_analysis/extract_multiple_time_windows.py`      | Extracción inicial de ventanas por ataque              |
| `scripts/02_attack_analysis/extract_attack_windows_unified.py`     | Extractor unificado de ventanas para todos los ataques |
| `scripts/02_attack_analysis/detect_synthetic_behavior.py`          | Detector heurístico inicial                            |
| `scripts/02_attack_analysis/detect_synthetic_behavior_extended.py` | Detector heurístico ampliado                           |
| `scripts/02_attack_analysis/detect_attack_flows_contextual_v3.py`  | Clasificador contextual por traza (v3, principal)      |

### Automatización de NotebookLM

| Script                                                                 | Función                                       |
| ---------------------------------------------------------------------- | --------------------------------------------- |
| `scripts/03_notebooklm_automation/build_notebooklm_attack_packages.py` | Generación de paquetes multifuente por ataque |
| `scripts/03_notebooklm_automation/upload_attack_package.py`            | Subida de paquetes a NotebookLM               |
| `scripts/03_notebooklm_automation/run_attack_prompts.py`               | Ejecución automatizada de prompts por ataque  |
| `scripts/03_notebooklm_automation/build_notebooklm_results_doc.py`     | Consolidación de resultados NotebookLM        |

---

## Modelo de comportamiento sintético

El proyecto organiza los ataques no solo por su etiqueta, sino por la localización de la automatización.

| Ataque            | Categoría                                   | Localización de la automatización     |
| ----------------- | ------------------------------------------- | ------------------------------------- |
| `dos`             | Distributed TCP Flood / TCP DoS             | Origen y concentración hacia servicio |
| `anomaly-udpscan` | UDP Hybrid Scan / UDP Low-Entropy Scan      | Espacio de destino/red                |
| `scan11`          | Single-Source Vertical Scan                 | Servicios del host objetivo           |
| `scan44`          | Distributed Vertical Scan                   | Red coordinada + servicios destino    |
| `anomaly-sshscan` | Low-and-Slow SSH Horizontal Scan            | Selección de IPs destino hacia SSH    |
| `nerisbotnet`     | Botnet multivector / Distributed C2         | Red distribuida/C2                    |
| `anomaly-spam`    | SMTP Spam Burst / Low-Entropy SMTP Campaign | Campaña SMTP de baja evidencia        |

---

## Validación experimental

### Detector inicial

El detector inicial permitió validar:

| Ataque      | Resultado                    |
| ----------- | ---------------------------- |
| DoS         | 3/3 ventanas                 |
| UDP Scan    | 3/3 ventanas                 |
| NerisBotnet | 1/3 ventanas                 |
| Normal      | 0/3 clasificadas como ataque |

### Detector ampliado

El detector ampliado se ejecutó sobre:

```text
194 ventanas reales
```

Archivo generado:

```text
data/attack_analysis/behavior_detection_results_extended.csv
```

Resultados aproximados por familia:

| Ataque esperado   | Aciertos | Total | Tasa aproximada |
| ----------------- | -------: | ----: | --------------: |
| `scan11`          |       24 |    28 |           85.7% |
| `anomaly-udpscan` |       22 |    28 |           78.6% |
| `scan44`          |       21 |    28 |           75.0% |
| `dos`             |       14 |    29 |           48.3% |
| `nerisbotnet`     |       13 |    28 |           46.4% |
| `anomaly-sshscan` |        5 |    24 |           20.8% |
| `anomaly-spam`    |        0 |    26 |            0.0% |

Los resultados muestran que el enfoque funciona mejor en patrones estructurados de baja entropía, especialmente escaneos. Los ataques distribuidos, low-and-slow o con baja evidencia requieren mayor contexto y deben interpretarse con cautela.

### Clasificación contextual por traza (v3)

Para clasificar **trazas concretas** (no solo ventanas) se desarrolló un clasificador contextual por traza con clasificación en **dos niveles**:

1. **ataque / background** (detección binaria)
2. **familia y subtipo** de comportamiento

La versión adoptada como principal es la **v3** (contexto local + pase global/temporal): recall binario de ataque ≈ 0,991 y precisión ≈ 0,930, resuelve la separación `scan11`/`scan44` y eleva `udp_scan` a recall ≈ 1,00.

Salida principal:

```text
data/attack_analysis/flow_level_detection_results_v3.csv
data/attack_analysis/flow_level_detection_summary_v3.csv
```

La v2 se conserva como referencia más conservadora en precisión binaria. El detalle de la comparación entre versiones está en `Docs/NotebookLLM/27_recomendacion_version_clasificador.md`.

---

## Estado actual

Fases completadas:

* limpieza del dataset de agosto semana 1
* extracción de tráfico malicioso
* generación de datasets balanceados
* extracción de perfiles normales
* extracción de ventanas de ataque
* extractor unificado de ventanas
* análisis inicial con NotebookLM
* análisis multifuente por ataque
* automatización parcial de NotebookLM mediante `notebooklm-py`
* consolidación de resultados NotebookLM
* especificación técnica para Claude Code
* implementación del detector heurístico ampliado
* validación sobre 194 ventanas
* clasificación contextual por traza (v1, v2 y v3); adopción de v3 como versión principal
* actualización de la documentación técnica
* actualización del borrador de memoria

---

## Limitaciones

Las principales limitaciones del proyecto son:

* análisis sobre ventanas previamente extraídas
* no ejecución sobre el dataset completo
* uso de reglas heurísticas
* umbrales empíricos
* ausencia de IDS en tiempo real
* no se entrena un modelo de Machine Learning propio
* dependencia del diseño de prompts
* necesidad de validar cualquier hipótesis generada por LLM
* dificultad para detectar patrones distribuidos o low-and-slow
* baja evidencia en `anomaly-spam`
* presencia de ruido automatizado en tráfico background real

---

## Trabajo futuro

Como trabajo futuro se plantea:

* aplicar el detector ampliado a más segmentos del dataset
* estudiar distintas configuraciones de umbrales
* mejorar la detección de botnets mediante correlación temporal más amplia
* analizar patrones low-and-slow con ventanas más largas
* buscar más evidencia para `anomaly-spam`
* comparar distintos LLMs
* automatizar más fases del pipeline
* desarrollar visualizaciones interactivas de los patrones detectados
* transformar el borrador técnico en memoria académica final

---

## Nota metodológica

Las respuestas generadas por LLMs no se consideran evidencia empírica por sí mismas.

En este proyecto, los LLMs se utilizan para:

* interpretar tráfico
* generar hipótesis
* proponer categorías de comportamiento
* apoyar la explicación técnica
* preparar especificaciones para validación programática

La validación se realiza posteriormente mediante scripts Python sobre ventanas reales del dataset.

Por tanto, el flujo metodológico defendido es:

```text
Datos NetFlow → Ventanas temporales → LLM → Hipótesis → Código Python → Validación → Documentación
```

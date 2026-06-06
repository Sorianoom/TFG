# Estado actual del proyecto

## 1. Fases completadas

- Limpieza del dataset UGR'16.
- Conteo y análisis de etiquetas.
- Extracción de tráfico malicioso.
- Generación de datasets balanceados.
- Extracción de perfiles normales.
- Extracción de ventanas por ataque.
- Creación del extractor unificado.
- Generación de paquetes multifuente por ataque.
- Automatización parcial de NotebookLM.
- Ejecución de prompts multifuente.
- Consolidación de resultados.
- Especificación técnica para Claude Code.
- Implementación del detector heurístico ampliado.
- Validación sobre 194 ventanas.
- Revisión de generalización del detector ampliado.
- Implementación del clasificador contextual por traza v1.
- Implementación del clasificador contextual jerárquico v2.
- Implementación del clasificador contextual v3 con pase global/temporal.
- Comparación entre versiones v1, v2 y v3.
- Selección de v3 como versión principal del clasificador contextual por traza.
- Experimento v4 (variante experimental) para mejorar familias débiles; no sustituye a la v3.
- Evaluación de generalización de la v3 sobre datos nuevos (`august.week2`).
- Actualización de documentación técnica.
- Actualización del README.
- Actualización del borrador de memoria.

## 2. Archivos principales

- `README.md`
- `Docs/NotebookLLM/00_indice_documentacion.md`
- `Docs/NotebookLLM/17_resultados_notebooklm_multifuente.md`
- `Docs/NotebookLLM/18_especificacion_detector_claude_code.md`
- `Docs/NotebookLLM/19_validacion_detector_ampliado.md`
- `Docs/NotebookLLM/99_borrador_memoria.md`
- `scripts/02_attack_analysis/detect_synthetic_behavior_extended.py`
- `data/attack_analysis/behavior_detection_results_extended.csv`
- `scripts/02_attack_analysis/detect_attack_flows_contextual.py` (clasificador por traza v1)
- `scripts/02_attack_analysis/detect_attack_flows_contextual_v2.py` (jerárquico v2)
- `scripts/02_attack_analysis/detect_attack_flows_contextual_v3.py` (v3, versión principal)
- `data/attack_analysis/flow_level_detection_results_v3.csv`
- `data/attack_analysis/flow_level_detection_summary_v3.csv`
- `Docs/NotebookLLM/27_recomendacion_version_clasificador.md`
- `scripts/02_attack_analysis/detect_attack_flows_contextual_v4_experimental.py` (variante EXPERIMENTAL, no principal)
- `Docs/NotebookLLM/30_experimento_mejora_familias_debiles_v4.md` (experimento de familias débiles)
- `scripts/04_generalization/prepare_generalization_dataset.py` (preparación de ventanas de generalización)
- `scripts/04_generalization/run_v3_on_generalization.py` (ejecuta la v3 sin modificarla sobre datos nuevos)
- `data/generalization/results/generalization_results_v3_august_week2.csv`
- `data/generalization/summaries/generalization_summary_v3_august_week2.csv`
- `Docs/NotebookLLM/28_evaluacion_generalizacion_v3.md`

## 3. Resultados principales

| Ataque | Estado |
|---|---|
| scan11 | Validación robusta |
| scan44 | Validación robusta |
| anomaly-udpscan | Validación robusta |
| dos | Validación parcial |
| nerisbotnet | Validación parcial |
| anomaly-sshscan | Validación limitada |
| anomaly-spam | Caso exploratorio |

### Clasificador contextual por traza (v3, versión principal)

- La v3 mantiene un recall binario de ataque de **0,991**.
- La v3 obtiene una precisión binaria de ataque de **0,930**.
- La v3 mejora el recall de `scan44` de **0,015 a 0,796**.
- La v3 mejora la precisión de `scan11` de **0,194 a 0,763**.
- La v3 mejora `udp_scan` hasta un recall **aproximado de 1,00**.
- La v3 reduce los falsos positivos de `sshscan` de **8.248 a 60**.
- La v3 reduce `unknown_attack` de **345.065 a 118.264 trazas**.
- `coordinated_botnet` no-C2, `anomaly-sshscan` y `anomaly-spam` quedan como limitaciones o señales exploratorias de baja confianza.

### Experimento v4 (variante experimental, NO sustituye a la v3)

Se exploró una variante experimental (`detect_attack_flows_contextual_v4_experimental.py`) para
intentar mejorar las familias débiles, sin tocar la lógica de scan11/scan44/udp_scan/tcp_flood.

La v4 **no mejora la detección binaria ni el recall de las familias débiles**. `anomaly-sshscan`
empeora al aumentar falsos positivos (de 60 a 128 predichas) sin obtener aciertos, y
`anomaly-spam` permanece sin mejora (0 aciertos). La única mejora defendible aparece en
`nerisbotnet`: separar `coordinated_botnet_high_confidence` y `coordinated_botnet_low_confidence`
permite aislar un subconjunto de alta confianza con **precisión 0,757** frente al **0,269**
combinado de la v3. Sin embargo, el **recall sigue siendo 0,044**, por lo que no detecta más
casos, solo separa mejor la evidencia fuerte del ruido.

La detección binaria (precisión 0,930 / recall 0,991) y las familias estructuradas (scan11,
scan44, udp_scan, dos) quedan **idénticas** a la v3.

Tras este experimento, se mantiene la v3 como versión principal del clasificador contextual. La
v4 queda documentada como variante experimental y como posible línea de trabajo futuro para
refinar familias de baja evidencia mediante niveles de confianza.

### Evaluación de generalización de la v3 (august.week2, datos nuevos)

Se evaluó la v3 **sin reajustar reglas ni umbrales** sobre `august.week2` (838 M filas
válidas; semana distinta no usada para formular reglas), mediante ventanas contiguas que
preservan la localidad temporal.

- **El núcleo fuerte generaliza**: recall binario **0,993 excluyendo `anomaly-spam`** (≈ 0,991
  de week1); `vertical_scan` recall **0,853** (≈ 0,847); `dos` recall **0,489** (≈ 0,488).
- **El recall binario agregado baja a 0,747** porque week2 está **dominada por `anomaly-spam`**
  (36,8 M filas; el 98 % de los falsos negativos), una debilidad ya documentada, ahora a escala.
- **`anomaly-udpscan` no aparece en week2** (0 filas) → no evaluable.
- **`nerisbotnet`, `anomaly-sshscan` y `anomaly-spam` siguen siendo débiles** en datos nuevos.
- La distinción de subtipo **scan11/scan44 es menos estable entre semanas** (scan11 absorbe más
  a scan44), aunque la familia `vertical_scan` se mantiene.

Conclusión: la v3 generaliza de forma razonable en su núcleo (escaneos estructurados) sin
sobreajuste; se confirma como clasificador principal y se delimitan con honestidad sus límites.

Segunda prueba — **april.week2** (564 M filas válidas): contiene **solo** familias débiles
(`anomaly-sshscan` 4,5 M y `anomaly-spam` 380 k) y **ninguna** del núcleo fuerte; `anomaly-udpscan`
tampoco aparece. La v3 detecta **~0** ataques (recall binario 0,0): incluso con 29.298 trazas
sshscan en las ventanas, el patrón *low-and-slow* queda diluido localmente y no se detecta. Ambas
pruebas son complementarias: august.week2 confirma que el núcleo generaliza; april.week2 confirma
que sshscan y spam siguen sin detectarse **a escala**. `udp_scan` sigue **sin evaluar** (ausente
en las dos semanas nuevas).

Se realizó además una auditoría de etiquetas sobre los datasets disponibles
(`data/generalization/summaries/raw_dataset_label_audit.csv`), confirmando que `anomaly-udpscan`
solo aparece en `august.week1`, por lo que su generalización externa queda como trabajo futuro.

## 4. Pendiente inmediato

- Revisar el borrador de memoria.
- Convertir el borrador técnico en memoria académica final.
- Preparar tablas y figuras definitivas.
- Revisar limitaciones y trabajo futuro.
- Decidir si se ajusta o no el detector ampliado.
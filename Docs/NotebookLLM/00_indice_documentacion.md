# Índice de documentación del proyecto

Este directorio contiene la documentación técnica generada durante el desarrollo del TFG.

El objetivo de esta documentación es mantener trazabilidad entre:

* el dataset utilizado
* las ventanas extraídas
* los prompts enviados a LLMs
* las respuestas obtenidas
* las hipótesis generadas
* la validación programática
* la redacción final de la memoria

---

## 1. Documentos principales

| Archivo                                  | Contenido                                                            |
| ---------------------------------------- | -------------------------------------------------------------------- |
| `01_contexto_y_objetivo.md`              | Contexto general del TFG, problema, objetivos y alcance              |
| `02_dataset_ugr16.md`                    | Descripción del dataset UGR'16 y datos utilizados                    |
| `03_notas_reunion_profesor.md`           | Interpretación de las indicaciones recibidas en reunión              |
| `04_metodologia_uso_llm.md`              | Metodología de uso de LLMs como apoyo al análisis                    |
| `05_prompts_llm.md`                      | Banco de prompts utilizados con NotebookLM/LLMs                      |
| `06_analisis_trafico_normal.md`          | Análisis de perfiles normales de calibración                         |
| `07_analisis_dos.md`                     | Análisis inicial del ataque DoS                                      |
| `08_analisis_udp_scan.md`                | Análisis inicial del ataque UDP Scan                                 |
| `09_analisis_nerisbotnet.md`             | Análisis inicial de NerisBotnet                                      |
| `10_modelo_comportamiento_sintetico.md`  | Modelo unificado de comportamiento sintético                         |
| `11_validacion_modelo_comportamiento.md` | Validación inicial del modelo mediante detector heurístico           |
| `12_validacion_hipotesis_llm.md`         | Contraste entre hipótesis generadas por LLM y evidencia programática |
| `13_limitaciones_y_trabajo_futuro.md`    | Limitaciones actuales y siguientes pasos                             |
| `99_borrador_memoria.md`                 | Borrador estructurado de la memoria final                            |

---

## 2. Análisis específicos por ataque

Estos documentos recogen análisis individuales de ataques concretos realizados durante la ampliación del modelo de comportamiento.

| Archivo                          | Contenido                                              |
| -------------------------------- | ------------------------------------------------------ |
| `14_analisis_scan11.md`          | Análisis de `scan11` como Single-Source Vertical Scan  |
| `15_analisis_scan44.md`          | Análisis de `scan44` como Distributed Vertical Scan    |
| `16_analisis_anomaly_sshscan.md` | Análisis de `anomaly-sshscan` como SSH Horizontal Scan |

---

## 3. Fase NotebookLM multifuente y detector ampliado

Estos documentos corresponden a la fase más reciente del proyecto, donde se generaron paquetes completos por ataque, se ejecutaron prompts multifuente con NotebookLM y se implementó una validación ampliada con Claude Code.

| Archivo                                     | Contenido                                                                                         |
| ------------------------------------------- | ------------------------------------------------------------------------------------------------- |
| `17_resultados_notebooklm_multifuente.md`   | Resultados consolidados de los análisis multifuente realizados con NotebookLM por ataque          |
| `18_especificacion_detector_claude_code.md` | Especificación técnica utilizada para implementar el detector heurístico ampliado con Claude Code |
| `19_validacion_detector_ampliado.md`        | Validación experimental del detector heurístico ampliado sobre ventanas reales del dataset        |

---

## 4. Fase de clasificación contextual por traza

Estos documentos corresponden a la fase de clasificación de **trazas concretas** (no solo ventanas), que culmina con el clasificador contextual v3 adoptado como referencia principal.

| Archivo | Contenido |
| --- | --- |
| `21_revision_generalizacion_detector.md` | Revisión de generalización del detector ampliado (uso de IPs, etiquetas y umbrales) |
| `22_clasificacion_contextual_por_traza.md` | Clasificador contextual por traza v1 (contexto local ±30 filas) |
| `23_analisis_errores_clasificador_contextual.md` | Análisis de errores del clasificador v1 (falsos positivos y negativos por familia) |
| `24_validacion_clasificador_contextual_v2.md` | Validación del clasificador jerárquico v2 (binario → familia → subtipo) |
| `26_validacion_clasificador_contextual_v3.md` | Validación del clasificador v3 con pase global/temporal |
| `27_recomendacion_version_clasificador.md` | Comparación de versiones y elección de v3 como clasificador principal |
| `28_evaluacion_generalizacion_v3.md` | Evaluación de generalización temporal de la v3 sobre datos nuevos (`august.week2` y `april.week2`) |
| `30_experimento_mejora_familias_debiles_v4.md` | Experimento v4 (variante experimental) para familias débiles; **no sustituye a la v3** |
| `32_experimento_contexto_largo_sshscan_spam_april.md` | Experimento de contexto largo para sshscan/spam en april.week2 (mejora sshscan a F1 0,951; experimental) |
| `33_validacion_clasificador_contextual_v5_integrated.md` | Validación de la **v5 integrated** (v3 + pase SSH fan-out): **versión principal recomendada**; v3 = versión base estable |

(El número 25 no se utiliza. El documento 29 recoge la comparación con ML clásico; el 31 no se utiliza.)

---

## 5. Documentos auxiliares

| Archivo                         | Contenido                                                         |
| ------------------------------- | ----------------------------------------------------------------- |
| `diario_decisiones_tecnicas.md` | Registro de decisiones técnicas tomadas durante el proyecto       |
| `contexto_modelo_actual.md`     | Resumen del modelo de comportamiento actual por familia de ataque |

---

## 6. Estructura del enfoque

El proyecto sigue el siguiente flujo:

1. Estudio del dataset UGR'16.
2. Limpieza y preparación de datos NetFlow.
3. Extracción de perfiles normales y ventanas de ataque.
4. Análisis asistido por LLM.
5. Comparación entre tráfico normal y tráfico anómalo.
6. Formalización de patrones de comportamiento.
7. Generación de hipótesis técnicas.
8. Validación programática mediante scripts Python.
9. Ampliación del análisis mediante paquetes multifuente por ataque.
10. Ejecución automatizada de prompts en NotebookLM.
11. Implementación de un detector heurístico ampliado con Claude Code.
12. Documentación de resultados, limitaciones y trabajo futuro.

---

## 7. Estado actual de análisis

| Ataque / perfil | Estado                                                                 |
| --------------- | ---------------------------------------------------------------------- |
| Tráfico normal  | Analizado como línea base de calibración                               |
| DoS             | Analizado y validado parcialmente mediante detector ampliado           |
| UDP Scan        | Analizado y validado de forma robusta mediante detector ampliado       |
| NerisBotnet     | Analizado y validado parcialmente; requiere correlación distribuida    |
| scan11          | Analizado y validado de forma robusta como Single-Source Vertical Scan |
| scan44          | Analizado y validado de forma robusta como Distributed Vertical Scan   |
| anomaly-sshscan | Analizado; validación limitada por su naturaleza low-and-slow          |
| anomaly-spam    | Analizado como caso exploratorio de baja evidencia                     |

---

## 8. Modelo de comportamiento actual

El modelo actual organiza los ataques según la localización de la automatización:

| Ataque          | Categoría                                   | Automatización                              |
| --------------- | ------------------------------------------- | ------------------------------------------- |
| DoS             | Distributed TCP Flood / TCP DoS             | Origen y concentración hacia servicio       |
| UDP Scan        | UDP Hybrid Scan / UDP Low-Entropy Scan      | Espacio de destino/red                      |
| scan11          | Single-Source Vertical Scan                 | Servicios del host objetivo                 |
| scan44          | Distributed Vertical Scan                   | Red coordinada + servicios destino          |
| anomaly-sshscan | Low-and-Slow SSH Horizontal Scan            | Selección de IPs destino hacia servicio SSH |
| NerisBotnet     | Botnet multivector / Distributed C2         | Red distribuida/C2                          |
| anomaly-spam    | SMTP Spam Burst / Low-Entropy SMTP Campaign | Campaña SMTP de baja evidencia              |

---

## 9. Validación programática actual

La validación más reciente se realizó mediante el detector heurístico ampliado:

```text
scripts/02_attack_analysis/detect_synthetic_behavior_extended.py
```

El archivo de resultados generado fue:

```text
data/attack_analysis/behavior_detection_results_extended.csv
```

El detector analizó 194 ventanas y generó 34 columnas de resultados.

Los resultados muestran:

* validación fuerte para ataques de escaneo estructurado como `scan11`, `scan44` y `anomaly-udpscan`
* validación parcial para `dos` y `nerisbotnet`
* validación limitada para `anomaly-sshscan`
* baja evidencia para `anomaly-spam`
* presencia de comportamientos automatizados en tráfico background/no etiquetado

---

## 10. Trabajo pendiente inmediato

Los siguientes pasos técnicos son:

1. Revisar `19_validacion_detector_ampliado.md` para comprobar que la interpretación de los resultados es correcta.
2. Actualizar `99_borrador_memoria.md` incorporando:

   * fase NotebookLM multifuente
   * especificación para Claude Code
   * detector heurístico ampliado
   * resultados de validación ampliada
3. Decidir si se mantiene el detector ampliado como resultado experimental o si se crea una versión ajustada de umbrales.
4. Analizar si `anomaly-spam` debe mantenerse únicamente como caso exploratorio.
5. Preparar una sección final de limitaciones y trabajo futuro coherente con los resultados obtenidos.

---

## 11. Nota metodológica

Las respuestas de NotebookLM no se consideran validación empírica por sí mismas.

En este trabajo, el LLM se utiliza para:

* interpretar patrones de tráfico
* generar hipótesis técnicas
* comparar ataques con tráfico normal
* proponer categorías de comportamiento
* apoyar la redacción explicativa

La validación se realiza posteriormente mediante scripts Python sobre ventanas reales del dataset.

Por tanto, el flujo metodológico seguido es:

```text
Datos NetFlow → Ventanas temporales → NotebookLM/LLM → Hipótesis técnicas → Detector heurístico → Validación programática → Documentación final
```

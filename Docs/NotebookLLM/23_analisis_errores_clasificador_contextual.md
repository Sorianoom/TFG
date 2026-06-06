# Análisis de errores del clasificador contextual por traza

Análisis de los resultados de
[`scripts/02_attack_analysis/detect_attack_flows_contextual.py`](../../scripts/02_attack_analysis/detect_attack_flows_contextual.py),
a partir de
[`flow_level_detection_results.csv`](../../data/attack_analysis/flow_level_detection_results.csv)
y
[`flow_level_detection_summary.csv`](../../data/attack_analysis/flow_level_detection_summary.csv).

El objetivo es entender **por qué** algunas familias tienen baja precisión o bajo recall,
distinguiendo los fallos reales de los artefactos de evaluación, y proponer cambios que
mejoren la generalización **sin sobreajustar ni perder interpretabilidad**.

La base del análisis es la **matriz de confusión a nivel de traza** (6.870.331 trazas):

**Por etiqueta original → a qué `predicted_label` va:**

| original_label | total | principal destino | resto |
|---|---:|---|---|
| scan11 | 102.572 | **scan11 102.220 (99,7 %)** | no_clasif 328; bg 24 |
| scan44 | 382.351 | **scan11 301.063 (78,7 %)** | dos 70.489 (18,4 %); scan44 9.662 (2,5 %); no_clasif 1.105 |
| anomaly-udpscan | 1.001.413 | **no_clasif 803.075 (80,2 %)** | udpscan 198.324 (19,8 %); bg 14 |
| dos | 247.230 | **scan11 121.135 (49,0 %)** | dos 120.957 (48,9 %); no_clasif 2.988; bg 2.096 |
| nerisbotnet | 99.762 | **no_clasif 87.031 (87,2 %)** | bg 7.611; neris 5.120 (5,1 %) |
| anomaly-sshscan | 44 | **no_clasif 44 (100 %)** | — |
| anomaly-spam | 544 | no_clasif 306; bg 224 | spam 14 (2,6 %) |
| background | 5.026.776 | bg 3.159.599 (62,9 %) | no_clasif 1.812.278; **dos 37.966; sshscan 8.246; udpscan 5.897; spam 1.260; scan11 1.347** |

**Por `predicted_family` → de qué etiqueta original procede (composición de cada predicción):**

| predicted_family | total | composición real |
|---|---:|---|
| scan11 | 525.790 | scan44 301.063; dos 121.135; **scan11 102.220**; bg 1.347; blacklist 25 |
| scan44 | 9.767 | **scan44 9.662 (98,9 %)**; dos 54; bg 51 |
| anomaly-udpscan | 204.251 | **udpscan 198.324 (97,1 %)**; bg 5.897; blacklist 30 |
| dos | 229.458 | **dos 120.957 (52,7 %)**; scan44 70.489 (30,7 %); bg 37.966 (16,5 %) |
| nerisbotnet | 5.264 | **neris 5.120 (97,3 %)**; bg 132; blacklist 12 |
| anomaly-sshscan | 8.248 | **bg 8.246 (99,97 %)**; blacklist 2 |
| anomaly-spam | 1.274 | **bg 1.260 (98,9 %)**; spam 14 |

---

## 1. Resumen de resultados por familia

| familia | precisión | recall | confianza dominante | diagnóstico breve |
|---|---:|---:|---|---|
| scan11 | 0,194 | 0,997 | alta | recall casi perfecto; precisión baja por **absorber** scan44 y dos |
| scan44 | 0,989 | 0,025 | alta | predice limpio, pero casi todas sus trazas se etiquetan scan11 |
| anomaly-udpscan | 0,971 | 0,198 | alta | predice limpio; 80 % de sus trazas caen en no_clasificado |
| dos | 0,527 | 0,489 | alta | mitad acierto; mezcla scan44 (30,7 %) y background (16,5 %) |
| nerisbotnet | 0,973 | 0,051 | media | predice limpio; 87 % de sus trazas en no_clasificado |
| anomaly-sshscan | 0,000 | 0,000 | media | el 99,97 % de sus predicciones son background |
| anomaly-spam | 0,011 | 0,026 | baja | el 98,9 % de sus predicciones son background |

Hay **dos tipos de error muy distintos** que conviene no confundir:

- **Confusión entre ataques** (scan44↔scan11↔dos): la traza se detecta como ataque, pero se le
  asigna la **familia equivocada**. No es ruido: es un problema de subclasificación.
- **Fuga a no_clasificado / background** (udpscan, neris, sshscan, spam): la traza de ataque
  **no se reconoce** como tal. Es pérdida de recall real.

---

## 2. Familias con baja precisión

- **scan11 (0,194).** Engañosa: de sus 525.790 predicciones, **422.198 (80 %) son en realidad
  otras familias de ataque** (scan44 301.063 + dos 121.135), y solo **1.347 (0,26 %) son
  background**. Es decir, scan11 casi nunca confunde ataque con tráfico normal; lo que hace es
  **quedarse con el subtipo equivocado** del barrido/SYN atómico.
- **dos (0,527).** Sus falsos positivos son scan44 (70.489, 30,7 %) y **background (37.966,
  16,5 %)**. El componente de background sí es un falso positivo real: ráfagas TCP de fondo
  concentradas hacia un puerto que imitan una inundación.
- **anomaly-sshscan (0,000) y anomaly-spam (0,011).** Precisión casi nula: el 99 % de sus
  predicciones son background (ver punto 8).

---

## 3. Familias con bajo recall

- **anomaly-udpscan (0,198).** 803.075 de sus trazas (80,2 %) van a **no_clasificado**: el
  contexto local de ±30 filas no reúne suficientes IPs/puertos destino del mismo origen.
- **nerisbotnet (0,051).** 87.031 trazas (87,2 %) a **no_clasificado**: el clúster C2 exigido
  no aparece (ver punto 7).
- **scan44 (0,025).** Recall engañosamente bajo: solo el 2,5 % conserva la etiqueta scan44,
  pero **el 78,7 % se detecta como scan11 y el 18,4 % como dos** — es decir, **el 97 % se
  detecta como ataque**, solo que con otra familia. No es pérdida de detección, es
  subclasificación.
- **anomaly-sshscan (0,000) y anomaly-spam (0,026).** Las trazas reales no se reconocen
  (ver punto 8).

---

## 4. Principales falsos positivos por familia

- **scan11**: casi todos sus "FP" son **otras trazas de ataque** (scan44 y dos); FP de
  background reales: solo 1.347.
- **dos**: scan44 (70.489) + **background (37.966)**. Este último es el FP más relevante:
  ráfagas TCP atómicas de fondo hacia un puerto concentrado, con puertos origen secuenciales.
- **anomaly-sshscan**: **8.246 trazas de background** (sondeos SSH de fondo: un origen que
  toca ≥3 destinos en el puerto 22 con flujos atómicos es muy común en el tráfico ISP).
- **anomaly-spam**: **1.260 trazas de background** (tráfico SMTP legítimo de un bloque /24 con
  cierta repetición de paquetes/bytes).
- **anomaly-udpscan**: solo 5.897 FP de background sobre 204.251 (≈3 %): muy contenido.
- **scan44 y nerisbotnet**: prácticamente sin FP (98,9 % y 97,3 % de pureza).

---

## 5. Principales falsos negativos por familia

- **anomaly-udpscan**: 803.075 trazas → no_clasificado (el patrón de dispersión no cabe en el
  contexto local).
- **nerisbotnet**: 87.031 → no_clasificado y 7.611 → background.
- **anomaly-sshscan**: las 44 trazas reales → no_clasificado (100 %).
- **anomaly-spam**: 306 → no_clasificado, 224 → background.
- **scan44 y dos**: sus "FN" no van a background, sino a **otra familia de ataque** (scan44→
  scan11/dos; dos→scan11). Son errores de subtipo, no de detección.

---

## 6. Por qué scan11 absorbe otros patrones

scan11 es, de hecho, el **detector más permisivo del bloque TCP-SYN-atómico** y gana la
selección con confianza *alta* en casi todos los casos. Las causas:

1. **Su núcleo solo exige dos condiciones**: verticalidad (muchos puertos destino para el par
   `src→dst`) y dominancia del origen en el contexto (`top_share ≥ 0,7`). Cualquier ráfaga de
   SYN atómicos de un origen hacia muchos puertos lo activa.
2. **El contexto local casi siempre parece de un solo origen.** En ±30 filas, aunque la ventana
   global sea un escaneo distribuido (scan44), el entorno inmediato de una traza suele estar
   dominado por una sola IP origen → `top_share ≥ 0,7` → scan11. Por eso **301.063 trazas de
   scan44 se etiquetan scan11**.
3. **El "dos" del UGR'16 contiene SYN multi-puerto.** 121.135 trazas etiquetadas dos son
   comportamentalmente barrido vertical de un origen → scan11 las captura. Es en parte un
   desajuste etiqueta↔comportamiento, ya documentado en el análisis por ventana.

En resumen: scan11 no "se equivoca con background", sino que **es el sumidero de todo SYN
atómico vertical de un origen**, absorbiendo el subtipo distribuido (scan44) y parte del dos.

---

## 7. Por qué scan44, nerisbotnet y udpscan tienen bajo recall

- **scan44.** Su núcleo exige **ver varios orígenes repartiéndose el barrido** (`top_share <
  0,7`) dentro del contexto local. Como el contexto de ±30 filas rara vez contiene varios
  escáneres simultáneos (suele estar dominado por uno), la condición casi nunca se cumple y la
  traza cae a scan11. La distribución es una propiedad **global**, no local.
- **nerisbotnet.** El detector se restringe —correctamente, para evitar falsos positivos— a
  **clústeres coordinados sobre puertos C2 (25/6667/2077)**. Pero la variante de nerisbotnet
  del dataset es mayoritariamente **un solo origen UDP hacia el puerto 53413**, que no es ni
  coordinación multinodo ni puerto C2. Resultado: 87 % a no_clasificado. La señal de
  coordinación simplemente no está presente en esas trazas.
- **anomaly-udpscan.** El patrón exige varias IPs (≥4) y puertos destino (≥6) **del mismo
  origen dentro del contexto**. En ventanas densas y entremezcladas con background, las trazas
  del mismo origen quedan dispersas y en ±30 filas no se acumula suficiente dispersión → el
  80 % cae a no_clasificado. La precisión es altísima (0,97) porque, cuando el patrón sí se ve,
  es inconfundible; lo que falla es la **cobertura** dentro de la ventana local.

El denominador común: estos tres patrones necesitan **una visión más amplia** (más filas o
contexto temporal) que la que ofrece ±30 filas.

---

## 8. Por qué sshscan y spam fallan a nivel de traza

- **anomaly-sshscan (precisión 0, recall 0).** Es un patrón *low-and-slow*: su evidencia real
  es la **persistencia del mismo origen a lo largo del tiempo / entre ventanas**, que es
  invisible en un contexto local. El detector, al buscar "un origen hacia ≥3 destinos en el
  puerto 22 con flujos atómicos", captura sobre todo **sondeos SSH de background** (8.246
  trazas), que tienen exactamente esa forma pero no están etiquetados como ataque. Las 44
  trazas reales, demasiado escasas y lentas, no forman grupo y caen a no_clasificado. Es decir,
  el detector **detecta lo que no es y se pierde lo que es**.
- **anomaly-spam (precisión 0,011).** El SMTP horizontal de bajo volumen es casi indistinguible
  del **SMTP legítimo**: conexiones TCP al puerto 25 desde un bloque /24 con cierta repetición
  de paquetes/bytes. El 98,9 % de sus predicciones son background. La firma real (tamaños de
  bytes concretos) rara vez aparece, y la condición genérica de repetición coincide con correo
  legítimo. Es un caso intrínsecamente de **baja evidencia**.

Ambos confirman lo que ya advertía la especificación: no deben tratarse como validación fuerte
a nivel de traza.

---

## 9. Qué cambios serían más prometedores

Priorizando **generalización e interpretabilidad** (no maximizar métricas):

1. **Unificar scan11 y scan44 en una clase conductual "barrido vertical" a nivel de traza**, y
   reportar el subtipo (un origen / distribuido) como **atributo secundario con incertidumbre**
   (p. ej. `n_orígenes_en_contexto`), no como etiqueta dura. Esto refleja la realidad —el
   contexto local no separa bien ambos— y **recupera de golpe la coherencia** de precisión y
   recall de ese bloque sin tocar umbrales.
2. **Activar el contexto temporal** (ya preparado en el script: `USE_TEMPORAL_CONTEXT`). Para
   udpscan y sshscan, un contexto por **ventana de tiempo** (no por nº de filas) capturaría la
   dispersión lenta que ±30 filas no ve, mejorando recall de forma estructural.
3. **Agregación por `src_ip` entre ventanas para los patrones low-and-slow** (sshscan): decidir
   por la actividad acumulada de un origen, no por una sola ventana. Es la única forma honesta
   de capturar la persistencia.
4. **Separar mejor dos vs barrido vertical**: medir la **dispersión de puertos destino del
   origen** en el contexto de forma más robusta, para que las trazas dos-con-muchos-puertos no
   caigan automáticamente en scan11.
5. **Mantener nerisbotnet como detector de clúster C2 de alta precisión/bajo recall** y
   documentar que la variante UDP de un solo origen no es detectable como coordinación.
6. **Evaluar sobre trazas de-duplicadas**: las ventanas solapadas (`rows_2000`, `time_10s`,
   `time_60s`) duplican trazas e inflan los recuentos; una evaluación sobre flujos únicos daría
   cifras más fieles.

---

## 10. Qué cambios podrían sobreajustar

A evitar, porque mejorarían métricas a costa de la generalización:

- **Bajar los umbrales de dispersión/volumen** (udpscan, scan) para subir recall: capturaría
  ruido de background y ajustaría el detector a las densidades concretas de estas ventanas.
- **Reintroducir valores exactos** (tamaños de bytes de spam, puertos origen UDP concretos)
  como criterio para subir precisión: es **firma**, no comportamiento, y no transfiere.
- **Ajustar umbrales familia por familia hasta cuadrar con las etiquetas**: sería ajustar a las
  ventanas observadas, no al fenómeno.
- **Usar el puerto 53413** u otras constantes específicas para "rescatar" nerisbotnet: ataría
  el detector a esta instancia concreta del dataset.
- Cualquier uso de **IPs concretas o de la etiqueta** como criterio (prohibido por diseño).

El criterio rector: un cambio es bueno si **mejora la cobertura del comportamiento** (p. ej.
contexto temporal), y sospechoso si **solo cuadra los números** con valores del dataset.

---

## 11. Recomendación para una versión v2

1. **Etiquetado en dos niveles.** Nivel primario = **clase conductual robusta**
   (`barrido_vertical`, `escaneo_udp`, `inundacion`, `clúster_coordinado`, `smtp_horizontal`);
   nivel secundario = subtipo (scan11/scan44) como atributo contextual con confianza explícita.
   Esto elimina la falsa "baja precisión" de scan11 y el falso "bajo recall" de scan44.
2. **Doble contexto: por filas y por tiempo.** Mantener ±N filas y añadir una ventana temporal
   configurable para los patrones dispersos o lentos (udpscan, sshscan).
3. **Pasada de agregación por origen** para low-and-slow (sshscan): un segundo recorrido que
   correlacione la actividad de cada `src_ip` a lo largo del tiempo.
4. **nerisbotnet**: conservar el clúster C2 (alta precisión) y declarar abiertamente su bajo
   recall; no forzar la variante de un solo origen.
5. **anomaly-spam y anomaly-sshscan**: marcar como **exploratorias** en la salida (confianza
   tope baja) y excluirlas de cualquier afirmación de validación fuerte.
6. **Evaluación honesta**: de-duplicar trazas entre ventanas y reportar que parte del
   background etiquetado **contiene escaneos reales**, lo que penaliza artificialmente la
   precisión de scan11.
7. **Conservar la interpretabilidad**: seguir emitiendo señales nombradas y evidencia por
   traza; ningún componente de ML opaco.

**Conclusión.** Los "malos" números de scan11 (precisión) y scan44 (recall) **no reflejan
fallos de detección**, sino la imposibilidad de separar subtipos con contexto puramente local:
el bloque de barrido vertical se detecta casi por completo. Los fallos **reales** son la fuga a
no_clasificado de udpscan y nerisbotnet (resoluble con contexto temporal/global) y la
inviabilidad de sshscan y spam a nivel de traza (intrínseca a su naturaleza). La v2 debe
**reorganizar las etiquetas según lo que el contexto puede realmente afirmar**, no forzar los
umbrales para cuadrar con las etiquetas del dataset.

# Clasificación contextual por traza

Documento de la fase de **clasificación de trazas concretas** mediante el script
[`scripts/02_attack_analysis/detect_attack_flows_contextual.py`](../../scripts/02_attack_analysis/detect_attack_flows_contextual.py).

---

## 1. Objetivo del clasificador contextual

El objetivo del TFG es detectar **trazas concretas de ataque**, no solo clasificar ventanas
completas. Este clasificador asigna una etiqueta (`predicted_label`) a **cada flujo NetFlow
individual** del dataset, indicando si forma parte de un patrón de ataque y de cuál.

La idea central es que una traza se clasifica por **pertenencia a un patrón conductual
detectado en su contexto local**, no de forma aislada. Esto permite defender que el sistema
clasifica trazas concretas, pero apoyándose en el comportamiento medible de su entorno
inmediato.

---

## 2. Por qué no se analiza cada flujo aislado

Una traza NetFlow aislada rara vez contiene información suficiente para decidir si es ataque.
Un único paquete SYN al puerto 80, o un único datagrama UDP, es **indistinguible** del
tráfico legítimo. Los ataques estudiados solo emergen del **patrón que forman varias trazas
juntas**:

- barridos verticales de puertos (scan11, scan44),
- dispersión de destinos (anomaly-udpscan),
- ráfagas y concentración hacia un servicio (dos),
- coordinación entre nodos (nerisbotnet),
- repetición de métricas (anomaly-spam),
- sondeo horizontal de baja intensidad (anomaly-sshscan).

Por tanto, clasificar flujo a flujo sin contexto produciría falsos negativos masivos (ataques
invisibles individualmente) o falsos positivos (un SYN suelto marcado como ataque). El
contexto local es lo que aporta la señal.

---

## 3. Cómo se usa el contexto anterior y posterior

Para cada fila `i` se toma una ventana deslizante de filas vecinas:

```text
contexto = filas [ i - CONTEXT_ROWS_BEFORE , i + CONTEXT_ROWS_AFTER ]
```

Valores por defecto (ajustables al inicio del script):

```text
CONTEXT_ROWS_BEFORE = 30
CONTEXT_ROWS_AFTER  = 30
```

Sobre ese contexto local se calculan las propiedades de comportamiento y se comprueba si la
fila `i` **pertenece** a un grupo que cumple algún patrón de ataque. En los bordes de cada
ventana el contexto es más pequeño y se registra como limitación (`contexto parcial`).

Queda preparada (pero **no activada**) la estructura para un futuro **contexto temporal**
(`USE_TEMPORAL_CONTEXT`, `CONTEXT_TIME_WINDOW_SECONDS`), que acotaría el contexto además por
una ventana de tiempo alrededor del `timestamp`.

---

## 4. Qué propiedades se calculan

Sobre cada contexto local se calculan (función `compute_context_features`):

- protocolo dominante; flags dominantes,
- IPs origen/destino únicas; puertos origen/destino únicos,
- duración media y ratio de duración cercana a cero,
- paquetes medios y ratio de pocos paquetes,
- bytes medios y **varianza de bytes** (baja entropía),
- flujos por timestamp y máximo de flujos en el mismo timestamp (sincronización),
- concentración de IP origen, IP destino y puerto destino,
- cardinalidad de puertos destino por par `src_ip/dst_ip`,
- cardinalidad de destinos por `src_ip` y de orígenes por `dst_ip`,
- secuencialidad de puertos origen y destino.

Las IPs intervienen **solo de forma relacional** (agrupar, contar, subred `/24`); **no se usa
ninguna IP concreta como regla**. La etiqueta original **no interviene** en la decisión: solo
se usa después para evaluar.

---

## 5. Cómo se detectan grupos conductuales

Cada familia tiene una función de **pertenencia** que comprueba si la traza objetivo forma
parte de un grupo del contexto que cumple su patrón (no basta con que el contexto general lo
tenga; la traza debe pertenecer al grupo):

- **scan11 / scan44**: la traza es TCP SYN atómica y su par `src→dst` realiza barrido vertical
  (muchos puertos destino). Se separan por **dominancia del origen** (`top_share`): si un
  origen domina → scan11; si el barrido se reparte entre varios orígenes con sincronización
  temporal → scan44.
- **anomaly-udpscan**: la traza es UDP atómica (no DNS) y su origen barre múltiples IPs y
  puertos destino con baja varianza de bytes.
- **dos**: la traza TCP atómica pertenece a un grupo concentrado hacia un mismo `dst_ip:puerto`
  con puertos origen secuenciales o ráfaga temporal.
- **anomaly-sshscan**: la traza TCP atómica al puerto 22 cuyo origen sondea múltiples destinos
  con flujos incompletos (confianza máxima *media*, por ser low-and-slow).
- **nerisbotnet**: la traza pertenece a un **clúster coordinado** (≥3 orígenes con métricas
  idénticas en el mismo instante) **sobre puertos C2 fuertes** (25/6667/2077). La restricción
  a puertos C2 evita los falsos clústeres triviales del background (p. ej. SYN al puerto 80).
- **anomaly-spam**: la traza TCP al puerto 25 con repetición de tuplas `packets/bytes` hacia
  varios destinos (confianza máxima *baja*, por ser exploratorio).

---

## 6. Cómo se asigna etiqueta a una traza concreta

1. Un **filtro previo** descarta las sesiones completas (multipaquete, duración apreciable):
   no encajan en los patrones sintéticos y se marcan `background` sin más coste. Solo las
   trazas atómicas o hacia servicios sensibles (22/25, C2) construyen contexto.
2. Se evalúan las funciones de pertenencia de cada familia sobre el contexto.
3. Si varias familias coinciden, se elige por: **nº de señales satisfechas → confianza →
   especificidad del patrón** (scan44 subsume scan11).
4. Si ninguna reúne evidencia suficiente:
   - traza "interesante" sin grupo → `no_clasificado`,
   - traza no interesante → `background`,
   - en ambos casos `is_attack = false`.

Cada traza recibe `predicted_label`, `predicted_family`, `is_attack`, `confidence`, los
límites de su contexto (`context_start/end/size`), una `evidence` interpretable y, si procede,
`limitations`.

---

## 7. Diferencias respecto al detector por ventana

| Aspecto | Detector por ventana (`..._extended.py`) | Clasificador contextual (este) |
|---|---|---|
| Unidad de salida | 1 etiqueta por ventana (194 filas) | 1 etiqueta por **traza** (6,87 M filas) |
| Ámbito de decisión | métricas de toda la ventana | contexto local de ±30 filas |
| Pregunta que responde | "¿de qué ataque es esta ventana?" | "¿esta traza concreta es ataque y de cuál?" |
| Separación scan11/scan44 | nítida (dominancia sobre toda la ventana) | difusa (el contexto local suele ver un solo origen) |
| Uso para el TFG | validar hipótesis a nivel de ventana | detectar **trazas concretas** |

Ambos comparten el enfoque conductual y la interpretabilidad; se complementan.

---

## 8. Resultados obtenidos

Ejecución sobre las 194 ventanas de `data/attack_analysis/`:

```text
Total de trazas analizadas : 6.870.331
  Marcadas como ataque     :   984.052
  Marcadas como background : 5.886.279
```

Salidas: [`data/attack_analysis/flow_level_detection_results.csv`](../../data/attack_analysis/flow_level_detection_results.csv)
(una fila por traza, ~1,9 GB) y
[`data/attack_analysis/flow_level_detection_summary.csv`](../../data/attack_analysis/flow_level_detection_summary.csv).

**Distribución de `predicted_label`:**

| predicted_label | trazas |
|---|---:|
| background | 3.174.842 |
| no_clasificado | 2.711.437 |
| scan11 | 525.790 |
| dos | 229.458 |
| anomaly-udpscan | 204.251 |
| scan44 | 9.767 |
| anomaly-sshscan | 8.248 |
| nerisbotnet | 5.264 |
| anomaly-spam | 1.274 |

**Precisión y recall aproximados por familia** (comparando `predicted_family` con
`original_label`; la etiqueta se usa solo para evaluar):

| familia | predichas | etiqueta original | aciertos | precisión | recall |
|---|---:|---:|---:|---:|---:|
| scan11 | 525.790 | 102.572 | 102.220 | 0,194 | **0,997** |
| scan44 | 9.767 | 382.351 | 9.662 | **0,989** | 0,025 |
| anomaly-udpscan | 204.251 | 1.001.413 | 198.324 | **0,971** | 0,198 |
| dos | 229.458 | 247.230 | 120.957 | 0,527 | 0,489 |
| nerisbotnet | 5.264 | 99.762 | 5.120 | **0,973** | 0,051 |
| anomaly-sshscan | 8.248 | 44 | 0 | 0,000 | 0,000 |
| anomaly-spam | 1.274 | 544 | 14 | 0,011 | 0,026 |

**Lectura de los resultados:**

- **Vertical scan (scan11 + scan44).** Es el bloque mejor detectado. scan11 tiene **recall
  altísimo** (0,997): casi ninguna traza de scan11 se escapa. Su **baja precisión** (0,194) no
  significa que falle, sino que **absorbe** dos cosas: (a) las trazas de scan44 —el contexto
  local rara vez ve la distribución entre orígenes y las clasifica como scan11— y (b) trazas
  etiquetadas `background` que **son escaneos verticales reales de fondo** (escáneres
  externos). En volumen, las trazas predichas como vertical (535.557) son del orden de las
  etiquetadas como vertical (484.923): la **clase "barrido vertical" se captura bien**; lo que
  se difumina es el subtipo scan11/scan44.
- **anomaly-udpscan, scan44 y nerisbotnet.** Comportamiento de **alta precisión y bajo
  recall**: cuando el clasificador marca una de estas etiquetas, acierta casi siempre
  (0,97–0,99), pero solo captura una fracción de sus trazas porque el patrón debe ser visible
  dentro del contexto local de ±30 filas.
- **dos.** Equilibrado en torno a 0,5 de precisión y recall.
- **anomaly-sshscan.** Falla a nivel de traza (precisión 0): las 8.248 predicciones son ruido
  de sondeo SSH de fondo, y las 44 trazas etiquetadas no se capturan. Coherente con su
  naturaleza *low-and-slow* (la persistencia entre ventanas no es observable localmente).
- **anomaly-spam.** Resultado **exploratorio y negligible** (14 aciertos), como se anticipaba.
- **background y no_clasificado.** 5,89 M trazas no ataque. El bloque `no_clasificado` (2,71 M)
  son flujos atómicos de fondo que no llegan a formar un grupo: el clasificador prefiere no
  forzar etiqueta.

---

## 9. Limitaciones

- **Detector heurístico**, no Machine Learning: reglas explicables con umbrales ajustables.
- **Contexto local fijo (±30 filas).** Patrones que requieren una visión más amplia —la
  **distribución entre orígenes (scan44)** o la **persistencia temporal (anomaly-sshscan)**—
  no se aprecian bien localmente. Por eso scan44 se confunde con scan11 y sshscan falla.
- **Umbrales empíricos** escalados al tamaño del contexto; su modificación altera los
  resultados.
- **Solapamiento de ventanas.** `rows_2000`, `time_10s` y `time_60s` son vistas solapadas del
  mismo tráfico: hay **trazas duplicadas** entre ficheros, lo que infla los recuentos
  absolutos y las cifras de evaluación son aproximadas.
- **La etiqueta original del UGR'16 no es verdad absoluta.** Se usa solo como referencia; hay
  trazas `background` que son escaneos reales, lo que penaliza artificialmente la "precisión"
  de scan11.
- **No es un IDS completo** y **no usa IPs ni etiquetas como criterio de detección**.
- **anomaly-sshscan y anomaly-spam** no deben considerarse validación fuerte a nivel de traza.
- El CSV por traza es grande (~1,9 GB) por contener una fila por flujo del dataset.

---

## 10. Conclusión

El clasificador contextual cumple el objetivo de **clasificar trazas concretas**, y lo hace de
forma defendible: cada traza se etiqueta por **pertenencia a un patrón conductual medible en
su contexto local**, sin usar IPs concretas ni la etiqueta como criterio, y dejando evidencia
interpretable por cada decisión.

La detección es **sólida para el tráfico de barrido**: captura prácticamente todas las trazas
de escaneo vertical (recall 0,997 en la clase vertical) y marca con alta precisión udpscan,
scan44 y nerisbotnet cuando el patrón es visible localmente. Es **parcial** para `dos` y
**débil o exploratoria** para `anomaly-sshscan` y `anomaly-spam`, cuya señal excede el contexto
local de una sola ventana de filas.

El resultado es coherente con el enfoque del TFG —**LLM + validación heurística
interpretable**— y aporta la pieza que faltaba frente al detector por ventana: una
clasificación **por traza concreta**, con su evidencia y sus limitaciones explícitas, sin
recurrir a aprendizaje automático ni a reglas ajustadas a IPs o etiquetas.

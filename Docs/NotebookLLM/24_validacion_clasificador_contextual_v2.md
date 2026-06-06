# Validación del clasificador contextual por traza v2 (jerárquico)

Validación de
[`scripts/02_attack_analysis/detect_attack_flows_contextual_v2.py`](../../scripts/02_attack_analysis/detect_attack_flows_contextual_v2.py)
y comparación frente a la v1
([`detect_attack_flows_contextual.py`](../../scripts/02_attack_analysis/detect_attack_flows_contextual.py)).

Salidas analizadas:
[`flow_level_detection_results_v2.csv`](../../data/attack_analysis/flow_level_detection_results_v2.csv)
y
[`flow_level_detection_summary_v2.csv`](../../data/attack_analysis/flow_level_detection_summary_v2.csv)
(6.870.331 trazas).

---

## 1. Qué cambia en la v2

El análisis de errores (doc 23) mostró que las métricas bajas de la v1 mezclaban **dos
problemas distintos**: la *confusión entre subtipos* (scan44 etiquetado como scan11) y la
*fuga real a background* (udpscan, nerisbotnet). La v2 los separa con un diseño **jerárquico
en dos etapas**:

- **ETAPA 1 — detección binaria contextual:** para cada traza decide
  `attack | background | insufficient_evidence`, respondiendo *"¿pertenece a comportamiento
  sintético/anómalo?"* sin asignar todavía subtipo.
- **ETAPA 2 — clasificación conductual:** solo para las trazas `attack`, asigna una **familia
  conductual** (`vertical_scan`, `udp_scan`, `tcp_flood`, `coordinated_botnet`,
  `ssh_horizontal_scan`, `smtp_campaign`, `unknown_attack`) y, de forma **secundaria y con su
  propia confianza**, un **subtipo** (scan11/scan44/…), que puede quedar *indeterminado*.

Además, según las reglas de diseño: scan11 y scan44 comparten primero la familia
`vertical_scan` (no se fuerza el subtipo si el contexto no lo permite); `tcp_flood` se separa
de `vertical_scan` por **baja diversidad de puerto destino**; `udp_scan` usa un **contexto más
amplio** (±60 filas); `coordinated_botnet` exige coordinación multinodo (si es débil, baja
confianza); y `ssh_horizontal_scan`/`smtp_campaign` se tratan como **baja evidencia**.

---

## 2. Detección binaria ataque/background (ETAPA 1)

Esta es la aportación principal de la v2 y la respuesta directa a *"clasificar trazas
concretas"*.

| Etiqueta binaria | trazas |
|---|---:|
| attack | 1.891.650 |
| background | 4.911.743 |
| insufficient_evidence | 66.938 |

Evaluación frente a la etiqueta original (atacante = una de las 7 familias):

```text
TP = 1.817.070   FP = 74.580   FN = 16.846   TN = 4.961.835
precisión ataque = 0,961        recall ataque = 0,991
```

**Comparación v1 vs v2** (la binaria de la v1 se deriva de su matriz de confusión del doc 23):

| Métrica binaria | v1 | v2 |
|---|---:|---:|
| Trazas marcadas attack | 984.052 | 1.891.650 |
| Precisión de ataque | 0,944 | **0,961** |
| Recall de ataque | 0,507 | **0,991** |
| Falsos positivos (background→attack) | 55.014 | 74.580 |
| Categoría `insufficient_evidence` | no existía | 66.938 |

La v2 **casi duplica el recall de detección de ataque (0,507 → 0,991) mejorando además la
precisión (0,944 → 0,961)**. La mejora de recall procede sobre todo de `udp_scan` (contexto
amplio) y del rescate de ráfagas atómicas por `unknown_attack`. El precio es un aumento
moderado de falsos positivos absolutos (55 k → 75 k, sobre 5 M de no-ataque: 1,5 %).

---

## 3. Clasificación por familia conductual (ETAPA 2)

| Familia | predichas | etiq. original | aciertos | precisión | recall |
|---|---:|---:|---:|---:|---:|
| vertical_scan | 533.659 | 484.923 | 411.041 | 0,770 | 0,848 |
| udp_scan | 780.761 | 1.001.413 | 774.653 | **0,992** | **0,774** |
| tcp_flood | 217.724 | 247.230 | 120.635 | 0,554 | 0,488 |
| coordinated_botnet | 5.270 | 99.762 | 5.120 | **0,972** | 0,051 |
| ssh_horizontal_scan | 8.248 | 44 | 0 | 0,000 | 0,000 |
| smtp_campaign | 923 | 544 | 14 | 0,015 | 0,026 |
| unknown_attack | 345.065 | — | — | n/a | n/a |

**Comparación a nivel de familia v1 vs v2** (en la v1, agregando sus subtipos a familias):

| Familia | v1 precisión / recall | v2 precisión / recall |
|---|---:|---:|
| vertical_scan | 0,771 / 0,852 | 0,770 / 0,848 |
| udp_scan | 0,971 / 0,198 | 0,992 / **0,774** |
| tcp_flood | 0,527 / 0,489 | 0,554 / 0,488 |
| coordinated_botnet | 0,973 / 0,051 | 0,972 / 0,051 |
| ssh_horizontal_scan | 0,000 / 0,000 | 0,000 / 0,000 |
| smtp_campaign | 0,011 / 0,026 | 0,015 / 0,026 |

Observaciones:

- **vertical_scan** rinde igual que en la v1 *agregada* (≈0,77 / 0,85): la detección del
  barrido vertical ya era buena. La diferencia es que **la v2 lo expresa correctamente como
  familia**, en lugar de esconderlo tras un subtipo `scan11` con precisión engañosa de 0,194.
- **udp_scan** es la gran mejora de la etapa 2: el contexto amplio sube el recall de **0,198 a
  0,774** manteniendo precisión casi perfecta (0,992).
- **tcp_flood** se mantiene (≈0,55 / 0,49): la frontera con el barrido distribuido sigue
  siendo intrínsecamente difusa.
- **coordinated_botnet** sigue siendo de alta precisión y bajo recall: la variante real
  (un solo origen UDP al puerto 53413) no es coordinación multinodo y no se captura.
- **unknown_attack** (345.065 trazas) es el coste del alto recall binario: agrupa trazas que
  son atómicas de baja entropía pero que no encajan en una firma de familia concreta; son
  mayoritariamente trazas de ataque rescatadas (p. ej. parte del dos) cuya familia no puede
  afirmarse con el contexto local.

---

## 4. Clasificación por subtipo

| Subtipo | v1 pred / aciertos (prec / recall) | v2 pred / aciertos (prec / recall) |
|---|---|---|
| scan11 | 525.790 / 102.220 (0,194 / 0,997) | 527.983 / 102.220 (0,194 / 0,997) |
| scan44 | 9.767 / 9.662 (0,989 / 0,025) | 5.676 / 5.608 (0,988 / **0,015**) |
| anomaly-udpscan | 204.251 / 198.324 (0,971 / 0,198) | 780.761 / 774.653 (0,992 / **0,774**) |
| dos | 229.458 / 120.957 (0,527 / 0,489) | 217.724 / 120.635 (0,554 / 0,488) |
| nerisbotnet | 5.264 / 5.120 (0,973 / 0,051) | 5.270 / 5.120 (0,972 / 0,051) |
| anomaly-sshscan | 8.248 / 0 (0 / 0) | 8.248 / 0 (0 / 0) |
| anomaly-spam | 1.274 / 14 (0,011 / 0,026) | 923 / 14 (0,015 / 0,026) |

La separación **scan11 ↔ scan44 sigue sin resolverse** a nivel de subtipo (scan11 absorbe el
barrido, scan44 baja incluso a recall 0,015), porque distinguir "un origen" de "varios" es una
propiedad **global** que el contexto local no ve. **La diferencia conceptual de la v2 es que
ya no presenta esto como un fallo de precisión**: el subtipo es explícitamente secundario,
lleva su propia `subtype_confidence` y queda `undetermined` cuando el contexto no permite
afirmarlo (se registra como limitación por traza).

---

## 5. Qué mejora respecto a v1

1. **Detección binaria de ataque mucho mejor y honesta**: recall 0,507 → **0,991** con
   precisión 0,944 → **0,961**. Es la métrica que mejor responde a "detectar trazas concretas".
2. **udp_scan deja de fugarse**: recall 0,198 → **0,774** (gracias al contexto amplio por
   `src_ip`), sin perder precisión.
3. **Representación correcta del barrido vertical**: `vertical_scan` como familia robusta
   (≈0,77 / 0,85) en lugar del subtipo `scan11` con precisión engañosa de 0,194.
4. **Tres salidas en vez de dos**: aparece `insufficient_evidence`, que separa lo dudoso de lo
   negativo en lugar de forzarlo a background.
5. **Incertidumbre explícita en el subtipo**: `subtype_confidence` y la etiqueta
   `undetermined` evitan afirmar scan11/scan44 cuando no hay base.

---

## 6. Qué empeora (o no mejora)

1. **Aparece `unknown_attack` (345.065 trazas)**: bolsa grande de "ataque sin familia". Es el
   coste de subir el recall binario; reduce la interpretabilidad fina de esas trazas.
2. **Más falsos positivos binarios absolutos** (55 k → 75 k), aunque la precisión global sube
   porque los TP crecen más rápido.
3. **subtype scan44 aún más bajo** (recall 0,025 → 0,015): la v2 es más conservadora al nombrar
   scan44 (exige reparto + sincronización), lo cual es intencionado pero reduce su recall de
   subtipo.
4. **tcp_flood, coordinated_botnet, ssh y spam no mejoran**: sus límites son estructurales, no
   de diseño de etiquetas (ver §7).

---

## 7. Limitaciones que quedan

- **scan11 vs scan44**: indistinguibles con contexto puramente local; requieren visión global
  del reparto entre orígenes. La v2 lo reconoce, no lo resuelve.
- **nerisbotnet**: la coordinación multinodo sobre puertos C2 casi no aparece; la variante de
  un solo origen (UDP 53413) no es detectable como botnet. Alta precisión, recall mínimo.
- **anomaly-sshscan**: *low-and-slow*; su evidencia es la persistencia temporal entre ventanas,
  invisible en contexto local. Las predicciones (8.248) son ruido SSH de fondo; las 44 trazas
  reales no se capturan.
- **anomaly-spam**: casi indistinguible del SMTP legítimo; baja evidencia (precisión 0,015).
- **unknown_attack**: detecta anomalía pero no familia; útil para el binario, pobre para la
  taxonomía.
- **Evaluación aproximada**: las ventanas (`rows_2000`, `time_10s`, `time_60s`) solapan vistas
  del mismo tráfico → trazas duplicadas que inflan los recuentos; y parte del `background`
  etiquetado contiene **escaneos reales**, que penaliza artificialmente la precisión.
- Sigue siendo **heurístico, sin ML, sin IPs ni labels como criterio**.

---

## 8. Por qué este enfoque responde mejor a la indicación del profesor

El profesor pedía **clasificar trazas concretas**, no ventanas. La v2 lo hace de la forma más
defendible posible:

1. **Da un veredicto por traza de alta calidad**: para cada flujo individual responde
   `attack / background / insufficient_evidence` con **precisión 0,96 y recall 0,99**. Esa es
   la afirmación robusta y verificable sobre una traza concreta.
2. **Separa lo que puede afirmarse de lo que no**: nivel binario (muy fiable) → familia
   conductual (fiable para vertical_scan y udp_scan) → subtipo (incierto, marcado como tal).
   No mezcla certezas con conjeturas.
3. **Es honesto con la incertidumbre**: usa `insufficient_evidence`, `undetermined` y
   `subtype_confidence` en lugar de forzar una etiqueta fina que el contexto no sostiene.
4. **Mantiene el enfoque metodológico del TFG**: reglas interpretables derivadas del análisis
   LLM, sin aprendizaje automático, sin IPs concretas y sin usar las etiquetas para decidir
   (solo para evaluar). Cada traza lleva su evidencia y sus limitaciones.

En términos del tribunal: la v1 permitía decir *"clasifico trazas concretas, pero las métricas
de subtipo son confusas"*; la v2 permite decir *"detecto con alta fiabilidad si una traza
concreta es ataque (0,96/0,99), la asigno a una familia de comportamiento robusta cuando puedo,
y declaro explícitamente la incertidumbre del subtipo"*. Es una afirmación más fuerte,
metodológicamente más limpia y más fácil de defender.

---

## 9. Conclusión

La v2 **no inventa detección donde no la hay** (scan11/scan44 siguen sin separarse localmente;
neris/ssh/spam siguen siendo débiles), pero **reorganiza el problema según lo que el contexto
puede afirmar de verdad**:

- una **detección binaria por traza casi perfecta en recall y muy precisa** (0,991 / 0,961),
- una **familia conductual robusta** para barrido vertical y escaneo UDP,
- y una **subclasificación honesta**, con incertidumbre explícita.

Es la pieza que faltaba para sostener, ante el profesor, que el sistema **clasifica trazas
concretas** mediante comportamiento medible en su contexto, priorizando generalización,
interpretabilidad y coherencia metodológica por encima de maximizar métricas de subtipo.

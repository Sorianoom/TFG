# Recomendación de versión del clasificador

## 1. Objetivo del documento

El objetivo de este documento es **decidir qué versión del clasificador se adopta como
referencia principal** para la memoria del TFG, una vez desarrolladas y validadas las distintas
aproximaciones para detectar tráfico de ataque en el dataset UGR'16.

Se comparan cuatro componentes:

- detector por ventana,
- clasificador contextual v1,
- clasificador contextual v2,
- clasificador contextual v3.

---

## 2. Evolución de los clasificadores

- **Detector por ventana** (`detect_synthetic_behavior_extended.py`):
  - clasifica **ventanas completas** (una etiqueta por ventana),
  - útil para **validar hipótesis globales** sobre cada familia de ataque,
  - **insuficiente** para responder plenamente a la indicación del profesor de **clasificar
    trazas concretas**.

- **v1 contextual** (`detect_attack_flows_contextual.py`):
  - clasifica **trazas concretas** usando **contexto local** (±30 filas),
  - detecta patrones por **pertenencia a grupos conductuales** del contexto,
  - problema: **mezcla errores de subtipo** (scan44 etiquetado como scan11) **con errores
    reales de detección** (fuga a background/no_clasificado).

- **v2 jerárquico** (`detect_attack_flows_contextual_v2.py`):
  - separa **ataque/background**, **familia conductual** y **subtipo**,
  - **mejora claramente la detección binaria por traza**,
  - introduce `unknown_attack`, `insufficient_evidence` y **subtipo con incertidumbre**.

- **v3 con pase global/temporal** (`detect_attack_flows_contextual_v3.py`):
  - mantiene el enfoque jerárquico de v2,
  - añade un **segundo pase global/temporal por ventana**,
  - **mejora la separación scan11/scan44**,
  - **mejora udp_scan**,
  - **reduce los falsos positivos de sshscan**,
  - **reduce unknown_attack**.

---

## 3. Comparación numérica principal

(Cifras tomadas de los documentos 24 y 26.)

| Métrica | v2 | v3 |
| --- | ---: | ---: |
| Precisión binaria de ataque | 0,961 | 0,930 |
| Recall binario de ataque | 0,991 | 0,991 |
| scan44 — recall | 0,015 | 0,796 |
| scan11 — precisión | 0,194 | 0,763 |
| udp_scan — recall | 0,774 | ~1,00 |
| Falsos positivos sshscan | 8.248 | 60 |
| unknown_attack (trazas) | 345.065 | 118.264 |
| coordinated_botnet — precisión | 0,972 | 0,269 |

Interpretación:

- **v2 es más conservador en precisión binaria** (0,961 frente a 0,930).
- **v3 es mejor para la clasificación estructural/fina**: resuelve scan11/scan44 y eleva
  udp_scan.
- **v3 mantiene el recall binario** (0,991): no se pierde capacidad de detectar ataque.
- **v3 mejora los subtipos estructurados** (scan44 recall 0,015 → 0,796; scan11 precisión
  0,194 → 0,763).
- **v3 empeora coordinated_botnet en el camino no-C2** (precisión 0,972 → 0,269), que **debe
  mantenerse como señal exploratoria** de baja confianza, no como validación fuerte.

---

## 4. Decisión final

**La versión v3 se adopta como clasificador contextual principal por traza para la memoria del
TFG.**

Justificación:

- responde mejor a la indicación del profesor (clasificar trazas concretas),
- clasifica **trazas concretas**, no ventanas,
- usa **contexto local y global**,
- **mantiene el recall binario en 0,991**,
- **mejora scan11/scan44** (subtipo por fin informativo),
- **mejora udp_scan** (recall ~1,00),
- **reduce los falsos positivos de sshscan** (8.248 → 60),
- **reduce unknown_attack** (345.065 → 118.264),
- **conserva evidencia interpretable** por traza,
- **no usa IPs concretas** como reglas,
- **no usa las etiquetas** para detectar.

Además:

- **La v2 se conserva como referencia más conservadora en precisión binaria** (0,961), por si
  en algún uso interesa maximizar la precisión por encima de la resolución de subtipo.
- **El detector por ventana se conserva como validación global de hipótesis** por familia.
- **La v1 se conserva como paso experimental intermedio** que motivó el rediseño jerárquico.

---

## 5. Limitaciones que quedan

- La **precisión binaria baja de 0,961 a 0,930** en v3 (en parte por escaneos UDP reales del
  background, que son comportamiento real más que error claro).
- **coordinated_botnet no-C2** tiene baja precisión (0,269) y debe tratarse como **señal
  exploratoria** de confianza baja.
- **anomaly-sshscan** sigue **sin validación fuerte** como subtipo real (su evidencia es la
  persistencia temporal, difícil de afirmar con seguridad).
- **anomaly-spam** sigue siendo un **caso de baja evidencia**.
- **Parte del background puede contener ruido automatizado real** (escaneos de fondo), lo que
  penaliza artificialmente la precisión y no debe leerse como simples falsos positivos.
- La **evaluación puede estar afectada por el solapamiento de ventanas** y por trazas
  duplicadas entre ficheros (`rows_2000`, `time_10s`, `time_60s`).
- **No se debe seguir ajustando para cuadrar métricas con las etiquetas**, porque eso podría
  producir **sobreajuste** al ruido concreto de este dataset.

---

## 6. Recomendación metodológica

- **Usar v3 como resultado principal** del clasificador contextual por traza.
- **Presentar las métricas en tres niveles**, de lo más fiable a lo más incierto:
  1. **ataque/background** (detección binaria, muy fiable),
  2. **familia conductual** (robusta para vertical_scan, udp_scan, tcp_flood),
  3. **subtipo** (informativo en scan11/scan44; exploratorio en el resto).
- **No vender sshscan, spam ni neris-no-C2 como validación fuerte**: son señales
  exploratorias.
- **Explicar que `unknown_attack` es una categoría de incertidumbre útil**: marca ataque
  atómico de baja entropía sin firma de familia clara, en lugar de forzar una etiqueta.
- **Detener el desarrollo del clasificador en este punto** para **evitar sobreajuste**.

---

## 7. Conclusión

La **v3 es la versión final recomendada** porque **reorganiza el problema según lo que el
contexto puede afirmar realmente**: primero **detecta si una traza es ataque**, después le
asigna una **familia conductual** robusta y **solo entonces** intenta el **subtipo**, y únicamente
cuando hay evidencia suficiente. Es la aproximación que mejor responde a la indicación del
profesor —clasificar trazas concretas— manteniendo la interpretabilidad y la generalización, y
asumiendo de forma explícita sus limitaciones. La v2 se mantiene como alternativa más
conservadora en precisión binaria, el detector por ventana como validación global de hipótesis
y la v1 como paso experimental intermedio.

> **Nota (experimento v4).** Posteriormente se realizó un experimento de mejora de familias
> débiles (`detect_attack_flows_contextual_v4_experimental.py`, documento 30). La v4 **no cambia
> esta decisión**: no mejora la detección binaria ni el recall de las familias débiles
> (`anomaly-sshscan` incluso empeora y `anomaly-spam` no mejora). Su único avance defendible es
> separar `nerisbotnet` en alta/baja confianza (precisión 0,757 en el subconjunto de alta
> confianza, sin ganar recall). La **v3 sigue siendo el clasificador principal**; la v4 queda
> como variante experimental y posible trabajo futuro.

# 32. Experimento de contexto largo para anomaly-sshscan y spam (april.week2)

Variante **experimental** que añade un pase de **contexto temporal largo** (agregación global
por `src_ip`) para intentar detectar `anomaly-sshscan` en `april.week2`, donde la v3 estándar
obtuvo recall 0. **No sustituye a la v3**, que sigue siendo el clasificador principal.

- Script: [`scripts/02_attack_analysis/detect_attack_flows_contextual_v3_long_context_experimental.py`](../../scripts/02_attack_analysis/detect_attack_flows_contextual_v3_long_context_experimental.py)
- Salidas: `data/generalization/results/generalization_results_v3_long_context_april_week2.csv` y
  `.../summaries/generalization_summary_v3_long_context_april_week2.csv`
- **No modifica la v3** (la importa y reutiliza); no usa IPs concretas, ni la etiqueta para
  detectar, ni firmas de bytes exactos.

## 1. Punto de partida y diagnóstico

En `april.week2` el sshscan es **un único origen** (`42.219.156.231`) con **fan-out enorme**:
**26.231 destinos distintos** en el puerto 22 (26.580 flujos). Sin embargo, **~87 % de esos
flujos son "completos"** (multipaquete, no SYN atómico). La v3 estándar exige *flujos
incompletos y sin sesión completa*, por lo que **excluye** a este origen y obtiene recall 0.

La señal robusta y generalizable aquí **no es la ligereza, sino el fan-out**: un origen que
sondea decenas de miles de servidores SSH distintos es inequívocamente un escaneo horizontal,
independientemente de si los flujos parecen completos.

## 2. Variante experimental

Pase de **contexto largo**: agrega por `src_ip` el tráfico hacia el puerto 22 sobre todo el
horizonte disponible (la unión de ventanas de april, con timestamps reales) y calcula por
origen: destinos distintos, nº de flujos, ratio de flujos ligeros/incompletos, sesiones
completas, paquetes/bytes medios y **persistencia temporal** (nº de sub-ventanas activas a
5/15/30/60 min).

Regla (sin IPs, sin bytes exactos, no solo por `dst_port=22`):

- **Núcleo**: fan-out ≥ `min_dsts` destinos distintos al puerto 22 por origen.
- **Persistencia temporal**: como señal de **confianza** (se prueban 5/15/30/60 min).
- **Ligereza/incompletitud**: como señal de confianza (no como gate, porque en april no se
  cumple).

Señal débil de **spam** (`smtp_campaign_low_confidence`): fan-out al puerto 25, concentración
temporal, repetición de patrón y baja varianza de bytes; siempre baja confianza.

## 3. Resultados: v3 original vs contexto largo (april.week2, 400.000 trazas)

| Métrica | v3 original | contexto largo |
| --- | ---: | ---: |
| Binario TP / FP / FN / TN | 0 / 4.871 / 29.438 / 365.691 | 26.580 / 4.871 / 2.858 / 365.691 |
| Precisión binaria | 0,000 | **0,845** |
| Recall binario | 0,000 | **0,903** |
| F1 binario | 0,000 | **0,873** |
| sshscan precisión | 0,000 | **0,999** |
| sshscan recall | 0,000 | **0,907** |
| sshscan F1 | 0,000 | **0,951** |
| spam precisión / recall / F1 | 0 / 0 / 0 | 0 / 0 / 0 |
| ssh predichas / aciertos / reales | 19 / 0 / 29.298 | 26.599 / 26.580 / 29.298 |

## 4. Falsos positivos nuevos

- **Ninguno relevante**: la variante añade solo **19 falsos positivos** de SSH (precisión ssh
  0,999). Los **4.871 FP binarios son los MISMOS** que en la v3 original (ruido de escaneo de
  fondo clasificado como udp/tcp_flood/unknown); el pase de contexto largo **no los aumenta**.
- La detección de sshscan, por tanto, **sube el recall sin disparar el ruido**.

## 5. Mejor ventana temporal

| Configuración | Orígenes marcados | Flujos marcados |
| --- | ---: | ---: |
| fan-out `min_dsts=20` | 3 | 26.716 |
| fan-out `min_dsts=50` | 1 | 26.580 |
| fan-out `min_dsts=100` | 1 | 26.580 |
| persistencia gate 5 min | 1 | 26.580 |
| persistencia gate 15 min | 0 | 0 |
| persistencia gate 30 min | 0 | 0 |
| persistencia gate 60 min | 0 | 0 |

- El **fan-out es la señal decisiva** (independiente de la ventana). Con `min_dsts=50` solo se
  marca el escáner real (sin FP); con `min_dsts=20` aparecen 2 orígenes adicionales de fondo
  (escaneos SSH no etiquetados, FP discutibles).
- En la **persistencia**, la **ventana de 5 minutos es la mejor**: a 15/30/60 min la actividad
  del escáner en la muestra colapsa a un solo bucket y el gate de persistencia la descarta.
  Esto refleja una **limitación del muestreo** (la unión de bloques cubre pocos instantes), no
  del método: cuanto más pequeña la ventana, mayor resolución temporal de persistencia.

## 6. ¿Mejora realmente o solo genera ruido?

**Mejora de forma clara y limpia para sshscan**: recall 0 → 0,907 con precisión 0,999 y sin
falsos positivos nuevos. No es ruido: es una detección correcta del escaneo horizontal SSH por
su fan-out. **Spam no mejora** (0 aciertos): sigue siendo indistinguible del SMTP legítimo con
metadatos de flujo, y se mantiene como caso exploratorio.

## 7. Matices y límites

- La mejora depende de un **pase de agregación GLOBAL por origen** (contexto largo), que la v3
  estándar **no tiene** por diseño (usa contexto local). Es una **diferencia arquitectónica**,
  no un ajuste de umbral.
- El recall (0,907, no 1,0) se debe a que ~2.700 trazas sshscan provienen de orígenes sin
  fan-out alto (flujos sueltos), que el fan-out no captura.
- El resultado es nítido **porque el escáner es un único origen con fan-out masivo**. Un sshscan
  **distribuido y de bajo fan-out por nodo** no se detectaría con esta regla; haría falta otra
  señal (p. ej. coordinación).
- La persistencia temporal no pudo evaluarse a fondo por la cobertura del muestreo; convendría
  validarla sobre un **segmento contiguo largo** de april en trabajo futuro.

## 8. Decisión

- **La v3 estándar sigue siendo el clasificador principal.** Esta variante es experimental.
- El pase de **contexto largo por origen (fan-out) para sshscan** es una **línea futura
  prometedora**: mejora de recall 0 → 0,907 con precisión 0,999 y sin FP nuevos, con una regla
  generalizable (fan-out, sin IPs ni bytes). Se propone como posible **"pase 3" global** añadido
  a la arquitectura, no como sustitución de la v3.
- **Spam** se mantiene como **caso exploratorio** (sin mejora).
- Configuración recomendada si se retoma: **fan-out `min_dsts` ≈ 50** + persistencia a **5 min**
  como confianza, validando antes sobre un tramo contiguo largo.

## 9. Conclusión

El experimento demuestra que la incapacidad de la v3 para detectar `anomaly-sshscan` en april
**no es intrínseca al enfoque conductual**, sino una consecuencia de usar **solo contexto
local**: agregando el comportamiento por `src_ip` a largo plazo, el escaneo horizontal SSH se
detecta casi perfectamente (F1 0,951) por su fan-out, sin coste en falsos positivos. Queda como
**trabajo futuro** (pase global por origen), manteniendo la v3 como versión principal y el spam
como límite estructural.

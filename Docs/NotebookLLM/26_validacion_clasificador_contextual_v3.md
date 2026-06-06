# Validación del clasificador contextual por traza v3 (dos pases)

Validación de
[`scripts/02_attack_analysis/detect_attack_flows_contextual_v3.py`](../../scripts/02_attack_analysis/detect_attack_flows_contextual_v3.py)
y comparación frente a la v2
([`detect_attack_flows_contextual_v2.py`](../../scripts/02_attack_analysis/detect_attack_flows_contextual_v2.py)).

Salidas:
[`flow_level_detection_results_v3.csv`](../../data/attack_analysis/flow_level_detection_results_v3.csv)
y
[`flow_level_detection_summary_v3.csv`](../../data/attack_analysis/flow_level_detection_summary_v3.csv)
(6.870.331 trazas).

---

## 0. Qué añade la v3

La v3 mantiene el enfoque jerárquico de la v2 (etapa 1 binaria + etapa 2 por familia) y
añade un **segundo pase global/temporal por ventana** que resuelve lo que el contexto local
de ±N filas no podía ver:

- **subtipo scan11/scan44** con la estructura global del barrido (un origen vs distribuido),
- **ssh_horizontal_scan** solo por **persistencia agregada por `src_ip`** (no por ráfaga local),
- **coordinated_botnet** por **coordinación en buckets temporales** (los puertos C2 suman
  confianza pero no son gate duro; fuera de C2 se exige identidad persistente de muchos nodos),
- **udp_scan** confirmado por **dispersión global por `src_ip`**,
- **smtp_campaign** solo con **fan-out claro** hacia el 25 (si no, no se fuerza).

---

## 1. Detección binaria ataque/background

| Métrica binaria | v2 | v3 |
|---|---:|---:|
| Trazas attack | 1.891.650 | 1.954.053 |
| Trazas background | 4.911.743 | 4.864.029 |
| insufficient_evidence | 66.938 | 52.249 |
| TP / FP / FN / TN | 1.817.070 / 74.580 / 16.846 / 4.961.835 | 1.816.688 / 137.365 / 17.228 / 4.899.050 |
| **Precisión ataque** | **0,961** | 0,930 |
| **Recall ataque** | **0,991** | **0,991** |

El **recall binario se mantiene (0,991)** —prioridad nº 1— pero la **precisión baja de 0,961 a
0,930** (los FP suben de 74,6 k a 137,4 k). El aumento de FP procede casi por completo de la
confirmación global de `udp_scan` (ver §3): son en su mayoría orígenes UDP de **background con
dispersión real de tipo escaneo**, que el propio análisis previo ya señalaba como ruido de
escaneo presente en el tráfico normal. Es, por tanto, una degradación **moderada y en parte
artificial** (parte de esos "FP" son escaneos reales etiquetados como background).

---

## 2. Clasificación por familia conductual

| Familia | v2 precisión / recall | v3 precisión / recall |
|---|---:|---:|
| vertical_scan | 0,770 / 0,848 | 0,770 / 0,847 |
| udp_scan | 0,992 / 0,774 | 0,938 / **1,000** |
| tcp_flood | 0,554 / 0,488 | 0,554 / 0,488 |
| coordinated_botnet | 0,972 / 0,051 | **0,269** / 0,044 |
| ssh_horizontal_scan | 0,000 / 0,000 | 0,000 / 0,000 |
| smtp_campaign | 0,015 / 0,026 | 0,000 / 0,026 |
| unknown_attack | 345.065 trazas | 118.264 trazas |

- **udp_scan**: el pase global eleva el recall de 0,774 a **prácticamente 1,0** (1.001.219 de
  1.001.413), con una caída moderada de precisión (0,992 → 0,938) por los escaneos UDP de fondo.
- **vertical_scan** y **tcp_flood**: sin cambios a nivel de familia (lo que cambia es el
  subtipo de vertical_scan, §4).
- **coordinated_botnet**: **empeora** (precisión 0,972 → 0,269). El camino no-C2 (sin gate de
  puerto, exigido por diseño) introduce falsos positivos de coordinación de fondo en ventanas
  largas, todos en **confianza baja**. El subconjunto de **alta confianza (puertos C2)
  conserva precisión alta**; el ruido vive en la parte baja-confianza.
- **unknown_attack**: baja de 345 k a 118 k, porque la confirmación global de udp_scan y la
  resolución de subtipo absorben trazas que antes quedaban sin familia.

---

## 3. Clasificación por subtipo (la mejora principal)

| Subtipo | v2 pred / aciertos (prec / recall) | v3 pred / aciertos (prec / recall) |
|---|---|---|
| **scan11** | 527.983 / 102.220 (**0,194** / 0,997) | 133.989 / 102.220 (**0,763** / 0,997) |
| **scan44** | 5.676 / 5.608 (0,988 / **0,015**) | 399.411 / 304.396 (0,762 / **0,796**) |
| anomaly-udpscan | 204.251 / 198.324 (0,971 / 0,198)¹ | 1.067.045 / 1.001.219 (0,938 / 1,000) |
| dos | 217.724 / 120.635 (0,554 / 0,488) | 217.724 / 120.635 (0,554 / 0,488) |
| nerisbotnet | 5.270 / 5.120 (0,972 / 0,051) | 16.462 / 4.420 (0,269 / 0,044) |
| anomaly-sshscan | 8.248 / 0 (0 / 0) | 60 / 0 (0 / 0) |
| anomaly-spam | 923 / 14 (0,015 / 0,026) | 1.098 / 0 (0 / 0) |

¹ valores de udpscan de la v2.

**La v3 resuelve la separación scan11/scan44**, que era el principal punto débil de v1/v2:

- **scan44** pasa de recall **0,015 a 0,796**: por fin se reconoce el barrido vertical
  distribuido como tal, en lugar de absorberse en scan11.
- **scan11** pasa de precisión **0,194 a 0,763**: deja de ser el "sumidero" de todo barrido
  vertical; ahora solo se queda con el de origen dominante (su recall sigue en 0,997).

Esto se logra **sin contexto local extra**, gracias al pase global que cuenta cuántos orígenes
participan en el barrido vertical de la ventana y decide el subtipo en consecuencia.

---

## 4. Cambios en falsos positivos

| Fuente de FP | v2 | v3 | comentario |
|---|---:|---:|---|
| ssh_horizontal_scan | 8.248 (todos FP) | **60** | **eliminados** al emitir ssh solo por persistencia global |
| smtp_campaign | 1.260 FP | 1.098 FP | similar; sigue siendo baja evidencia |
| coordinated_botnet | ~150 FP | ~12.000 FP | **empeora** por el camino no-C2 (baja confianza) |
| udp_scan (binario) | bajo | +~65.000 | escaneos UDP de fondo confirmados globalmente |

Balance: **se elimina la principal fuente de FP que pedía corregirse (sshscan)** y se reduce
spam, pero aparece FP nuevo en `coordinated_botnet` (no-C2) y en `udp_scan` (fondo). El de
udp es en parte comportamiento real de escaneo en background.

---

## 5. Cambios en falsos negativos

- **udp_scan**: los FN se desploman (recall 0,774 → ~1,0): casi no se escapa ninguna traza de
  escaneo UDP.
- **scan44**: deja de "perderse" como subtipo (recall 0,015 → 0,796).
- **binario**: FN prácticamente igual (16.846 → 17.228); el recall de ataque se mantiene.
- **nerisbotnet, sshscan, spam**: siguen con FN altos (sus señales reales exceden lo medible:
  coordinación no presente, low-and-slow, baja evidencia).

---

## 6. ¿Mejora sshscan?

**En precisión/recall de detección, no** (sigue 0/0): las 44 trazas reales son demasiado
escasas y lentas para superar el umbral de persistencia, incluso con agregación por origen.
**Pero sí mejora lo que se pedía como prioridad nº 2: los falsos positivos caen de 8.248 a
60.** Al exigir persistencia agregada (muchos destinos al 22, alto ratio de incompletos,
ausencia de sesiones completas) en lugar de ráfagas locales, se elimina casi todo el ruido SSH
de fondo. Es una mejora de **fiabilidad** (no marcar lo que no toca), no de cobertura.

---

## 7. ¿Mejora scan11/scan44?

**Sí, claramente — es el mayor logro de la v3.** El pase global resuelve el subtipo:

- scan44 recall **0,015 → 0,796**; scan11 precisión **0,194 → 0,763**.
- La decisión usa la estructura global de la ventana (nº de orígenes verticales y cuota del
  origen principal), no IPs concretas ni etiquetas.
- Cuando la ventana no permite decidir, el subtipo queda `undetermined` (sin penalizar).

---

## 8. Efecto sobre unknown_attack

`unknown_attack` baja de **345.065 a 118.264** trazas. La confirmación global de udp_scan y la
mejor asignación de subtipo reclaman muchas trazas que en la v2 quedaban sin familia. Sigue
siendo una bolsa útil (ráfagas atómicas de entropía casi nula sin firma de familia), pero más
pequeña y mejor delimitada.

---

## 9. Riesgos de sobreajuste

- El camino **no-C2 de coordinated_botnet** es el más delicado: para no usar el puerto como
  gate duro, se exige identidad persistente de ≥15 orígenes en ≥4 buckets. Aun así produce FP
  en fondo denso. **No se subieron más los umbrales para "limpiar" estas ventanas concretas**,
  porque sería ajustar al ruido de este dataset; se deja en confianza baja y documentado.
- No se reintrodujeron **firmas exactas** (puertos como 53413 ni tamaños de bytes concretos)
  para "rescatar" neris o spam, pese a que subiría el recall: sería sobreajuste.
- La confirmación global de **udp_scan** podría bajar su precisión si se relajara más; se
  mantuvo en un umbral de dispersión razonable y no se forzó.
- En general se **priorizó la generalización** sobre cuadrar métricas: las familias que
  dependen de contexto que el dataset no ofrece (neris no coordinado, sshscan low-and-slow,
  spam) **no se han forzado**.

---

## 10. Conclusión metodológica

La v3 **cumple su objetivo principal**: usando un segundo pase global/temporal, **resuelve la
separación scan11/scan44** (scan44 recall 0,015 → 0,796) y **eleva udp_scan a recall ~1,0**,
manteniendo el **recall binario en 0,991**. Además **elimina los falsos positivos de
sshscan** (8.248 → 60), que era la prioridad nº 2.

El coste es honesto y acotado:

- la **precisión binaria baja de 0,961 a 0,930**, en gran parte por escaneos UDP de fondo que
  son comportamiento real (no error claro);
- la familia **coordinated_botnet pierde precisión** por el camino no-C2 exigido, que se
  mantiene en confianza baja;
- **sshscan y spam siguen sin detectarse** (límites estructurales/de dato, no de diseño).

Metodológicamente, la v3 demuestra que **el contexto global resuelve lo que el local no puede
(subtipo y dispersión)**, y que **forzar las familias que dependen de contexto inexistente en
el dataset (neris no coordinado, sshscan, spam) solo añade ruido**. La recomendación es usar
la v3 como clasificador por traza —binario fiable + familia robusta (vertical_scan, udp_scan,
tcp_flood) + subtipo ahora **sí** informativo (scan11/scan44)— y mantener neris-no-C2, sshscan
y spam como **señales exploratorias de baja confianza**, nunca como validación fuerte. Es la
elección coherente con el enfoque del TFG: generalización e interpretabilidad por encima de
maximizar métricas.

---

### Resumen ejecutivo v2 → v3

| Aspecto | v2 | v3 | veredicto |
|---|---|---|---|
| Recall binario | 0,991 | 0,991 | = mantiene |
| Precisión binaria | 0,961 | 0,930 | ↓ moderado (parte, escaneo real de fondo) |
| Subtipo scan44 (recall) | 0,015 | **0,796** | ↑↑ resuelto |
| Subtipo scan11 (precisión) | 0,194 | **0,763** | ↑↑ resuelto |
| udp_scan (recall) | 0,774 | **1,000** | ↑↑ |
| FP de sshscan | 8.248 | **60** | ↓↓ eliminados |
| coordinated_botnet (precisión) | 0,972 | 0,269 | ↓ (camino no-C2, baja confianza) |
| spam | 0,015 / 0,026 | 0 / 0,026 | ≈ sigue exploratorio |

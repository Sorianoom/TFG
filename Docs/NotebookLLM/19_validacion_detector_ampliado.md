# Validación del detector heurístico ampliado

## 1. Objetivo de la validación

Este documento recoge la **validación programática** de las hipótesis técnicas generadas
mediante NotebookLM sobre el comportamiento de los ataques del dataset UGR'16. El objetivo
no es construir un sistema de detección de intrusiones (IDS) completo, sino comprobar de
forma reproducible si los patrones de comportamiento descritos por el análisis asistido
por LLM son **medibles** sobre las ventanas reales ya extraídas, contrastando la categoría
inferida heurísticamente con la familia de ataque esperada.

La validación responde a una pregunta concreta: *¿es posible aislar cada patrón de ataque
combinando métricas de flujo NetFlow, sin emplear la etiqueta como criterio de detección?*

---

## 2. Script utilizado

```text
scripts/02_attack_analysis/detect_synthetic_behavior_extended.py
```

Detector heurístico ampliado, independiente del detector original
(`detect_synthetic_behavior.py`, no modificado). Implementa un detector modular por familia
de ataque, con selección por nivel de confianza, evidencia interpretable y registro
explícito de limitaciones por ventana.

---

## 3. Archivo de resultados

```text
data/attack_analysis/behavior_detection_results_extended.csv
```

---

## 4. Número total de ventanas analizadas

Se analizaron **194 ventanas** CSV, recorriendo recursivamente `data/attack_analysis/` y
excluyendo los ficheros de resumen de extracción y los propios CSV de resultados.

---

## 5. Número de columnas del CSV

El archivo de resultados contiene **34 columnas** por ventana: identificación
(`file`, `attack_expected`), resultado de detección (`attack_detected`,
`predicted_category`, `confidence_level`, `confidence_score`, `detected_categories`),
métricas generales (totales, IPs y puertos únicos, medias y varianzas de duración, paquetes
y bytes, ratios de duración cero y pocos paquetes, concentraciones, máximos temporales) y
los campos interpretativos `evidence_summary` y `limitations`.

---

## 6. Distribución de ventanas por etiqueta esperada

| Etiqueta esperada (`attack_expected`) | Ventanas |
| --- | ---: |
| dos | 29 |
| anomaly-udpscan | 28 |
| nerisbotnet | 28 |
| scan11 | 28 |
| scan44 | 28 |
| anomaly-spam | 26 |
| anomaly-sshscan | 24 |
| none (background normal) | 3 |
| **Total** | **194** |

---

## 7. Distribución de categorías detectadas

Recuento de ventanas por categoría asignada por el detector (`predicted_category`,
expresada de forma abreviada):

| Categoría detectada | Ventanas |
| --- | ---: |
| scan11 (Single-Source Vertical Scan) | 35 |
| dos (Distributed TCP Flood / TCP DoS) | 35 |
| scan44 (Distributed Vertical Scan) | 30 |
| no_clasificado | 27 |
| anomaly-udpscan (UDP Low-Entropy Scan) | 25 |
| nerisbotnet (Distributed C2) | 21 |
| anomaly-sshscan (SSH Horizontal Scan) | 15 |
| anomaly-spam (SMTP Spam Burst) | 6 |
| **Total** | **194** |

El nivel `no_clasificado` corresponde a ventanas en las que ningún detector reunió
evidencia de comportamiento suficiente (confianza `insuficiente`).

---

## 8. Matriz de confusión

Filas = etiqueta esperada (`attack_expected`); columnas = categoría detectada
(`predicted_category`). La diagonal (en correspondencia) marca los aciertos.

| esperada \ detectada | scan11 | scan44 | udpscan | dos | neris | sshscan | spam | no_clasif | Total |
| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| **scan11** | **24** | 0 | 0 | 0 | 0 | 0 | 0 | 4 | 28 |
| **scan44** | 7 | **21** | 0 | 0 | 0 | 0 | 0 | 0 | 28 |
| **anomaly-udpscan** | 0 | 0 | **22** | 2 | 2 | 0 | 1 | 1 | 28 |
| **dos** | 0 | 6 | 0 | **14** | 2 | 5 | 1 | 1 | 29 |
| **nerisbotnet** | 0 | 3 | 1 | 4 | **13** | 1 | 3 | 3 | 28 |
| **anomaly-sshscan** | 0 | 0 | 0 | 6 | 2 | **5** | 1 | 10 | 24 |
| **anomaly-spam** | 3 | 0 | 0 | 9 | 2 | 4 | **0** | 8 | 26 |
| **none** | 1 | 0 | 2 | 0 | 0 | 0 | 0 | 0 | 3 |

---

## 9. Tabla de aciertos por familia

Aciertos = ventanas cuya categoría detectada coincide con la familia esperada.

| Familia | Aciertos | Tasa |
| --- | --- | ---: |
| scan11 | 24/28 | 0,86 |
| anomaly-udpscan | 22/28 | 0,79 |
| scan44 | 21/28 | 0,75 |
| dos | 14/29 | 0,48 |
| nerisbotnet | 13/28 | 0,46 |
| anomaly-sshscan | 5/24 | 0,21 |
| anomaly-spam | 0/26 | 0,00 |
| none | 0/3 | n/a |

(Para `none` no existe categoría "correcta": son ventanas de tráfico normal sin etiqueta de
ataque; su interpretación se aborda en la sección 10.)

---

## 10. Interpretación técnica

### Patrones más robustos: scan11, scan44 y anomaly-udpscan
Las tres familias presentan firmas sintéticas de muy baja entropía directamente medibles
(flujos atómicos, paquete SYN de 44 bytes, verticalidad de puertos en los escaneos TCP, o
barrido UDP secuencial con origen estable). Sus tasas de acierto (0,75–0,86) y la baja
contaminación cruzada de sus columnas en la matriz confirman que las hipótesis de NotebookLM
sobre estos ataques **se validan con claridad**. La distinción entre `scan11` (un único
origen domina el barrido) y `scan44` (barrido repartido entre varios orígenes) se sostiene
sobre la dominancia del origen, y la confusión residual entre ambos (7 ventanas de `scan44`
clasificadas como `scan11`) corresponde a ventanas con un origen dominante.

### dos: validado parcialmente
La familia `dos` se confunde principalmente con escaneos distribuidos: 6 ventanas se
clasifican como `scan44` y 5 como `anomaly-sshscan`. El propio modelo describe el DoS como
*Distributed TCP Flood*; en varias ventanas el tráfico se manifiesta como SYN multi-origen
hacia **múltiples puertos** destino, comportamiento difícil de separar de un barrido vertical
distribuido. El discriminador conceptual es la **concentración frente a la dispersión del
puerto destino**: el DoS concentra el volumen en un puerto fijo, mientras que el escaneo lo
dispersa. La confusión refleja, por tanto, una ambigüedad real del fenómeno.

### nerisbotnet: validado parcialmente
La señal de botnet reside en la **correlación distribuida entre nodos** (clústeres de IPs
origen con métricas idénticas y sincronizadas sobre puertos C2/servicio), no en el flujo
individual. Cuando una ventana no contiene coordinación multinodo suficiente, el detector
registra evidencia insuficiente en lugar de forzar una clasificación. La tasa de 13/28
refleja que la coordinación no está presente en todas las ventanas.

### anomaly-sshscan: limitado por su naturaleza low-and-slow
Es un patrón de goteo: pocos flujos atómicos hacia el puerto 22 dispersos en muchos destinos,
sin ráfagas. No puede detectarse por umbrales de volumen y su firma coincide con conexiones
fallidas legítimas. La verdadera evidencia —la **persistencia temporal del mismo origen entre
ventanas**— no es observable dentro de una única ventana, de ahí la baja tasa de acierto
(5/24) y las 10 ventanas declaradas como `no_clasificado`.

### anomaly-spam: caso exploratorio de baja evidencia
La campaña de spam es de bajo volumen y su firma real (paquetes y bytes hacia el puerto 25)
es más variable que los valores idealizados del análisis LLM, por lo que rara vez supera el
umbral de repetición. El detector la mantiene capada a confianza baja; con 0/26 aciertos,
**no debe utilizarse como validación fuerte** del modelo.

### Ventanas none/background
Las 3 ventanas de tráfico normal contienen comportamiento **automatizado de escaneo real**
(2 clasificadas como UDP scan y 1 como escaneo vertical, todas con `attack_label_rows = 0`).
El propio análisis de NotebookLM señalaba que el *background* del UGR'16 contiene ruido de
escaneo (sondeos externos, listas negras). Por tanto, estas detecciones **no deben
interpretarse automáticamente como falsos positivos simples**: son patrones de escaneo
genuinos presentes en el tráfico normal, que requieren revisión antes de cualquier conclusión.

---

## 11. Limitaciones

- El detector es **heurístico**: combina umbrales y reglas de comportamiento; no aprende de
  los datos.
- Opera sobre **ventanas previamente extraídas**, no sobre el flujo completo del dataset; los
  resultados dependen del modo y la densidad de extracción de cada ventana.
- Los **umbrales son empíricos** y ajustables; su modificación altera las tasas de acierto.
- **No es un IDS completo** ni produce alertas operativas.
- **No entrena modelos de aprendizaje automático**; toda la lógica es explicable y trazable.
- **No usa las etiquetas como criterio de detección**; la etiqueta solo se emplea a
  posteriori para comparar con la familia esperada.
- **Algunas ventanas contienen background mezclado con el ataque**, de modo que el patrón
  etiquetado puede ser minoritario frente al tráfico de fondo.
- El **tráfico normal real puede contener ruido de escaneo**, lo que puede producir
  detecciones legítimas de comportamiento automatizado en ventanas sin etiqueta de ataque.

---

## 12. Conclusión

El detector ampliado **valida parcialmente** las hipótesis técnicas generadas mediante
NotebookLM sobre el dataset UGR'16:

- La validación es **fuerte para los escaneos estructurados** —`scan11`, `scan44` y
  `anomaly-udpscan`—, cuyas firmas de baja entropía son medibles de forma fiable y con escasa
  confusión cruzada.
- La validación es **parcial o exploratoria para `nerisbotnet`, `anomaly-sshscan` y
  `anomaly-spam`**, que requieren contexto adicional (correlación entre nodos, persistencia
  temporal entre ventanas o un mayor número de muestras) que excede el análisis de una única
  ventana.
- La familia `dos` queda **parcialmente validada**, con confusión frente a escaneos
  distribuidos derivada de una ambigüedad real de comportamiento.

En conjunto, el resultado es **útil como evidencia metodológica** —demuestra que el
conocimiento estructurado extraído con NotebookLM es contrastable de forma reproducible
mediante métodos clásicos sobre flujos de red—, pero **no constituye un sistema final de
detección**. La combinación *análisis asistido por LLM + validación programática* se confirma
como una metodología coherente, siempre que las conclusiones del LLM se traten como hipótesis
sujetas a verificación.

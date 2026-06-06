# Validación de hipótesis generadas por LLM

## 1. Objetivo

Este documento recoge las principales hipótesis generadas durante el análisis asistido por modelos de lenguaje grandes (LLMs) y su validación mediante scripts Python sobre ventanas temporales extraídas del dataset UGR'16.

El objetivo es comprobar si las conclusiones propuestas por el LLM son coherentes con la evidencia empírica observada en los datos.

En este trabajo, el LLM se utiliza como herramienta de apoyo para interpretar, comparar y formular hipótesis sobre patrones de tráfico. Sin embargo, las hipótesis no se aceptan directamente como válidas: se contrastan mediante análisis programático sobre las ventanas NetFlow extraídas.

---

## 2. Metodología de validación

La validación se realizó mediante un detector heurístico implementado en Python.

El detector analiza ventanas temporales de flujos NetFlow y calcula métricas agregadas, entre ellas:

- número total de flujos
- IPs origen únicas
- IPs destino únicas
- puertos origen únicos
- puertos destino únicos
- duración media
- paquetes medios
- bytes medios
- varianza de bytes
- secuencialidad de puertos
- sincronización temporal
- concentración o dispersión del tráfico

Los resultados completos del detector se guardan en:

```text
data/attack_analysis/behavior_detection_results.csv
```

El detector no utiliza la etiqueta `blacklist` como criterio de clasificación. Las decisiones se basan únicamente en patrones estructurales del tráfico.

---

## 3. Hipótesis validadas

| Nº | Hipótesis generada por LLM | Evidencia observada | Estado |
|---:|---|---|---|
| 1 | El DoS se caracteriza por concentración hacia un único destino y puerto. | Las ventanas DoS presentan grupos TCP concentrados hacia `42.219.158.16:80`. | Validada |
| 2 | El DoS presenta secuencialidad en puertos de origen. | El detector identifica `src_port` secuencial en las tres ventanas DoS. | Validada |
| 3 | El DoS usa flujos de baja duración y baja variabilidad. | En los grupos DoS detectados, `zero_duration_ratio = 1.00` y `bytes_var = 0.00`. | Validada |
| 4 | El UDP Scan se caracteriza por un origen fijo y múltiples destinos. | Las ventanas UDP Scan presentan origen `217.156.59.213:5061` hacia múltiples IPs destino. | Validada |
| 5 | El UDP Scan realiza barrido secuencial de puertos destino. | El detector identifica `dst_port_sequential = True` en las tres ventanas UDP Scan. | Validada |
| 6 | El UDP Scan presenta baja varianza de bytes. | Las ventanas UDP Scan tienen varianza de bytes muy baja, cercana a 2. | Validada |
| 7 | El tráfico normal no debe clasificarse como ataque si no presenta estructura sintética dominante. | Los perfiles normales laboral, nocturno y transición no son clasificados como ataque. | Validada |
| 8 | NerisBotnet requiere evidencia de coordinación distribuida hacia un canal C2. | La tercera ventana presenta 20 IPs origen hacia `220.194.21.2:6667/TCP` en el mismo timestamp. | Validada |
| 9 | Las ventanas NerisBotnet con pocos flujos etiquetados no ofrecen evidencia suficiente para clasificación automática. | Las ventanas 1 y 2 contienen muy pocos flujos `nerisbotnet` y no son clasificadas. | Validada |
| 10 | El uso de `blacklist` no debe ser la base de clasificación. | El detector no utiliza la etiqueta `blacklist`, sino métricas de comportamiento. | Validada |

---

## 4. Resultados globales del detector

| Tipo de ventana | Ventanas detectadas        | Total    | Resultado                                      |
|-----------------|----------------------------|----------|------------------------------------------------|
| DoS             | 3                          | 3        | Correcto                                       |
| UDP Scan        | 3                          | 3        | Correcto                                       |
| NerisBotnet     | 1                          | 3        | Correcto cuando existe evidencia C2 suficiente |
| Normal          | 0 clasificadas como ataque | 3        | Sin falsos positivos                           |

---

## 5. Interpretación de los resultados

Los resultados confirman que las hipótesis principales generadas por el LLM son medibles mediante análisis programático.

El detector valida especialmente bien los ataques sintéticos simples:

- DoS
- UDP Scan

Estos ataques presentan patrones claros de baja entropía, secuencialidad y estructura rígida.

En el caso de NerisBotnet, la detección requiere mayor contexto y evidencia de coordinación distribuida. La tercera ventana permite validar el patrón C2, mientras que las dos primeras no contienen suficiente densidad de tráfico botnet para activar la regla sin aumentar el riesgo de falsos positivos.

Esto refuerza una conclusión importante: no todos los ataques pueden detectarse con la misma granularidad. Los ataques de tipo DoS y UDP Scan presentan estructuras locales claras, mientras que una botnet requiere observar relaciones distribuidas entre múltiples nodos.

---

## 6. Relación entre hipótesis del LLM y validación programática

El LLM fue útil para identificar patrones candidatos:

- concentración de flujos en DoS
- barrido secuencial en UDP Scan
- coordinación distribuida en NerisBotnet
- diferencia entre tráfico normal y tráfico sintético
- importancia de no depender de `blacklist`

Posteriormente, estos patrones fueron traducidos a reglas medibles en código.

Ejemplo:

```text
Hipótesis LLM:
El UDP Scan barre puertos de destino de forma secuencial.

Validación:
El detector calcula dst_port_sequential=True en las tres ventanas UDP Scan.
```

De esta forma, el LLM no se utiliza como clasificador directo, sino como apoyo para formular hipótesis interpretables que posteriormente se contrastan con datos.

---

## 7. Limitaciones

La validación presenta varias limitaciones:

- Se realiza sobre ventanas previamente extraídas, no sobre el dataset completo.
- El detector es heurístico y no pretende sustituir a un IDS completo.
- La detección de botnets requiere ventanas con suficiente evidencia temporal y distribuida.
- Los umbrales utilizados se han ajustado a partir de observaciones empíricas.
- El LLM puede proponer hipótesis útiles, pero siempre requieren validación externa.
- El análisis depende de que las ventanas seleccionadas sean representativas.

---

## 8. Conclusión

El uso de LLMs ha permitido generar hipótesis técnicas sobre el comportamiento de distintos ataques en UGR'16. La validación mediante código demuestra que muchas de estas hipótesis se corresponden con patrones reales presentes en los datos.

El enfoque combinado LLM + validación programática permite transformar explicaciones cualitativas en reglas técnicas verificables, manteniendo un enfoque explicable y reproducible.

Este resultado apoya la idea central del trabajo: los LLMs pueden ser útiles como herramientas de análisis y explicación en ciberseguridad, siempre que sus conclusiones sean contrastadas mediante evidencia empírica.
# Validación de hipótesis generadas por LLM

## 1. Objetivo

El objetivo de este documento es validar las principales hipótesis generadas durante el análisis asistido por modelos de lenguaje grandes (LLMs) sobre el dataset UGR'16.

En este trabajo, el LLM se utiliza como una herramienta de apoyo para interpretar tráfico NetFlow, comparar patrones y generar explicaciones técnicas. Sin embargo, las conclusiones propuestas por el LLM no se aceptan automáticamente como válidas.

Para mantener rigor técnico, las hipótesis generadas se contrastan mediante análisis programático sobre ventanas temporales extraídas del dataset.

Este documento diferencia entre:

- hipótesis validadas mediante código
- hipótesis validadas parcialmente
- hipótesis integradas conceptualmente, pero pendientes de validación programática

---

## 2. Relación entre LLM y validación

El proceso seguido es el siguiente:

```text
Ventanas de tráfico → Prompt → Respuesta del LLM → Hipótesis técnica → Validación con código
```

El LLM permite detectar patrones candidatos y formular explicaciones.

El código permite comprobar si esos patrones existen realmente en los datos.

Por tanto, el LLM no actúa como clasificador final, sino como herramienta de análisis e interpretación.

---

## 3. Fuentes utilizadas

Las hipótesis se generaron a partir de:

- perfiles normales de calibración
- ventanas DoS
- ventanas UDP Scan
- ventanas NerisBotnet
- ventanas scan11
- ventanas scan44
- ventanas anomaly-sshscan
- ventana anomaly-spam
- resultados del detector heurístico
- documentos intermedios de análisis

Los documentos relacionados son:

```text
docs/06_analisis_trafico_normal.md
docs/07_analisis_dos.md
docs/08_analisis_udp_scan.md
docs/09_analisis_nerisbotnet.md
docs/10_modelo_comportamiento_sintetico.md
docs/11_validacion_modelo_comportamiento.md
docs/14_analisis_scan11.md
docs/15_analisis_scan44.md
docs/16_analisis_anomaly_sshscan.md
```

---

## 4. Metodología de validación

La validación programática inicial se realizó mediante el script:

```text
scripts/02_attack_analysis/detect_synthetic_behavior.py
```

El script analiza ventanas temporales de flujos NetFlow y calcula métricas agregadas, entre ellas:

- número total de flujos
- IPs origen únicas
- IPs destino únicas
- puertos origen únicos
- puertos destino únicos
- duración media
- paquetes medios
- bytes medios
- varianza de bytes
- varianza de duración
- ratio de duración cercana a cero
- ratio de pocos paquetes
- concentración temporal
- secuencialidad de puertos
- dispersión de destinos
- coordinación distribuida

Los resultados se guardan en:

```text
data/attack_analysis/behavior_detection_results.csv
```

Hasta este punto, la validación programática se ha aplicado principalmente sobre:

- DoS
- UDP Scan
- NerisBotnet
- tráfico normal

Las nuevas categorías `scan11`, `scan44` y `anomaly-sshscan` están integradas conceptualmente, pero todavía requieren adaptación del detector heurístico para su validación formal.

---

## 5. Hipótesis generadas y validación inicial

| Nº | Hipótesis generada por LLM | Evidencia observada | Estado |
|---:|---|---|---|
| 1 | El tráfico normal del ISP presenta diversidad estadística y cicloestacionariedad. | Los perfiles normales muestran diversidad de IPs, puertos, protocolos, duraciones y tamaños. | Validada |
| 2 | El DoS se caracteriza por concentración hacia un único destino y puerto. | Las ventanas DoS presentan grupos TCP concentrados hacia `42.219.158.16:80`. | Validada |
| 3 | El DoS presenta secuencialidad en puertos de origen. | El detector identifica `src_port` secuencial en las tres ventanas DoS. | Validada |
| 4 | El DoS usa flujos de baja duración y baja variabilidad. | En los grupos DoS detectados, `zero_duration_ratio = 1.00` y `bytes_var = 0.00`. | Validada |
| 5 | El UDP Scan se caracteriza por un origen fijo y múltiples destinos. | Las ventanas UDP Scan presentan origen `217.156.59.213:5061` hacia múltiples IPs destino. | Validada |
| 6 | El UDP Scan realiza barrido secuencial de puertos destino. | El detector identifica `dst_port_sequential = True` en las tres ventanas UDP Scan. | Validada |
| 7 | El UDP Scan presenta baja varianza de bytes. | Las ventanas UDP Scan tienen varianza de bytes muy baja, cercana a 2. | Validada |
| 8 | El UDP Scan no debe confundirse con tráfico DNS normal. | Los perfiles normales contienen UDP/DNS, pero no presentan barrido secuencial de puertos destino ni el mismo patrón de dispersión. | Validada |
| 9 | NerisBotnet requiere evidencia de coordinación distribuida hacia un canal C2. | La tercera ventana presenta 20 IPs origen hacia `220.194.21.2:6667/TCP` en el mismo timestamp. | Validada |
| 10 | Las ventanas NerisBotnet con pocos flujos etiquetados no ofrecen evidencia suficiente para clasificación automática. | Las ventanas 1 y 2 contienen pocos flujos `nerisbotnet` y no se clasifican como botnet. | Validada |
| 11 | El tráfico normal no debe clasificarse como ataque si no presenta estructura sintética dominante. | Los perfiles `normal_laboral`, `normal_nocturno` y `normal_transicion` no se clasifican como ataque. | Validada |
| 12 | La etiqueta `blacklist` no debe ser la base del modelo. | El detector no utiliza `blacklist`; clasifica mediante métricas de comportamiento. | Validada |

---

## 6. Hipótesis sobre DoS

### 6.1 Hipótesis planteada

El LLM propuso que el DoS se caracteriza por una generación de flujos sintéticos desde un origen hacia un destino concreto, con puertos origen secuenciales y duración cercana a cero.

### 6.2 Validación

El detector encontró en las tres ventanas DoS grupos TCP con:

- mismo origen
- mismo destino
- mismo puerto destino
- puertos origen secuenciales
- duración cercana a cero
- pocos paquetes por flujo
- varianza de bytes igual a cero

### 6.3 Resultado

La hipótesis queda validada.

El DoS puede modelarse como automatización localizada en el origen.

---

## 7. Hipótesis sobre UDP Scan

### 7.1 Hipótesis planteada

El LLM propuso que el UDP Scan se caracteriza por un origen fijo, un puerto origen fijo, múltiples destinos y barrido secuencial de puertos destino.

### 7.2 Validación

El detector encontró en las tres ventanas UDP Scan:

- origen `217.156.59.213`
- puerto origen `5061`
- múltiples IPs destino
- 30 puertos destino únicos
- secuencialidad de puertos destino
- varianza de bytes muy baja

### 7.3 Resultado

La hipótesis queda validada.

El UDP Scan puede modelarse como automatización localizada en el espacio de destino.

---

## 8. Hipótesis sobre NerisBotnet

### 8.1 Hipótesis planteada

El LLM propuso que NerisBotnet no debe analizarse como un patrón simple de un único origen, sino como una coordinación distribuida entre múltiples nodos.

### 8.2 Validación

El detector identificó en la tercera ventana:

```text
20 IPs origen → 220.194.21.2:6667/TCP
timestamp: 2016-08-01 09:00:15
bytes_var = 0.00
```

Las dos primeras ventanas no fueron clasificadas, ya que no contenían suficiente evidencia de coordinación distribuida.

### 8.3 Resultado

La hipótesis queda validada con matices.

NerisBotnet requiere mayor contexto temporal y distribuido que DoS o UDP Scan.

---

## 9. Hipótesis sobre tráfico normal

### 9.1 Hipótesis planteada

El LLM propuso que el tráfico normal se caracteriza por diversidad, periodicidad y ausencia de estructuras sintéticas dominantes.

### 9.2 Validación

Los perfiles normales no fueron clasificados como ataque por el detector.

Esto indica que el modelo no dispara alertas por la simple existencia de:

- UDP
- puerto 53
- puerto 80
- flujos de baja duración
- tráfico de fondo con ruido

### 9.3 Resultado

La hipótesis queda validada.

La normalidad no se define por una métrica aislada, sino por la ausencia de una estructura sintética clara.

---

## 10. Papel de la etiqueta blacklist

Durante el análisis se observó que algunas ventanas contienen flujos etiquetados como `blacklist`.

Sin embargo, la etiqueta `blacklist` no se utiliza como criterio de detección.

Esto es importante porque el objetivo del trabajo no es detectar tráfico mediante listas negras, sino mediante comportamiento.

El detector clasifica a partir de:

- concentración
- dispersión
- secuencialidad
- baja varianza
- sincronización temporal
- estructura de comunicación

---

## 11. Resultados globales de validación programática inicial

| Tipo de ventana | Ventanas detectadas | Total | Interpretación |
|---|---:|---:|---|
| DoS | 3 | 3 | Patrón validado completamente |
| UDP Scan | 3 | 3 | Patrón validado completamente |
| NerisBotnet | 1 | 3 | Validado cuando existe evidencia C2 suficiente |
| Normal | 0 | 3 | Sin falsos positivos en perfiles normales |

---

## 12. Interpretación técnica inicial

Los resultados muestran que el LLM fue útil para generar hipótesis estructurales sobre el tráfico.

Estas hipótesis no se limitaron a describir etiquetas, sino que permitieron identificar rasgos medibles:

- en DoS, la secuencialidad aparece en los puertos origen
- en UDP Scan, la secuencialidad aparece en los puertos destino
- en NerisBotnet, la anomalía aparece en la sincronización de múltiples nodos
- en tráfico normal, se mantiene diversidad y ausencia de estructura rígida

La validación programática permitió confirmar que estas observaciones eran coherentes con los datos.

---

## 13. Nuevas hipótesis pendientes de validación programática

Tras la primera fase de validación del modelo, se analizaron nuevas familias de ataque mediante LLM:

- `scan11`
- `scan44`
- `anomaly-sshscan`

Estas hipótesis todavía no han sido validadas mediante el detector heurístico, pero se consideran suficientemente estructuradas para incorporarse al modelo conceptual.

---

## 14. Hipótesis sobre scan11

| Hipótesis | Evidencia observada por LLM | Estado |
|---|---|---|
| `scan11` representa un escaneo TCP vertical | Un origen contacta con un único destino recorriendo múltiples puertos | Pendiente de validación programática |
| La automatización se localiza en los servicios del host objetivo | El puerto destino varía de forma amplia mientras el destino permanece fijo | Pendiente de validación programática |
| No debe clasificarse como DoS | Aunque es 1→1, no mantiene un único puerto destino fijo | Pendiente de validación programática |
| Presenta baja entropía | Duración 0.000s, 1 paquete y bytes reducidos | Pendiente de validación programática |

### Interpretación

`scan11` amplía el modelo con la categoría:

```text
Single-Source Vertical Scan
```

Su estructura principal es:

```text
1 origen → 1 destino → muchos puertos
```

El elemento automatizado no es la saturación de un servicio, sino el barrido de servicios de un único host.

---

## 15. Hipótesis sobre scan44

| Hipótesis | Evidencia observada por LLM | Estado |
|---|---|---|
| `scan44` representa un escaneo TCP vertical distribuido | Múltiples orígenes contactan múltiples destinos con muchos puertos por destino | Pendiente de validación programática |
| La automatización se localiza en una red coordinada | Varias IPs origen actúan de forma sincronizada | Pendiente de validación programática |
| Es una variante distribuida de `scan11` | Comparte la lógica de barrido vertical, pero con múltiples actores | Pendiente de validación programática |
| Presenta firma atómica | Duración 0.000s, 1 paquete y bytes reducidos | Pendiente de validación programática |

### Interpretación

`scan44` amplía el modelo con la categoría:

```text
Distributed Vertical Scan
```

Su estructura principal es:

```text
muchos orígenes → muchos destinos → muchos puertos por destino
```

El elemento automatizado aparece tanto en la coordinación de varios orígenes como en el barrido de servicios de múltiples hosts.

---

## 16. Hipótesis sobre anomaly-sshscan

| Hipótesis | Evidencia observada por LLM | Estado |
|---|---|---|
| `anomaly-sshscan` representa un escaneo SSH horizontal | Un origen contacta múltiples destinos manteniendo fijo el puerto 22 | Pendiente de validación programática |
| La automatización se localiza en la selección de IPs destino | El puerto objetivo permanece fijo y lo que cambia son las IPs destino | Pendiente de validación programática |
| No debe confundirse con tráfico SSH legítimo | No hay sesión SSH completa, solo intentos atómicos de 40-44 bytes | Pendiente de validación programática |
| Puede indicar un nodo interno comprometido | El origen pertenece al espacio interno del ISP y escanea hacia el exterior | Hipótesis interpretativa pendiente de validación adicional |

### Interpretación

`anomaly-sshscan` amplía el modelo con la categoría:

```text
SSH Horizontal Scan
```

Su estructura principal es:

```text
1 origen → muchos destinos → puerto fijo 22
```

El elemento automatizado no es el barrido de puertos, sino la selección horizontal de direcciones IP destino manteniendo constante el servicio SSH.

---

## 17. Caso anomaly-spam

Durante la extracción rutinaria de ventanas, `anomaly-spam` presentó baja representatividad.

El script de extracción procesó el fichero completo analizado y solo pudo extraer una ventana:

```text
data/attack_analysis/anomaly-spam/anomaly-spam_window_1.csv
```

Esto se debe a que el número de flujos identificados para `anomaly-spam` es muy reducido en comparación con otras etiquetas de ataque.

### Estado

`anomaly-spam` debe tratarse como caso exploratorio de baja evidencia.

No se utilizará como validación fuerte del modelo hasta disponer de más contexto o de un análisis específico adaptado a una sola ventana.

---

## 18. Síntesis de categorías generadas por LLM

| Ataque | Categoría propuesta | Estado |
|---|---|---|
| DoS | Inundación / automatización en origen | Validado programáticamente |
| UDP Scan | Reconocimiento UDP | Validado programáticamente |
| NerisBotnet | Coordinación distribuida/C2 | Validado parcialmente |
| scan11 | Single-Source Vertical Scan | Pendiente de validación programática |
| scan44 | Distributed Vertical Scan | Pendiente de validación programática |
| anomaly-sshscan | SSH Horizontal Scan | Pendiente de validación programática |
| anomaly-spam | Caso exploratorio | Baja evidencia |

---

## 19. Hipótesis que requieren adaptación del detector

El siguiente paso técnico será adaptar el detector heurístico para medir:

### 19.1 Escaneo vertical de fuente única

Aplicable a `scan11`.

```text
mismo src_ip
mismo dst_ip
muchos dst_port únicos
TCP
duration == 0.000s
packets == 1
bytes ≈ 44
```

### 19.2 Escaneo vertical distribuido

Aplicable a `scan44`.

```text
múltiples src_ip
múltiples dst_ip
muchos dst_port por dst_ip
TCP
duration == 0.000s
packets == 1
sincronización temporal
bytes ≈ 44
```

### 19.3 Escaneo horizontal SSH

Aplicable a `anomaly-sshscan`.

```text
mismo src_ip
múltiples dst_ip
dst_port == 22
TCP
duration == 0.000s
packets == 1
bytes ∈ {40, 44}
```

Estas reglas permitirán transformar la integración conceptual del modelo en validación empírica mediante código.

---

## 20. Limitaciones

La validación presenta varias limitaciones:

- se realiza sobre ventanas previamente extraídas
- no se analiza todavía el dataset completo
- el detector es heurístico
- los umbrales se ajustaron empíricamente
- algunas hipótesis requieren más contexto temporal
- el análisis depende de la representatividad de las ventanas
- el LLM puede generar hipótesis plausibles que deben contrastarse siempre
- las nuevas categorías de escaneo TCP todavía están pendientes de validación programática
- la interpretación de nodo interno comprometido en `anomaly-sshscan` es plausible, pero no debe tratarse como certeza absoluta
- `anomaly-spam` dispone únicamente de una ventana, por lo que su análisis tendrá carácter exploratorio

---

## 21. Conclusión

La validación confirma que los LLMs pueden ser útiles para generar hipótesis interpretables sobre tráfico de red, siempre que dichas hipótesis se contrasten posteriormente mediante análisis programático.

El enfoque seguido permite transformar respuestas cualitativas del LLM en reglas técnicas verificables.

La primera fase de validación confirmó programáticamente los patrones de DoS, UDP Scan y parte de NerisBotnet, además de comprobar que los perfiles normales no eran clasificados como ataque.

Posteriormente, el análisis asistido por LLM permitió ampliar conceptualmente el modelo con nuevas familias de reconocimiento:

- `scan11` como Single-Source Vertical Scan
- `scan44` como Distributed Vertical Scan
- `anomaly-sshscan` como SSH Horizontal Scan

Estas nuevas hipótesis están pendientes de validación programática, pero ya se encuentran formalizadas mediante invariantes estructurales claros.

Esta combinación de LLM y validación empírica constituye el eje metodológico del trabajo.
# Borrador de memoria del TFG

## Título provisional

**Uso de modelos de lenguaje grandes para el análisis explicativo de anomalías en tráfico NetFlow: estudio sobre el dataset UGR'16**

---

# 1. Introducción

## 1.1 Contexto

La detección de anomalías en redes de comunicaciones es un problema relevante dentro del ámbito de la ciberseguridad. Las infraestructuras de red de gran escala, como las pertenecientes a Proveedores de Servicios de Internet (ISP), generan volúmenes masivos de tráfico con una elevada heterogeneidad en protocolos, servicios, usuarios y patrones temporales.

En este contexto, los sistemas de detección de intrusiones deben ser capaces de diferenciar entre tráfico legítimo, ruido de fondo y comportamiento malicioso. Esta tarea resulta especialmente compleja debido a que el tráfico normal no es estático, sino que evoluciona siguiendo patrones temporales asociados a ciclos diarios, laborales y de uso humano.

El dataset UGR'16 proporciona un escenario adecuado para estudiar este problema, ya que contiene tráfico real capturado en un ISP español mediante colectores NetFlow v9, incluyendo tanto tráfico de fondo como ataques sintéticos y anomalías reales.

---

## 1.2 Motivación

En los últimos años, los modelos de lenguaje grandes (LLMs) han mostrado capacidad para interpretar información técnica, generar explicaciones y ayudar en tareas de análisis.

En ciberseguridad, esto abre la posibilidad de utilizar LLMs como herramientas de apoyo para interpretar patrones de tráfico, comparar comportamientos y generar hipótesis técnicas sobre posibles ataques.

Sin embargo, un LLM no debe utilizarse como detector final sin validación. Sus respuestas pueden ser útiles como hipótesis, pero deben contrastarse con evidencia empírica.

Este trabajo parte de esa idea: combinar la capacidad explicativa de los LLMs con validación programática sobre datos reales.

---

## 1.3 Problema

El problema abordado consiste en analizar si un LLM puede ayudar a identificar y explicar patrones de ataques en tráfico NetFlow, y cómo validar posteriormente esas hipótesis con código.

El trabajo no se centra en entrenar un modelo de Machine Learning propio, sino en estudiar el uso de LLMs como herramienta de apoyo al análisis de tráfico de red.

---

## 1.4 Objetivo principal

El objetivo principal del TFG es estudiar el uso de modelos de lenguaje grandes como apoyo al análisis explicativo de anomalías en tráfico NetFlow, utilizando el dataset UGR'16 como caso de estudio.

---

## 1.5 Objetivos específicos

Los objetivos específicos son:

1. Estudiar el dataset UGR'16 y su estructura.
2. Extraer perfiles normales de tráfico a partir del conjunto de calibración.
3. Extraer ventanas temporales de ataques del conjunto de test.
4. Utilizar LLMs para analizar tráfico normal y anómalo.
5. Identificar patrones de comportamiento en ataques DoS, UDP Scan, NerisBotnet, scan11, scan44 y anomaly-sshscan.
6. Formalizar un modelo de comportamiento sintético basado en la localización de la automatización.
7. Implementar un detector heurístico para validar parte de las hipótesis generadas.
8. Documentar ventajas, limitaciones y posibilidades del uso de LLMs en este contexto.

---

## 1.6 Alcance

El trabajo se limita al análisis offline de ventanas temporales extraídas del dataset UGR'16.

No se implementa un IDS en tiempo real ni se entrena un modelo de Machine Learning propio.

El uso de LLMs se plantea como apoyo al análisis, interpretación y generación de hipótesis, no como mecanismo autónomo de clasificación.

---

# 2. Dataset UGR'16

## 2.1 Descripción general

UGR'16 es un dataset de tráfico de red capturado en un ISP español mediante colectores NetFlow v9.

El dataset contiene tráfico de fondo real, ataques sintéticos y anomalías reales. Su diseño permite estudiar tanto el comportamiento normal de una red a gran escala como la aparición de patrones maliciosos.

---

## 2.2 Conjunto de calibración

El conjunto de calibración contiene tráfico de fondo real recogido durante varios meses.

En este trabajo se utiliza para obtener perfiles normales de referencia:

- horario laboral
- horario nocturno
- horario de transición

Estos perfiles permiten caracterizar la normalidad de la red y compararla con ventanas de ataque.

---

## 2.3 Conjunto de test

El conjunto de test contiene tráfico de fondo mezclado con ataques y anomalías.

En este trabajo se han analizado principalmente ataques presentes en la primera semana de agosto.

Los ataques estudiados son:

- DoS
- UDP Scan
- NerisBotnet
- scan11
- scan44
- anomaly-sshscan
- anomaly-spam, como caso exploratorio de baja evidencia

---

## 2.4 Etiquetas identificadas

Durante la exploración del dataset se identificaron distintas etiquetas de ataque, entre ellas:

| Etiqueta | Descripción |
|---|---|
| `dos` | Ataque de Denegación de Servicio |
| `anomaly-udpscan` | Escaneo UDP |
| `nerisbotnet` | Actividad asociada a botnet |
| `scan11` | Escaneo TCP vertical de fuente única |
| `scan44` | Escaneo TCP vertical distribuido |
| `anomaly-spam` | Actividad de spam |
| `anomaly-sshscan` | Escaneo SSH horizontal |
| `blacklist` | Tráfico asociado a listas negras |

La etiqueta `blacklist` no se utiliza como criterio principal de clasificación, ya que el objetivo del trabajo es detectar comportamiento y no depender de listas negras.

---

## 2.5 Importancia de la cicloestacionariedad

El tráfico de una red ISP no es constante. Presenta variaciones asociadas a:

- ciclos día/noche
- horario laboral
- fines de semana
- cambios de actividad humana

Esta propiedad se conoce como cicloestacionariedad.

El análisis de ataques debe tener en cuenta esta característica para no confundir variaciones normales del tráfico con anomalías maliciosas.

---

# 3. Metodología basada en LLMs

## 3.1 Papel del LLM

En este trabajo, el LLM se utiliza como herramienta de apoyo al análisis.

Sus funciones principales son:

- interpretar ventanas de tráfico
- comparar tráfico normal y malicioso
- identificar patrones estructurales
- generar hipótesis técnicas
- ayudar a formalizar reglas de detección
- redactar explicaciones comprensibles

El LLM no se utiliza como clasificador final.

---

## 3.2 Flujo metodológico

El proceso seguido es:

```text
Datos NetFlow → Ventanas temporales → Prompts → Respuesta LLM → Hipótesis → Validación con código
```

Este flujo permite aprovechar la capacidad explicativa del LLM sin renunciar a la validación empírica.

---

## 3.3 Fuentes proporcionadas al LLM

Se proporcionaron al LLM:

- perfiles normales de calibración
- ventanas DoS
- ventanas UDP Scan
- ventanas NerisBotnet
- ventanas scan11
- ventanas scan44
- ventanas anomaly-sshscan
- documentos técnicos intermedios
- contexto resumido del modelo de comportamiento sintético
- resultados del detector heurístico

---

## 3.4 Diseño de prompts

Los prompts se diseñaron para pedir:

- patrones globales
- comparación con tráfico normal
- métricas alteradas
- hipótesis técnicas
- reglas de detección
- revisión crítica de conclusiones
- integración de nuevos ataques en el modelo existente

Se evitó pedir únicamente descripciones línea por línea.

---

## 3.5 Validación de las respuestas del LLM

Las respuestas del LLM se consideran hipótesis técnicas, no resultados definitivos.

Posteriormente, estas hipótesis se contrastan mediante scripts Python que calculan métricas sobre ventanas temporales reales del dataset. Esta validación permite comprobar si los patrones descritos por el LLM son medibles en los datos.

Durante el trabajo se realizaron dos fases de validación:

1. Una primera validación heurística sobre DoS, UDP Scan, NerisBotnet y perfiles normales.
2. Una validación ampliada posterior, basada en los resultados multifuente de NotebookLM y en un detector heurístico extendido implementado con apoyo de Claude Code.

La validación ampliada permitió evaluar las siguientes familias:

* DoS
* UDP Scan
* NerisBotnet
* scan11
* scan44
* anomaly-sshscan
* anomaly-spam

El objetivo de esta validación no fue construir un IDS completo, sino comprobar hasta qué punto las hipótesis generadas mediante LLM podían transformarse en reglas medibles e interpretables sobre ventanas reales.


# 4. Preparación de datos

## 4.1 Extracción de perfiles normales

Se extrajeron perfiles representativos del tráfico normal:

- `normal_laboral.csv`
- `normal_nocturno.csv`
- `normal_transicion.csv`

Estos perfiles se utilizaron como línea base para comparar con los ataques.

---

## 4.2 Extracción de ventanas de ataque

Para cada ataque se extrajeron ventanas temporales alrededor de eventos etiquetados.

Las ventanas incluyen tráfico anterior, tráfico del ataque y tráfico posterior.

Esto permite analizar el contexto del ataque y no solo una fila aislada.

---

## 4.3 Ventanas analizadas

Inicialmente se trabajó con un número reducido de ventanas por ataque para realizar una primera caracterización estructural.

Posteriormente se creó un extractor unificado de ventanas que permitió generar paquetes más amplios por ataque. Estos paquetes incluyeron distintas escalas de contexto:

* ventanas centradas por número de filas
* ventanas temporales de 10 segundos
* resúmenes de ventanas temporales de 60 segundos
* fuentes centradas en trazas de ataque
* contexto metodológico asociado

En la fase de validación ampliada, el detector heurístico extendido se ejecutó sobre un total de 194 ventanas reales almacenadas en `data/attack_analysis/`.

La distribución de ventanas analizadas fue:

| Tipo esperado              | Ventanas |
| -------------------------- | -------: |
| DoS                        |       29 |
| UDP Scan                   |       28 |
| NerisBotnet                |       28 |
| scan11                     |       28 |
| scan44                     |       28 |
| anomaly-sshscan            |       24 |
| anomaly-spam               |       26 |
| normal/background (`none`) |        3 |

---

## 4.4 Caso anomaly-spam

`anomaly-spam` se trata como un caso exploratorio de baja evidencia.

En la primera extracción rutinaria solo se obtuvo una ventana claramente asociada a esta etiqueta, lo que ya indicaba baja representatividad del patrón dentro del subconjunto analizado. En fases posteriores, el extractor unificado generó ventanas adicionales con contexto, pero los resultados del detector ampliado mostraron que el patrón de spam no se validaba de forma robusta.

Por este motivo, `anomaly-spam` no se utiliza como validación fuerte del modelo de comportamiento sintético. Se conserva como caso exploratorio para analizar los límites del enfoque cuando la señal etiquetada es escasa, ruidosa o aparece mezclada con otros comportamientos de fondo.

---

## 4.5 Importancia del contexto

El análisis por ventanas permite observar:

- transición entre tráfico normal y ataque
- mezcla de background y tráfico malicioso
- patrones repetitivos
- concentración o dispersión
- sincronización temporal
- consistencia del etiquetado
- existencia de flujos anteriores o posteriores relacionados

---

# 5. Análisis de tráfico normal

## 5.1 Objetivo

El análisis de tráfico normal permite establecer una línea base de comportamiento del ISP.

---

## 5.2 Resultados principales

El tráfico normal se caracteriza por:

- diversidad de IPs origen y destino
- diversidad de puertos
- mezcla de protocolos
- variabilidad de duración
- variabilidad de bytes
- presencia de servicios estándar como HTTP, HTTPS, DNS, SMTP o NTP
- comportamiento cicloestacionario

---

## 5.3 Perfiles normales

### Perfil laboral

Presenta mayor diversidad y actividad interactiva.

### Perfil nocturno

Presenta menor interactividad humana y mayor presencia de procesos automáticos.

### Perfil de transición

Presenta comportamiento híbrido entre tráfico laboral y tráfico residencial.

---

## 5.4 Conclusión

El tráfico normal mantiene diversidad estadística. Esta diversidad sirve como referencia para identificar ataques sintéticos, que tienden a presentar estructuras más rígidas.

---

# 6. Análisis del ataque DoS

## 6.1 Patrón observado

El ataque DoS observado presenta una estructura:

```text
1 origen → 1 destino
```

Concretamente:

```text
42.219.150.246 → 42.219.158.16:80
```

---

## 6.2 Rasgos principales

Los rasgos identificados son:

- concentración hacia un único destino
- puerto destino fijo
- protocolo TCP
- duración cercana a cero
- baja varianza de bytes
- puertos origen secuenciales
- generación de múltiples flujos de corta duración

---

## 6.3 Interpretación

El DoS se interpreta como una inundación orientada al agotamiento del plano de control del sistema objetivo.

La automatización se localiza en el origen.

---

## 6.4 Validación

El detector heurístico identificó correctamente las tres ventanas DoS.

---

# 7. Análisis del ataque UDP Scan

## 7.1 Patrón observado

El UDP Scan presenta una estructura:

```text
1 origen → muchos destinos
```

El origen observado es:

```text
217.156.59.213:5061
```

---

## 7.2 Rasgos principales

Los rasgos identificados son:

- protocolo UDP
- origen fijo
- puerto origen fijo
- múltiples destinos
- puertos destino secuenciales
- duración cero
- un paquete por flujo
- baja varianza de bytes

---

## 7.3 Interpretación

El UDP Scan se interpreta como una estrategia de reconocimiento automatizado.

La automatización se localiza en el espacio de destino.

---

## 7.4 Validación

El detector heurístico identificó correctamente las tres ventanas UDP Scan.

---

# 8. Análisis de NerisBotnet

## 8.1 Patrón observado

NerisBotnet presenta un comportamiento distribuido y más complejo que DoS o UDP Scan.

Puede adoptar estructuras:

```text
1 origen → muchos destinos
```

y:

```text
muchos orígenes → 1 destino
```

---

## 8.2 Rasgos principales

Los rasgos identificados son:

- múltiples nodos implicados
- posible comunicación C2
- sincronización temporal
- puerto 6667 asociado a IRC/C2
- métricas homogéneas entre nodos
- comportamiento colectivo

---

## 8.3 Evidencia principal

La evidencia más clara aparece en la tercera ventana:

```text
20 IPs origen → 220.194.21.2:6667/TCP
```

---

## 8.4 Interpretación

NerisBotnet se interpreta como automatización distribuida en red.

La anomalía no reside en un único flujo, sino en la coordinación de múltiples nodos.

---

## 8.5 Validación

El detector identificó NerisBotnet en una de las tres ventanas, concretamente cuando existía evidencia suficiente de coordinación C2.

---

# 9. Nuevas familias de reconocimiento analizadas

Tras la primera fase de análisis, centrada en DoS, UDP Scan y NerisBotnet, se amplió el estudio a nuevas etiquetas de ataque del dataset UGR'16:

- `scan11`
- `scan44`
- `anomaly-sshscan`
- `anomaly-spam`

El objetivo de esta ampliación fue comprobar si el modelo de comportamiento sintético podía generalizarse a nuevas formas de reconocimiento y no limitarse a los primeros ataques estudiados.

---

## 9.1 scan11: Single-Source Vertical Scan

El ataque `scan11` se caracteriza como un escaneo TCP vertical de fuente única.

Su patrón estructural es:

```text
1 origen → 1 destino → muchos puertos
```

A diferencia de un DoS, aunque la topología también es 1→1, el objetivo no es saturar un servicio concreto, sino recorrer múltiples puertos de un único host para identificar servicios disponibles.

La automatización se localiza en el barrido vertical de servicios del host objetivo.

### Rasgos principales

- protocolo TCP
- un único origen
- un único destino
- múltiples puertos destino
- duración 0.000s
- un paquete por flujo
- bytes reducidos, aproximadamente 44 bytes
- predominio de intentos TCP incompletos
- comportamiento de reconocimiento

---

## 9.2 scan44: Distributed Vertical Scan

El ataque `scan44` representa una variante distribuida del escaneo TCP vertical.

Su patrón estructural es:

```text
muchos orígenes → muchos destinos → muchos puertos por destino
```

A diferencia de `scan11`, el reconocimiento no procede de un único origen, sino de varios nodos coordinados que ejecutan barridos verticales sobre varios hosts.

La automatización se localiza tanto en la coordinación de los orígenes como en el barrido de servicios de los destinos.

### Rasgos principales

- protocolo TCP
- múltiples IPs origen
- múltiples IPs destino
- múltiples puertos destino por host
- duración 0.000s
- un paquete por flujo
- bytes reducidos
- sincronización temporal
- comportamiento de reconocimiento distribuido

---

## 9.3 anomaly-sshscan: SSH Horizontal Scan

El ataque `anomaly-sshscan` representa un escaneo TCP horizontal especializado en SSH.

Su patrón estructural es:

```text
1 origen → muchos destinos → puerto fijo 22
```

A diferencia de los escaneos verticales, aquí no se recorren múltiples puertos de un host, sino múltiples direcciones IP manteniendo fijo el servicio objetivo.

La automatización se localiza en la selección del espacio de direcciones destino.

### Rasgos principales

- protocolo TCP
- mismo origen
- múltiples destinos externos
- puerto destino fijo 22
- duración 0.000s
- un paquete por flujo
- bytes entre 40 y 44
- ausencia de sesiones SSH completas
- posible comportamiento de nodo interno comprometido

---

## 9.4 anomaly-spam: caso exploratorio

Durante la extracción de ventanas temporales, `anomaly-spam` presentó baja representatividad.

Solo se pudo extraer una ventana:

```text
data/attack_analysis/anomaly-spam/anomaly-spam_window_1.csv
```

Por este motivo, `anomaly-spam` se considera un caso exploratorio de baja evidencia y no se utiliza como validación fuerte del modelo.

---

## 9.5 Ampliación del modelo

Con estas nuevas familias, el modelo de comportamiento sintético queda ampliado de la siguiente forma:

| Ataque | Categoría | Localización de la automatización |
|---|---|---|
| DoS | Inundación | Origen |
| UDP Scan | Reconocimiento UDP | Espacio de destino/red |
| scan11 | Single-Source Vertical Scan | Servicios del host objetivo |
| scan44 | Distributed Vertical Scan | Red coordinada + servicios destino |
| anomaly-sshscan | SSH Horizontal Scan | Selección de IPs destino |
| NerisBotnet | Botnet/C2 | Red distribuida/C2 |

Esta ampliación demuestra que el enfoque basado en LLMs permite generar nuevas hipótesis estructurales a medida que se analizan nuevas ventanas de ataque.

Posteriormente, estas nuevas categorías fueron incorporadas a un detector heurístico ampliado. Los resultados mostraron una validación sólida para `scan11` y `scan44`, mientras que `anomaly-sshscan` presentó una validación más limitada debido a su naturaleza low-and-slow y a su baja densidad temporal.

---

# 10. Modelo de comportamiento sintético

## 10.1 Concepto

El tráfico sintético se define como tráfico generado por herramientas automatizadas que rompe la diversidad estadística del tráfico normal.

---

## 10.2 Pipeline jerárquico

El modelo se divide en tres fases:

1. Detección de anomalía sintética.
2. Análisis estructural.
3. Clasificación del comportamiento.

---

## 10.3 Localización de la automatización

La clave del modelo es identificar dónde aparece la automatización:

| Ataque | Localización de la automatización |
|---|---|
| DoS | Origen |
| UDP Scan | Espacio de destino/red |
| scan11 | Servicios del host objetivo |
| scan44 | Red coordinada + servicios destino |
| anomaly-sshscan | Selección de IPs destino |
| NerisBotnet | Red distribuida/C2 |

---

## 10.4 Tabla comparativa

| Característica | DoS | UDP Scan | scan11 | scan44 | anomaly-sshscan | NerisBotnet |
|---|---|---|---|---|---|---|
| Categoría | Inundación | Reconocimiento UDP | Single-Source Vertical Scan | Distributed Vertical Scan | SSH Horizontal Scan | Botnet/C2 |
| Topología | 1 → 1 | 1 → muchos | 1 → 1 | Muchos → Muchos | 1 → muchos | Muchos → 1 / híbrida |
| Objetivo | Saturación | Reconocimiento de red | Reconocimiento de servicios en un host | Reconocimiento distribuido de servicios | Búsqueda de SSH expuesto | Coordinación |
| Automatización | Origen | Espacio de destino/red | Servicios del host objetivo | Red coordinada + servicios destino | Selección de IPs destino | Red distribuida |
| Protocolo | TCP | UDP | TCP | TCP | TCP | TCP/UDP |
| Puerto destino | Fijo | Secuencial | Muchos | Muchos por destino | Fijo: 22 | C2 fijo |
| Rasgo clave | `src_port` secuencial | `dst_port` secuencial | muchos puertos en un host | coordinación + barrido vertical | muchas IPs hacia 22 | sincronización hacia C2 |

---

# 11. Validación experimental

## 11.1 Validación inicial

En una primera fase se implementó un detector heurístico para validar las hipótesis generadas sobre DoS, UDP Scan y NerisBotnet.

El script utilizado fue:

```text
scripts/02_attack_analysis/detect_synthetic_behavior.py
```

Los resultados iniciales fueron:

| Tipo de ventana | Detectadas | Total |
| --------------- | ---------: | ----: |
| DoS             |          3 |     3 |
| UDP Scan        |          3 |     3 |
| NerisBotnet     |          1 |     3 |
| Normal          |          0 |     3 |

Esta primera validación confirmó que DoS y UDP Scan presentaban patrones sintéticos muy claros y medibles. NerisBotnet, en cambio, requería mayor contexto distribuido y temporal.

---

## 11.2 Validación ampliada

Tras ampliar el análisis con nuevas familias de ataque y generar resultados multifuente con NotebookLM, se creó una especificación técnica para implementar un detector heurístico ampliado.

El script utilizado fue:

```text
scripts/02_attack_analysis/detect_synthetic_behavior_extended.py
```

El archivo de salida generado fue:

```text
data/attack_analysis/behavior_detection_results_extended.csv
```

Este detector se ejecutó sobre 194 ventanas reales y generó 34 columnas de resultados, incluyendo métricas generales, categoría esperada, categoría detectada, nivel de confianza, evidencias y limitaciones.

El detector no utiliza la etiqueta como criterio de detección. La etiqueta se conserva únicamente para comparar posteriormente la predicción con el tipo de ventana esperado.

---

## 11.3 Distribución de ventanas analizadas

| Etiqueta esperada | Ventanas |
| ----------------- | -------: |
| `dos`             |       29 |
| `anomaly-udpscan` |       28 |
| `nerisbotnet`     |       28 |
| `scan11`          |       28 |
| `scan44`          |       28 |
| `anomaly-spam`    |       26 |
| `anomaly-sshscan` |       24 |
| `none`            |        3 |

---

## 11.4 Resultados globales del detector ampliado

| Categoría detectada                         | Ventanas |
| ------------------------------------------- | -------: |
| Distributed TCP Flood / TCP DoS             |       35 |
| Single-Source Vertical Scan                 |       35 |
| Distributed Vertical Scan                   |       30 |
| No clasificado                              |       27 |
| UDP Hybrid Scan / UDP Low-Entropy Scan      |       25 |
| Botnet multivector / Distributed C2         |       21 |
| Low-and-Slow SSH Horizontal Scan            |       15 |
| SMTP Spam Burst / Low-Entropy SMTP Campaign |        6 |

---

## 11.5 Aciertos por familia

| Ataque esperado   | Aciertos | Total | Tasa aproximada |
| ----------------- | -------: | ----: | --------------: |
| `scan11`          |       24 |    28 |           85.7% |
| `anomaly-udpscan` |       22 |    28 |           78.6% |
| `scan44`          |       21 |    28 |           75.0% |
| `dos`             |       14 |    29 |           48.3% |
| `nerisbotnet`     |       13 |    28 |           46.4% |
| `anomaly-sshscan` |        5 |    24 |           20.8% |
| `anomaly-spam`    |        0 |    26 |            0.0% |
| `none`            |        0 |     3 |            0.0% |

---

## 11.6 Interpretación de la validación ampliada

Los resultados muestran que el detector ampliado valida con mayor claridad los ataques que presentan patrones estructurales fuertes y de baja entropía.

Las mejores tasas de validación se observan en:

* `scan11`
* `anomaly-udpscan`
* `scan44`

Esto confirma que los escaneos estructurados son especialmente adecuados para un enfoque basado en comportamiento, ya que presentan invariantes medibles como baja duración, pocos paquetes, baja varianza de bytes, secuencialidad de puertos o alta concentración temporal.

El caso `dos` queda validado parcialmente. Algunas ventanas esperadas como DoS se clasifican como escaneo distribuido, lo que indica una posible confusión estructural entre patrones de concentración e indicios de dispersión de puertos u orígenes dentro de determinadas ventanas.

`nerisbotnet` también queda validado parcialmente. Este resultado es coherente con la naturaleza del ataque, ya que la señal de botnet no reside necesariamente en un único flujo, sino en la correlación temporal entre múltiples nodos.

`anomaly-sshscan` obtiene una validación limitada. Esto se debe a que se trata de un patrón low-and-slow, de bajo volumen y baja densidad temporal. En este tipo de ataque, la ausencia de clasificación en varias ventanas no implica necesariamente ausencia de comportamiento anómalo, sino insuficiencia de evidencia dentro de la ventana concreta.

`anomaly-spam` no se valida como categoría robusta en esta fase. Sus ventanas se clasifican frecuentemente como otros comportamientos o como no clasificadas. Por tanto, se mantiene como caso exploratorio de baja evidencia.

Finalmente, las ventanas `none` o background no deben interpretarse únicamente como falsos positivos simples. El tráfico real de una red ISP puede contener ruido automatizado o escaneos de fondo no etiquetados, por lo que la detección de comportamiento sintético en estas ventanas debe analizarse con cautela.

---

## 11.7 Clasificación contextual por traza

La indicación del profesor fue clara: el objetivo último no es clasificar ventanas completas, sino **detectar trazas concretas de ataque**. El detector por ventana validaba hipótesis globales por familia, pero asignaba una única etiqueta a toda la ventana y no permitía decir si **un flujo concreto** era malicioso.

El reto es que **una traza NetFlow aislada no siempre contiene información suficiente**: muchos ataques solo emergen del patrón que forman varias trazas juntas (barridos de puertos, ráfagas, dispersión de destinos, coordinación entre nodos). Por ello la clasificación por traza se apoya en el comportamiento de su **contexto local** y, en la versión final, también en un **contexto global/temporal** por ventana.

### Evolución de las versiones

1. **Detector por ventana.** Útil para validar hipótesis, insuficiente para clasificar trazas.
2. **v1 contextual (contexto local, ±30 filas).** Primer clasificador por traza; mezclaba errores de subtipo (scan44 etiquetado como scan11) con fuga real a background.
3. **v2 jerárquico.** Separa **ataque/background → familia conductual → subtipo**, con `insufficient_evidence`, `unknown_attack` y subtipo con incertidumbre. Eleva la detección binaria por traza.
4. **v3 con pase global/temporal.** Mantiene la jerarquía de v2 y añade un segundo pase por ventana que resuelve el subtipo scan11/scan44, confirma campañas UDP, detecta sshscan por persistencia de origen y la coordinación de botnet por buckets temporales.

### Por qué se adopta v3

Se adopta la **v3** como clasificador contextual por traza de referencia porque clasifica trazas concretas combinando contexto local y global, mantiene el recall binario, mejora la separación de subtipos estructurados y reduce los falsos positivos, sin usar IPs concretas ni etiquetas como criterio de detección y conservando la evidencia interpretable por traza.

### Resultados principales de v3

- Precisión binaria de ataque: **0,930**.
- Recall binario de ataque: **0,991**.
- `scan44` — recall: **0,796** (frente a 0,015 en v2).
- `scan11` — precisión: **0,763** (frente a 0,194 en v2).
- `udp_scan` — recall: **aproximadamente 1,00**.
- Falsos positivos de `sshscan`: **60** (frente a 8.248 en v2).
- `unknown_attack`: **118.264 trazas** (frente a 345.065 en v2).

### Limitaciones

- La precisión binaria baja de 0,961 (v2) a **0,930** (v3), en parte por escaneos UDP reales presentes en el background.
- `coordinated_botnet` por el camino no-C2 tiene baja precisión y se trata como **señal exploratoria** de baja confianza.
- `anomaly-sshscan` sigue **sin validación fuerte** como subtipo (patrón low-and-slow).
- `anomaly-spam` se mantiene como **caso de baja evidencia**.
- La evaluación puede estar afectada por el solapamiento de ventanas y trazas duplicadas.

### Por qué no se sigue ajustando el clasificador

El desarrollo se detiene en la v3 de forma deliberada para **evitar el sobreajuste**. Seguir ajustando umbrales o reintroducir firmas exactas (puertos o bytes concretos del dataset) subiría artificialmente las métricas frente a las etiquetas, pero ataría el clasificador al ruido específico de este conjunto de datos y reduciría su generalización e interpretabilidad. La clasificación por traza queda, por tanto, resuelta como resultado del trabajo, con sus limitaciones explícitas.

---

# 12. Discusión

## 12.1 Utilidad de los LLMs

Los LLMs resultaron útiles para:

* interpretar patrones complejos
* comparar tráfico normal y anómalo
* generar hipótesis técnicas
* formalizar modelos de comportamiento
* redactar explicaciones comprensibles
* ampliar el modelo a nuevas familias de ataque
* preparar especificaciones técnicas para validación programática

Su utilidad principal no reside en clasificar directamente el tráfico, sino en ayudar a construir una explicación estructurada del comportamiento observado.

---

## 12.2 Necesidad de validación

Las respuestas del LLM no deben aceptarse automáticamente.

La validación con código es necesaria para evitar:

* sobreinterpretaciones
* afirmaciones no demostradas
* dependencia excesiva del lenguaje natural
* errores por falta de contexto
* confusión entre etiqueta y comportamiento real
* generalización indebida a partir de pocas ventanas

La metodología seguida permite transformar respuestas cualitativas del LLM en hipótesis técnicas verificables.

---

## 12.3 Papel del detector heurístico

El detector heurístico no es un IDS final.

Su función es comprobar si los patrones propuestos por el LLM son medibles en los datos.

El detector ampliado permitió validar de forma sólida los patrones de escaneo estructurado, especialmente `scan11`, `scan44` y `anomaly-udpscan`.

En cambio, los patrones distribuidos, de baja densidad temporal o con baja evidencia, como `nerisbotnet`, `anomaly-sshscan` y `anomaly-spam`, requieren mayor contexto, correlación temporal o análisis más específico.

---

## 12.4 Uso de Claude Code

Claude Code se utilizó como herramienta de apoyo para implementar el detector heurístico ampliado a partir de una especificación técnica previamente generada.

El proceso seguido fue:

```text
Resultados NotebookLM → especificación técnica → implementación con Claude Code → ejecución sobre ventanas reales → CSV de resultados → análisis de validación
```

Claude Code no sustituyó el análisis técnico. Su función fue ayudar a transformar una especificación estructurada en código Python modular y ejecutable.

---

# 13. Limitaciones

Las principales limitaciones del trabajo son:

* el análisis se realiza sobre ventanas previamente extraídas
* no se ejecuta el detector sobre el dataset completo
* el detector es heurístico
* los umbrales se ajustan empíricamente
* no se entrena un modelo de Machine Learning propio
* el sistema no constituye un IDS en tiempo real
* la calidad del análisis depende del diseño de los prompts
* las respuestas del LLM pueden contener sobreinterpretaciones
* algunas ventanas contienen mezcla de background y ataque
* el tráfico normal real puede contener ruido automatizado o escaneos de fondo
* la detección de botnets requiere correlación distribuida y mayor contexto temporal
* la detección de patrones low-and-slow, como `anomaly-sshscan`, no puede depender solo de volumen
* `anomaly-spam` presenta baja evidencia y no debe utilizarse como validación fuerte del modelo

---

# 14. Trabajo futuro

Como trabajo futuro se propone:

1. Aplicar el detector ampliado a más ventanas y, si es viable, a segmentos mayores del dataset.
2. Evaluar distintas configuraciones de umbrales para estudiar la sensibilidad del detector.
3. Analizar con más detalle las confusiones entre DoS y escaneos distribuidos.
4. Mejorar la detección de botnets mediante ventanas temporales más amplias y correlación entre nodos.
5. Diseñar una estrategia específica para patrones low-and-slow como `anomaly-sshscan`.
6. Mantener `anomaly-spam` como caso exploratorio o buscar más muestras representativas antes de utilizarlo como validación fuerte.
7. Comparar los resultados obtenidos con diferentes LLMs.
8. Automatizar en mayor medida el pipeline de análisis asistido por LLM.
9. Explorar visualizaciones interactivas de los patrones detectados para facilitar la interpretación.
10. Estudiar cómo separar mejor tráfico normal con ruido automatizado de comportamiento malicioso confirmado.

---

# 15. Conclusiones

El trabajo demuestra que los LLMs pueden ser útiles como herramientas de apoyo al análisis de tráfico de red, especialmente para interpretar patrones, generar hipótesis explicables y organizar comportamientos maliciosos según sus invariantes estructurales.

Sin embargo, su uso debe estar acompañado de validación empírica. En este trabajo, las respuestas del LLM se han tratado como hipótesis técnicas que posteriormente se han contrastado mediante detectores heurísticos implementados en Python.

El enfoque combinado permite transformar respuestas cualitativas del LLM en reglas técnicas verificables.

Los ataques analizados muestran que la automatización puede localizarse en distintos niveles:

* en el origen, como en DoS
* en el espacio de destino/red, como en UDP Scan
* en los servicios de un host, como en scan11
* en la coordinación de escaneos distribuidos, como en scan44
* en la selección horizontal de IPs destino, como en anomaly-sshscan
* en la red distribuida orientada a C2, como en NerisBotnet

La validación ampliada muestra que los patrones de escaneo estructurado son los más robustos para este enfoque. En particular, `scan11`, `scan44` y `anomaly-udpscan` presentan resultados sólidos. En cambio, ataques distribuidos, low-and-slow o con baja evidencia, como `nerisbotnet`, `anomaly-sshscan` y `anomaly-spam`, requieren mayor cautela y contexto adicional.

Este enfoque aporta una visión explicable del comportamiento malicioso en tráfico NetFlow y permite organizar los ataques según sus patrones de automatización, no únicamente según su etiqueta.


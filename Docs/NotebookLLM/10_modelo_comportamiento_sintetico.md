# Modelo de comportamiento sintético en redes ISP

## 1. Objetivo

El objetivo de este documento es integrar los patrones observados en los ataques DoS, UDP Scan, scan11, scan44, anomaly-sshscan y NerisBotnet dentro de un único modelo de comportamiento sintético.

El modelo no pretende ser un IDS completo, sino una formalización técnica de los patrones identificados mediante LLMs y validados posteriormente con código o análisis estructural.

La idea principal es que los ataques analizados no se diferencian únicamente por sus etiquetas, sino por la localización de su estructura de automatización.

---

## 2. Punto de partida: tráfico normal

El tráfico normal del dataset UGR'16 se caracteriza por:

- diversidad de IPs origen y destino
- diversidad de puertos
- mezcla de protocolos
- variabilidad en duración
- variabilidad en bytes y paquetes
- comportamiento cicloestacionario
- ausencia de estructuras repetitivas dominantes

Esta diversidad es propia de una red ISP real, donde múltiples usuarios y servicios generan tráfico de forma heterogénea.

El tráfico normal puede contener flujos breves, tráfico UDP, conexiones TCP incompletas o ruido de fondo. Por tanto, una única métrica aislada no basta para clasificar una ventana como ataque. La detección debe basarse en combinaciones estructurales de métricas.

---

## 3. Concepto de tráfico sintético

En este trabajo se denomina tráfico sintético al tráfico generado por herramientas automatizadas de ataque o reconocimiento.

Este tráfico tiende a romper la diversidad del tráfico normal mediante patrones como:

- baja duración
- baja varianza de bytes
- pocos paquetes por flujo
- ráfagas temporales
- secuencialidad de puertos
- concentración hacia un objetivo
- dispersión sistemática hacia múltiples destinos
- sincronización entre nodos
- predominio de flags de control
- ausencia de transferencia real de datos

El tráfico sintético no siempre implica gran volumen de datos. En muchos casos, su peligrosidad reside en la repetición estructurada y automatizada de flujos pequeños.

---

## 4. Pipeline jerárquico de detección

El modelo propuesto se organiza en tres fases.

---

### 4.1 Fase 1: Detección de anomalía sintética

La primera fase identifica ventanas o grupos de flujos que presentan características no interactivas.

Criterios principales:

- duración cercana a cero
- pocos paquetes por flujo
- baja varianza en bytes
- alta densidad temporal
- repetición de métricas similares
- ráfagas con muchos flujos en el mismo timestamp o intervalo reducido

Esta fase no clasifica todavía el tipo de ataque. Solo identifica posible tráfico automatizado.

---

### 4.2 Fase 2: Análisis estructural

La segunda fase analiza cómo se distribuye el tráfico dentro de la ventana.

Se estudian:

- número de IPs origen
- número de IPs destino
- puertos origen únicos
- puertos destino únicos
- secuencialidad de puertos
- concentración o dispersión
- sincronización temporal
- relación entre orígenes y destinos
- si los puertos barridos pertenecen a un único host o a múltiples hosts
- si el patrón mantiene fijo un puerto de servicio y varía las IPs destino

Esta fase permite distinguir si la automatización aparece en:

- el origen
- el espacio de destino
- los servicios de un host objetivo
- la selección horizontal de IPs destino
- la red distribuida

---

### 4.3 Fase 3: Clasificación del comportamiento

La tercera fase clasifica el comportamiento según la estructura observada:

```text
Concentración 1→1 + src_port secuencial + dst_port fijo → DoS

Dispersión 1→muchos + UDP + dst_port secuencial → UDP Scan

1→1 + TCP + muchos dst_port por un mismo host → Single-Source Vertical Scan

Muchos→Muchos + TCP + muchos dst_port por destino + sincronización → Distributed Vertical Scan

1→muchos + TCP + dst_port fijo 22 + muchos dst_ip → SSH Horizontal Scan

Muchos→1 sincronizado + puerto C2 → NerisBotnet
```

Esta clasificación no depende de IPs concretas, sino de patrones estructurales.

---

## 5. Modelo DoS

El ataque DoS se caracteriza por una concentración de flujos hacia un único destino y un único servicio.

### 5.1 Topología

```text
1 origen → 1 destino:puerto fijo
```

### 5.2 Automatización

La automatización se localiza en el origen.

El atacante genera múltiples flujos hacia el mismo objetivo utilizando puertos origen secuenciales.

### 5.3 Indicadores principales

- mismo `src_ip`
- mismo `dst_ip`
- mismo `dst_port`
- protocolo TCP
- duración cercana a cero
- pocos paquetes por flujo
- puertos origen secuenciales
- baja varianza de bytes
- concentración temporal

### 5.4 Interpretación

El ataque busca agotar recursos de control o gestión de conexiones del sistema objetivo mediante la generación de múltiples flujos de corta duración.

La finalidad principal no es reconocer servicios, sino saturar o degradar un objetivo concreto.

---

## 6. Modelo UDP Scan

El ataque UDP Scan se caracteriza por la exploración sistemática de múltiples destinos y puertos mediante UDP.

### 6.1 Topología

```text
1 origen → muchos destinos
```

### 6.2 Automatización

La automatización se localiza en el espacio de destino.

El atacante mantiene un origen estable y explora puertos destino de forma secuencial sobre múltiples IPs.

### 6.3 Indicadores principales

- mismo `src_ip`
- mismo `src_port`
- protocolo UDP
- múltiples `dst_ip`
- múltiples `dst_port`
- puertos destino secuenciales
- duración cercana a cero
- un paquete por flujo
- baja varianza de bytes

### 6.4 Interpretación

El ataque busca mapear servicios activos o puertos abiertos mediante una estrategia de reconocimiento automatizada.

Se diferencia del tráfico UDP normal, como DNS, porque presenta barrido secuencial de puertos, dispersión sistemática y baja varianza de carga.

---

## 7. Familia TCP Vertical Scan

Los ataques `scan11` y `scan44` amplían el modelo inicial con una nueva familia de reconocimiento: el escaneo TCP vertical.

Esta familia no busca saturar un servicio, sino explorar qué puertos o servicios están disponibles en uno o varios hosts objetivo.

---

### 7.1 Concepto general

Un TCP Vertical Scan se caracteriza por:

```text
origen/es → destino/s → muchos puertos por destino
```

El rasgo clave es el barrido de puertos destino mediante flujos TCP atómicos.

### 7.2 Indicadores generales

- protocolo TCP
- duración cercana a cero
- un paquete por flujo
- bytes reducidos, normalmente alrededor de 44 bytes en SYN
- predominio de flags SYN
- ausencia de transferencia real de datos
- muchos puertos destino únicos
- secuencialidad o alta diversidad de puertos destino
- concentración temporal

---

## 8. Modelo scan11: Single-Source Vertical Scan

`scan11` representa un escaneo TCP vertical de fuente única.

### 8.1 Topología

```text
1 origen → 1 destino → muchos puertos
```

### 8.2 Automatización

La automatización se localiza en el espacio de servicios del host objetivo.

El atacante ya tiene seleccionado un host y realiza un barrido exhaustivo de sus puertos.

### 8.3 Indicadores principales

- mismo `src_ip`
- mismo `dst_ip`
- protocolo TCP
- muchos `dst_port`
- puertos destino secuenciales o altamente diversos
- duración `0.000s`
- `packets == 1`
- bytes alrededor de `44`
- predominio de SYN
- ráfagas temporales

### 8.4 Interpretación

`scan11` busca mapear la superficie de exposición de un único host.

Aunque comparte topología 1→1 con DoS, no debe clasificarse como DoS porque el puerto destino no es fijo. El objetivo no es saturar un servicio, sino enumerar servicios disponibles.

---

## 9. Modelo scan44: Distributed Vertical Scan

`scan44` representa una variante distribuida y coordinada del escaneo TCP vertical.

### 9.1 Topología

```text
muchos orígenes → muchos destinos → muchos puertos por destino
```

### 9.2 Automatización

La automatización se localiza en la red coordinada y en el espacio de servicios de los hosts objetivo.

Varios orígenes ejecutan escaneos verticales sincronizados contra varios destinos.

### 9.3 Indicadores principales

- múltiples `src_ip`
- múltiples `dst_ip`
- protocolo TCP
- muchos `dst_port` por cada destino
- duración `0.000s`
- `packets == 1`
- bytes alrededor de `44`
- predominio de SYN
- respuestas RST-ACK en algunos casos
- sincronización temporal
- posible pertenencia de orígenes a una misma subred
- barrido vertical coordinado

### 9.4 Interpretación

`scan44` busca mapear varios hosts de forma paralela.

Es una evolución del escaneo vertical simple: mantiene la lógica de reconocimiento de servicios, pero añade coordinación distribuida entre varios orígenes y varios destinos.

---

## 10. Modelo anomaly-sshscan: SSH Horizontal Scan

`anomaly-sshscan` representa un escaneo TCP horizontal especializado en el servicio SSH.

A diferencia de los escaneos verticales, donde se recorren muchos puertos de uno o varios hosts, en `anomaly-sshscan` el puerto objetivo se mantiene fijo y lo que varía es el conjunto de IPs destino.

---

### 10.1 Topología

```text
1 origen → muchos destinos → puerto fijo 22
```

### 10.2 Automatización

La automatización se localiza en la selección del espacio de direcciones destino.

El atacante mantiene fijo el servicio objetivo, SSH, y genera múltiples intentos hacia diferentes IPs externas.

### 10.3 Indicadores principales

- mismo `src_ip`
- múltiples `dst_ip`
- protocolo TCP
- `dst_port == 22`
- duración `0.000s`
- `packets == 1`
- bytes entre `40` y `44`
- flags de control TCP
- ausencia de sesiones SSH completas
- alta dispersión de destinos
- concentración temporal

### 10.4 Interpretación

`anomaly-sshscan` busca localizar hosts con SSH accesible.

La dirección del tráfico es especialmente relevante porque el origen observado pertenece al espacio interno del ISP. Esto sugiere que puede tratarse de un nodo interno comprometido realizando exploración hacia el exterior.

No debe confundirse con tráfico SSH legítimo, ya que una sesión SSH real presenta establecimiento de conexión, intercambio de claves, múltiples paquetes, duración superior a cero y tráfico bidireccional.

---

## 11. Modelo NerisBotnet

NerisBotnet se caracteriza por coordinación distribuida entre múltiples nodos.

### 11.1 Topología

Puede presentar estructuras híbridas:

```text
1 origen → muchos destinos
```

y también:

```text
muchos orígenes → 1 destino
```

### 11.2 Automatización

La automatización se localiza en la red.

El patrón no aparece únicamente en un flujo individual, sino en la coordinación temporal entre múltiples nodos.

### 11.3 Indicadores principales

- múltiples `src_ip`
- mismo `dst_ip`
- mismo `dst_port`
- mismo protocolo
- sincronización temporal
- puerto asociado a C2
- baja varianza de bytes dentro del grupo
- métricas homogéneas entre nodos

### 11.4 Interpretación

El comportamiento es compatible con coordinación mediante Command & Control, donde múltiples nodos actúan como una única entidad lógica.

A diferencia de `scan44`, cuyo objetivo es reconocimiento de servicios, NerisBotnet se orienta a coordinación operativa o comunicación C2.

---

## 12. Tabla comparativa

| Característica | DoS | UDP Scan | scan11 | scan44 | anomaly-sshscan | NerisBotnet |
|---|---|---|---|---|---|---|
| Categoría | Inundación | Reconocimiento UDP | Single-Source Vertical Scan | Distributed Vertical Scan | SSH Horizontal Scan | Botnet/C2 |
| Topología | 1 → 1 | 1 → muchos | 1 → 1 | Muchos → Muchos | 1 → muchos | Muchos → 1 / híbrida |
| Objetivo | Saturación | Reconocimiento de red | Reconocimiento de servicios en un host | Reconocimiento distribuido de servicios | Búsqueda de SSH expuesto | Coordinación |
| Automatización | Origen | Espacio de destino/red | Servicios del host objetivo | Red coordinada + servicios destino | Selección de IPs destino | Red distribuida |
| Protocolo dominante | TCP | UDP | TCP | TCP | TCP | TCP/UDP |
| Puerto origen | Secuencial | Fijo | Variable/estable por ráfagas | Fijo por ráfaga | Efímero/variable | Variable |
| Puerto destino | Fijo | Secuencial | Muchos, vertical | Muchos por destino | Fijo: 22 | C2 fijo |
| Duración | ≈ 0.000s | ≈ 0.000s | 0.000s | 0.000s | 0.000s | Variable por fase |
| Paquetes | Bajo | 1 | 1 | 1 | 1 | Variable por fase |
| Bytes | Muy baja varianza | ~433B | ~44B | ~44B / 40B respuestas | 40-44B | Baja en grupos C2 |
| Rasgo clave | `src_port` secuencial | `dst_port` secuencial sobre red | muchos `dst_port` en un host | coordinación + muchos `dst_port` por host | muchos `dst_ip` hacia puerto 22 | sincronización hacia C2 |

---

## 13. Localización de la automatización

La aportación principal del modelo es clasificar los ataques según dónde aparece la automatización.

---

### 13.1 Automatización en el origen

Propia del DoS.

El atacante manipula el origen del tráfico generando múltiples flujos hacia un mismo destino y servicio.

---

### 13.2 Automatización en el espacio de destino/red

Propia del UDP Scan.

El atacante estructura la exploración de múltiples destinos y puertos, normalmente con un origen estable.

---

### 13.3 Automatización en los servicios del host objetivo

Propia de `scan11`.

El atacante selecciona un host concreto y recorre múltiples puertos para descubrir servicios expuestos.

---

### 13.4 Automatización en red coordinada

Propia de `scan44`.

La anomalía aparece en la coordinación de varios orígenes que ejecutan escaneos verticales simultáneos sobre varios hosts.

---

### 13.5 Automatización en la selección de IPs destino

Propia de `anomaly-sshscan`.

El atacante mantiene fijo un servicio crítico, SSH/22, y automatiza la exploración de múltiples direcciones IP externas.

La anomalía no aparece en el barrido de puertos, sino en la dispersión horizontal hacia muchos destinos con un puerto destino fijo.

---

### 13.6 Automatización distribuida tipo C2

Propia de NerisBotnet.

La anomalía aparece en la coordinación de múltiples nodos hacia un canal común de mando y control.

---

## 14. Reglas generales del modelo ampliado

### 14.1 Regla DoS

```text
Si existe un grupo TCP con:
- mismo src_ip
- mismo dst_ip
- mismo dst_port
- duración cercana a cero
- pocos paquetes por flujo
- src_port secuencial
- baja varianza de bytes

entonces posible DoS.
```

---

### 14.2 Regla UDP Scan

```text
Si existe un grupo UDP con:
- mismo src_ip
- mismo src_port
- múltiples dst_ip
- múltiples dst_port
- dst_port secuencial
- duración cercana a cero
- baja varianza de bytes

entonces posible UDP Scan.
```

---

### 14.3 Regla Single-Source Vertical Scan

```text
Si existe un grupo TCP con:
- mismo src_ip
- mismo dst_ip
- muchos dst_port únicos
- duration == 0.000s
- packets == 1
- bytes ≈ 44
- predominio de SYN
- concentración temporal

entonces posible Single-Source Vertical Scan.
```

---

### 14.4 Regla Distributed Vertical Scan

```text
Si existe una ventana con:
- múltiples src_ip
- múltiples dst_ip
- protocolo TCP
- muchos dst_port únicos por dst_ip
- duration == 0.000s
- packets == 1
- bytes ≈ 44
- predominio de SYN
- sincronización temporal
- posible relación de subred entre orígenes

entonces posible Distributed Vertical Scan.
```

---

### 14.5 Regla SSH Horizontal Scan

```text
Si existe un grupo TCP con:
- mismo src_ip
- múltiples dst_ip
- dst_port fijo en 22
- duration == 0.000s
- packets == 1
- bytes ∈ {40, 44}
- flags de control sin sesión completa
- alta concentración temporal

entonces posible SSH Horizontal Scan.
```

---

### 14.6 Regla NerisBotnet

```text
Si existe un grupo con:
- múltiples src_ip
- mismo dst_ip
- mismo dst_port
- mismo protocolo
- mismo timestamp o intervalo muy reducido
- puerto asociado a C2
- baja varianza en bytes
- métricas homogéneas entre nodos

entonces posible NerisBotnet/C2.
```

---

## 15. Relación con los LLMs

El LLM se utilizó para identificar y explicar estos patrones.

Su papel fue:

- comparar tráfico normal y anómalo
- detectar relaciones estructurales
- formular hipótesis
- proponer reglas
- ayudar a formalizar el modelo
- diferenciar ataques con topologías parecidas pero objetivos distintos

Posteriormente, las hipótesis se validaron mediante código cuando fue posible.

De esta forma, el LLM no actúa como clasificador final, sino como herramienta de análisis y explicación.

---

## 16. Relación con la validación programática

El modelo fue validado parcialmente mediante el script:

```text
scripts/02_attack_analysis/detect_synthetic_behavior.py
```

Resultados disponibles hasta este punto:

| Tipo | Ventanas detectadas | Total | Estado |
|---|---:|---:|---|
| DoS | 3 | 3 | Validado |
| UDP Scan | 3 | 3 | Validado |
| NerisBotnet | 1 | 3 | Validado con matices |
| Normal | 0 clasificadas como ataque | 3 | Sin falsos positivos |
| scan11 | Pendiente | 3 | Analizado con LLM |
| scan44 | Pendiente | 3 | Analizado con LLM |
| anomaly-sshscan | Pendiente | 3 | Analizado con LLM |

La validación confirma que los patrones DoS y UDP Scan son claramente medibles, mientras que NerisBotnet requiere mayor contexto y evidencia distribuida.

`scan11`, `scan44` y `anomaly-sshscan` han sido integrados conceptualmente en el modelo, pero requieren adaptación del detector heurístico para validar formalmente las reglas de escaneo TCP vertical, escaneo TCP distribuido y escaneo horizontal SSH.

---

## 17. Limitaciones

El modelo presenta varias limitaciones:

- se basa en ventanas previamente extraídas
- no se ha aplicado todavía al dataset completo
- los umbrales se han ajustado empíricamente
- no pretende sustituir a un IDS real
- la detección de botnets requiere mayor contexto temporal
- la detección de escaneos distribuidos requiere correlación entre orígenes
- la detección de escaneos horizontales requiere medir dispersión de IPs destino por puerto fijo
- `anomaly-sshscan` requiere diferenciar tráfico SSH legítimo de intentos atómicos de reconocimiento
- la hipótesis de host interno comprometido debe tratarse como interpretación plausible, no como certeza absoluta
- el análisis de flags TCP debe validarse programáticamente
- el análisis depende de la representatividad de las ventanas
- el LLM puede generar hipótesis que requieren validación externa

---

## 18. Conclusión

El modelo de comportamiento sintético permite integrar distintos tipos de ataque bajo una misma lógica estructural.

La diferencia fundamental entre DoS, UDP Scan, scan11, scan44, anomaly-sshscan y NerisBotnet no reside únicamente en el protocolo o en la etiqueta, sino en la localización de la automatización.

- En DoS, la automatización aparece en el origen.
- En UDP Scan, la automatización aparece en la exploración del espacio de destino/red.
- En scan11, la automatización aparece en el barrido vertical de servicios de un único host.
- En scan44, la automatización aparece en la coordinación distribuida de escaneos verticales.
- En anomaly-sshscan, la automatización aparece en la selección horizontal de IPs destino hacia un servicio fijo, SSH/22.
- En NerisBotnet, la automatización aparece en la coordinación distribuida orientada a C2.

Este enfoque permite explicar los ataques de forma más interpretable y proporciona una base para validar hipótesis generadas por LLMs mediante análisis programático.
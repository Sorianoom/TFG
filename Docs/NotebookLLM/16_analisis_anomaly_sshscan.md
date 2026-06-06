# Análisis del ataque anomaly-sshscan

## 1. Objetivo

El objetivo de este análisis es estudiar el comportamiento del ataque `anomaly-sshscan` en el dataset UGR'16 y determinar cómo debe integrarse dentro del modelo de comportamiento sintético.

A diferencia de los escaneos verticales `scan11` y `scan44`, este ataque no se centra en recorrer múltiples puertos de uno o varios hosts, sino en buscar un servicio concreto, SSH, a través de múltiples direcciones IP.

El análisis permite ampliar el modelo con una nueva categoría:

```text
TCP Horizontal Scan
```

o, de forma más específica:

```text
SSH Horizontal Scan
```

---

## 2. Datos utilizados

Se analizaron tres ventanas temporales:

| Archivo | Descripción |
|---|---|
| `anomaly-sshscan_window_1.csv` | Primera ventana anomaly-sshscan |
| `anomaly-sshscan_window_2.csv` | Segunda ventana anomaly-sshscan |
| `anomaly-sshscan_window_3.csv` | Tercera ventana anomaly-sshscan |

También se utilizaron como referencia los perfiles normales de calibración:

- `normal_laboral.csv`
- `normal_nocturno.csv`
- `normal_transicion.csv`

Además, se comparó el patrón con el modelo de comportamiento sintético ya construido para:

- DoS
- UDP Scan
- scan11
- scan44
- NerisBotnet

---

## 3. Análisis asistido por LLM

Las tres ventanas `anomaly-sshscan` fueron proporcionadas a NotebookLM para extraer el patrón estructural global del ataque.

El LLM identificó un comportamiento de reconocimiento horizontal persistente, ejecutado por una IP interna del ISP hacia múltiples direcciones externas.

La conclusión principal fue que `anomaly-sshscan` no encaja plenamente en las categorías anteriores y debe modelarse como una nueva categoría de escaneo horizontal TCP orientado a SSH.

---

## 4. Patrón observado

El patrón observado se resume como:

```text
1 origen interno → muchas IPs externas → puerto 22/TCP
```

Esto indica un escaneo horizontal dirigido a un servicio específico.

A diferencia de un escaneo vertical, donde se prueban muchos puertos en un mismo host, aquí se mantiene fijo el puerto objetivo y se varían las IPs destino.

---

## 5. Identificación de actores

### 5.1 IP origen

La IP origen identificada como atacante es:

```text
42.219.156.231
```

Esta IP pertenece al espacio interno del ISP.

Este detalle es relevante porque sugiere que el origen del escaneo no es un atacante externo directo, sino posiblemente un nodo interno comprometido que realiza exploración hacia el exterior.

---

### 5.2 IPs destino

El ataque se dirige hacia múltiples IPs externas.

Ejemplos identificados en el análisis:

```text
129.104.110.251
209.48.6.54
154.29.70.254
```

La diversidad de destinos es una de las señales principales del escaneo horizontal.

---

## 6. Topología del ataque

La topología del ataque es:

```text
1 origen → muchos destinos
```

Sin embargo, a diferencia del UDP Scan, el servicio objetivo es fijo:

```text
dst_port = 22
```

Por tanto, la estructura completa puede representarse como:

```text
1 origen → muchas IPs destino → puerto fijo 22
```

---

## 7. Protocolo y puertos

### 7.1 Protocolo

El protocolo utilizado es TCP.

---

### 7.2 Puerto destino

El puerto destino principal es:

```text
22/TCP
```

Este puerto corresponde al servicio SSH.

No se observa un barrido amplio de puertos destino, sino una focalización clara en un servicio concreto.

---

### 7.3 Puertos origen

Los puertos origen son puertos altos o efímeros, variables entre ráfagas.

Ejemplos observados:

```text
61193
16397
```

Esto indica que la estructura principal del ataque no está en los puertos origen, sino en la selección masiva de IPs destino manteniendo fijo el puerto SSH.

---

## 8. Métricas de flujo

El ataque presenta una firma atómica y de baja entropía.

### 8.1 Duración

Los flujos presentan duración:

```text
0.000s
```

Esto indica intentos instantáneos, sin establecimiento de sesión prolongada.

---

### 8.2 Paquetes

Cada intento suele estar formado por:

```text
1 paquete
```

---

### 8.3 Bytes

El tamaño observado se mantiene en valores muy bajos:

```text
40-44 bytes
```

Esto coincide con flujos de control TCP sin intercambio real de datos.

---

### 8.4 Entropía

La entropía del ataque es prácticamente nula.

Los flujos son muy repetitivos en:

- duración
- paquetes
- bytes
- puerto destino
- protocolo

La variabilidad aparece principalmente en las IPs destino.

---

## 9. Flags TCP

El análisis identifica flags de control como:

```text
.A....
...R..
```

Estas flags sugieren intentos incompletos, resets o técnicas de sondeo.

La ausencia de sesiones completas con intercambio de datos permite diferenciar el patrón de una conexión SSH legítima.

---

## 10. Comportamiento temporal

El ataque aparece en ráfagas en distintos momentos del día.

El análisis asistido por LLM identificó actividad alrededor de:

```text
07:35
11:30
```

La repetición de ráfagas en distintos momentos indica una actividad automatizada persistente.

Cada intento es atómico e instantáneo.

---

## 11. Diferencias con tráfico normal

El tráfico normal de calibración se caracteriza por:

- diversidad de IPs y servicios
- sesiones TCP completas
- variabilidad en duración
- variabilidad en bytes y paquetes
- comportamiento transaccional
- presencia de tráfico asociado a actividad humana o servicios legítimos

En cambio, `anomaly-sshscan` presenta:

- un único origen dominante
- múltiples IPs destino externas
- puerto destino fijo 22
- duración cero
- un paquete por flujo
- bytes constantes entre 40 y 44
- ausencia de sesión SSH real
- comportamiento exploratorio

La diferencia principal es que el tráfico normal es interactivo y variable, mientras que `anomaly-sshscan` es determinista y exploratorio.

---

## 12. Diferencias con tráfico SSH legítimo

Una sesión SSH legítima suele presentar:

- relación 1→1
- establecimiento de conexión
- intercambio de claves
- múltiples paquetes
- duración superior a cero
- tamaños variables
- tráfico bidireccional
- posible transferencia de datos

El patrón `anomaly-sshscan`, en cambio, presenta:

- relación 1→muchos
- puerto destino fijo 22
- duración 0.000s
- un paquete por flujo
- 40-44 bytes
- ausencia de intercambio real
- múltiples destinos en ráfaga

Por tanto, no debe confundirse con tráfico SSH legítimo.

---

## 13. Diferencias con scan11

`scan11` representa un escaneo TCP vertical.

```text
scan11:
1 origen → 1 destino → muchos puertos
```

`anomaly-sshscan` representa un escaneo TCP horizontal especializado en SSH.

```text
anomaly-sshscan:
1 origen → muchas IPs destino → puerto fijo 22
```

La diferencia clave está en qué elemento varía:

| Ataque | Elemento variable |
|---|---|
| scan11 | Puertos destino |
| anomaly-sshscan | IPs destino |

---

## 14. Diferencias con scan44

`scan44` representa un escaneo vertical distribuido.

```text
scan44:
muchos orígenes → muchos destinos → muchos puertos
```

`anomaly-sshscan` no muestra la misma coordinación distribuida entre múltiples orígenes.

```text
anomaly-sshscan:
1 origen interno → muchos destinos externos → puerto 22
```

La diferencia principal es:

| Característica | scan44 | anomaly-sshscan |
|---|---|---|
| Orígenes | Múltiples | Uno |
| Destinos | Múltiples | Múltiples |
| Puertos destino | Muchos por host | Fijo en 22 |
| Tipo | Vertical distribuido | Horizontal SSH |
| Automatización | Red coordinada + puertos destino | Selección de IPs destino |

---

## 15. Diferencias con UDP Scan

Aunque ambos presentan una estructura 1→muchos, difieren en protocolo y objetivo.

| Característica | UDP Scan | anomaly-sshscan |
|---|---|---|
| Protocolo | UDP | TCP |
| Puerto destino | Secuencial / variable | Fijo en 22 |
| Objetivo | Reconocimiento UDP de servicios | Búsqueda de SSH |
| Métrica de bytes | ~433 bytes | 40-44 bytes |
| Tipo | Escaneo UDP | Escaneo TCP horizontal |

---

## 16. Diferencias con NerisBotnet

NerisBotnet se caracteriza por coordinación distribuida y comunicación con C2.

`anomaly-sshscan` no muestra una comunicación muchos→1 hacia un C2, sino un origen interno escaneando múltiples destinos externos.

| Característica | NerisBotnet | anomaly-sshscan |
|---|---|---|
| Topología | Muchos→1 / híbrida | 1→muchos |
| Objetivo | Coordinación C2 | Reconocimiento SSH |
| Puerto | C2 fijo, como 6667 | SSH/22 |
| Automatización | Red distribuida | Selección de IPs destino |
| Métricas | Variables por fase | Atómicas y constantes |

---

## 17. Implicación de que el origen sea interno

Uno de los aspectos más relevantes del ataque es que la IP origen pertenece al espacio interno del ISP:

```text
42.219.156.231
```

Esto sugiere que el host podría estar comprometido y actuando como nodo de propagación o exploración.

La dirección del tráfico es importante:

```text
interno → externo
```

Esto cambia la interpretación respecto a un atacante externo que intenta entrar en la red.

En este caso, el patrón puede interpretarse como una posible actividad de propagación desde dentro del ISP hacia Internet.

---

## 18. Integración en el modelo de comportamiento sintético

`anomaly-sshscan` debe integrarse como nueva categoría:

```text
TCP Horizontal Scan
```

o más específicamente:

```text
SSH Horizontal Scan
```

La automatización se localiza en:

```text
selección del espacio de direcciones destino
```

El atacante mantiene fijo el servicio objetivo y varía las IPs para localizar hosts con SSH accesible.

---

## 19. Modelo ampliado

Con esta incorporación, el modelo queda ampliado así:

| Ataque | Categoría | Topología | Automatización |
|---|---|---|---|
| DoS | Inundación | 1→1 | Origen |
| UDP Scan | Reconocimiento UDP | 1→muchos | Espacio de destino/red |
| scan11 | Single-Source Vertical Scan | 1→1 + muchos puertos | Servicios del host objetivo |
| scan44 | Distributed Vertical Scan | Muchos→Muchos + muchos puertos | Red coordinada + servicios destino |
| anomaly-sshscan | SSH Horizontal Scan | 1→muchos + puerto fijo 22 | Selección de IPs destino |
| NerisBotnet | Botnet/C2 | Muchos→1 / híbrida | Red distribuida/C2 |

---

## 20. Reglas de detección propuestas

### 20.1 Regla de dispersión horizontal SSH

```text
Si una misma src_ip contacta con muchas dst_ip únicas
en un intervalo temporal reducido
y el dst_port es constante e igual a 22,
entonces posible SSH Horizontal Scan.
```

---

### 20.2 Regla de firma sintética TCP horizontal

```text
protocol == TCP
AND duration == 0.000s
AND packets == 1
AND bytes IN {40, 44}
AND dst_port == 22
```

---

### 20.3 Regla de incompletitud SSH

```text
Alto ratio de intentos de control TCP
frente a ausencia de sesiones SSH completas
hacia el puerto 22.
```

---

### 20.4 Regla de origen interno proactivo

```text
Si una IP interna genera muchos intentos externos
hacia el puerto 22
sin sesiones establecidas,
entonces elevar sospecha de host comprometido.
```

---

## 21. Regla general derivada

La regla general puede expresarse así:

```text
Si existe un grupo TCP con:
- mismo src_ip
- múltiples dst_ip
- dst_port fijo en 22
- duration == 0.000s
- packets == 1
- bytes entre 40 y 44
- flags de control sin sesión completa
- alta concentración temporal

entonces clasificar como posible SSH Horizontal Scan.
```

---

## 22. Limitaciones

El análisis presenta varias limitaciones:

- se basa en tres ventanas previamente extraídas
- todavía no se ha validado con el detector heurístico
- el análisis de flags debe comprobarse programáticamente
- se deben ajustar umbrales para número de destinos por intervalo temporal
- algunos usos legítimos de SSH podrían generar actividad repetida, aunque no con esta firma atómica
- escaneos lentos podrían diluirse en el tráfico normal
- la interpretación de host comprometido es plausible, pero debe tratarse como hipótesis

---

## 23. Conclusión

El ataque `anomaly-sshscan` representa una nueva categoría dentro del modelo de comportamiento sintético: el escaneo TCP horizontal orientado a SSH.

Su patrón se caracteriza por un único origen interno que contacta múltiples destinos externos manteniendo fijo el puerto 22/TCP.

A diferencia de los escaneos verticales `scan11` y `scan44`, aquí la automatización no se localiza en el barrido de puertos, sino en la selección del espacio de direcciones IP destino.

La firma principal del ataque es la combinación de duración cero, un paquete por flujo, 40-44 bytes, puerto destino fijo y alta dispersión de destinos.

Este análisis amplía el modelo del TFG al incorporar una familia de reconocimiento horizontal especializada en un servicio crítico.
# Análisis del ataque scan11

## 1. Objetivo

El objetivo de este análisis es estudiar el comportamiento del ataque `scan11` en el dataset UGR'16 y determinar si encaja dentro del modelo de comportamiento sintético previamente definido.

Hasta este punto, el modelo contemplaba tres familias principales:

- DoS: automatización localizada en el origen.
- UDP Scan: automatización localizada en el espacio de destino/red.
- NerisBotnet: automatización distribuida en red.

El análisis de `scan11` permite ampliar el modelo con una nueva categoría de reconocimiento: el escaneo TCP vertical.

---

## 2. Datos utilizados

Se analizaron tres ventanas temporales:

| Archivo | Descripción |
|---|---|
| `scan11_window_1.csv` | Primera ventana scan11 |
| `scan11_window_2.csv` | Segunda ventana scan11 |
| `scan11_window_3.csv` | Tercera ventana scan11 |

También se utilizaron como referencia los perfiles normales de calibración:

- `normal_laboral.csv`
- `normal_nocturno.csv`
- `normal_transicion.csv`

---

## 3. Análisis asistido por LLM

Las tres ventanas `scan11` fueron proporcionadas a NotebookLM para identificar el patrón estructural del ataque.

El LLM identificó un comportamiento altamente estructurado, automatizado y distinto de los ataques previamente analizados.

La conclusión principal fue que `scan11` no encaja completamente ni como DoS ni como UDP Scan, aunque comparte elementos parciales con ambos.

Debe considerarse una nueva subcategoría dentro del modelo:

```text
TCP Vertical Scan
```

o en español:

```text
Escaneo TCP vertical
```

---

## 4. Patrón observado

El patrón observado corresponde a una topología estrictamente:

```text
1 origen → 1 destino
```

En las ventanas analizadas aparece de forma persistente la comunicación:

```text
42.219.150.246 → 42.219.154.69
```

A diferencia del DoS, el tráfico no se concentra en un único puerto de destino.

A diferencia del UDP Scan, el tráfico no se dispersa hacia múltiples IPs.

La automatización se manifiesta en el barrido de múltiples puertos destino dentro de un único host objetivo.

---

## 5. Identificación de actores

### 5.1 IP origen

La IP origen identificada como atacante es:

```text
42.219.150.246
```

Esta IP aparece como origen persistente en las tres ventanas analizadas.

---

### 5.2 IP destino

La IP destino observada es:

```text
42.219.154.69
```

El ataque se concentra en este único host, lo que permite interpretarlo como un escaneo vertical de servicios.

---

## 6. Topología del ataque

La topología de `scan11` es:

```text
1 origen → 1 destino → muchos puertos
```

Esto lo diferencia de otros patrones:

| Ataque | Topología |
|---|---|
| DoS | 1 origen → 1 destino:puerto fijo |
| UDP Scan | 1 origen → muchas IPs/puertos |
| NerisBotnet | muchos orígenes → 1 destino C2 |
| scan11 | 1 origen → 1 destino:muchos puertos |

---

## 7. Protocolo y puertos

### 7.1 Protocolo

El ataque utiliza TCP.

El patrón identificado es compatible con un escaneo tipo TCP SYN Scan o escaneo half-open.

---

### 7.2 Puertos destino

El ataque realiza un barrido amplio de puertos de destino.

Entre los puertos identificados aparecen servicios estándar como:

| Puerto | Servicio asociado |
|---:|---|
| 22 | SSH |
| 23 | Telnet |
| 53 | DNS |
| 80 | HTTP |
| 110 | POP3 |
| 139 | NetBIOS/SMB |
| 443 | HTTPS |
| 445 | SMB |
| 3306 | MySQL |

También aparecen rangos de puertos no estándar o altos, como:

```text
1000-1100
10000-10004
```

Esto indica que el atacante no intenta saturar un servicio concreto, sino descubrir qué servicios están expuestos en el host objetivo.

---

### 7.3 Puertos origen

Los puertos de origen son variables, aunque pueden mantenerse estables durante ráfagas cortas.

Ejemplos observados en el análisis:

```text
44428
44429
```

Esto refuerza que la automatización principal no se encuentra en el puerto origen, sino en la progresión de puertos destino.

---

## 8. Métricas de flujo

El ataque presenta métricas extremadamente rígidas.

### 8.1 Duración

Los flujos presentan duración:

```text
0.000s
```

Esto indica intentos de conexión instantáneos sin establecimiento de sesión completa.

---

### 8.2 Paquetes

Cada intento de conexión suele estar compuesto por:

```text
1 paquete
```

---

### 8.3 Bytes

El tamaño típico observado es:

```text
44 bytes
```

También se observaron algunos flujos de 40 bytes y algún caso excepcional de 84 bytes.

La baja variabilidad en duración, paquetes y bytes indica un comportamiento sintético y automatizado.

---

## 9. Flags TCP

El análisis identificó un predominio de flags SYN.

Esto es coherente con un TCP SYN Scan, donde el atacante intenta detectar puertos abiertos sin completar el handshake TCP completo.

La ausencia de flujos de transferencia de datos posteriores diferencia este patrón de una conexión TCP legítima.

---

## 10. Comportamiento temporal

El ataque aparece en forma de ráfagas masivas.

En las ventanas analizadas se observan cientos de flujos concentrados en el mismo instante o milisegundo.

Este comportamiento rompe la dinámica temporal normal del tráfico del ISP, que tiende a ser más heterogénea y distribuida.

---

## 11. Diferencias con tráfico normal

El tráfico normal de calibración se caracteriza por:

- diversidad de IPs
- diversidad de puertos usados de forma funcional
- sesiones TCP completas
- variabilidad en duración
- variabilidad en paquetes y bytes
- presencia de flags asociados a transferencia y cierre de sesión
- comportamiento cicloestacionario

En cambio, `scan11` presenta:

- un único origen
- un único destino
- muchos puertos destino
- duración cero
- un paquete por flujo
- bytes constantes
- predominio de SYN
- barrido vertical de servicios
- ráfagas masivas

La diferencia principal es que el tráfico normal es transaccional, mientras que `scan11` es exploratorio.

---

## 12. Diferencias con DoS

Aunque `scan11` comparte con DoS la topología 1→1, su objetivo técnico es distinto.

### DoS

```text
1 origen → 1 destino:puerto fijo
```

El objetivo es saturar un servicio o agotar recursos del sistema objetivo.

### scan11

```text
1 origen → 1 destino:muchos puertos
```

El objetivo es descubrir servicios expuestos en un host concreto.

Por tanto, `scan11` no debe clasificarse como DoS.

---

## 13. Diferencias con UDP Scan

`scan11` comparte con UDP Scan la idea de reconocimiento, pero difiere en la estructura.

### UDP Scan

```text
1 origen → muchas IPs + puertos destino
```

El atacante explora una red o bloque de direcciones.

### scan11

```text
1 origen → 1 IP + muchos puertos destino
```

El atacante explora en profundidad un único host.

Además:

| Característica | UDP Scan | scan11 |
|---|---|---|
| Protocolo | UDP | TCP |
| Dispersión IP | Alta | Nula |
| Tipo de escaneo | Horizontal/híbrido | Vertical |
| Métrica típica | 1 paquete, ~433 bytes | 1 paquete, ~44 bytes |
| Automatización | Exploración de red/destinos | Exploración de servicios del host |

---

## 14. Diferencias con NerisBotnet

NerisBotnet se caracteriza por coordinación distribuida entre múltiples nodos.

`scan11`, en cambio, es una actividad centralizada de un único origen contra un único objetivo.

| Característica | NerisBotnet | scan11 |
|---|---|---|
| Topología | Muchos→1 / híbrida | 1→1 |
| Objetivo | Coordinación C2 | Reconocimiento de servicios |
| Automatización | Red distribuida | Puertos destino del host |
| Rasgo clave | Sincronización de nodos | Barrido vertical |

---

## 15. Integración en el modelo de comportamiento sintético

El modelo debe ampliarse para incluir `scan11` como nueva categoría.

La categoría propuesta es:

```text
TCP Vertical Scan
```

o:

```text
Escaneo TCP vertical
```

La automatización se localiza en:

```text
espacio de servicios del host objetivo
```

Esto significa que el atacante ya ha seleccionado una víctima concreta y ahora intenta mapear en profundidad sus puertos y servicios disponibles.

---

## 16. Modelo ampliado

El modelo de comportamiento sintético queda ampliado de la siguiente forma:

| Ataque | Localización de la automatización | Patrón |
|---|---|---|
| DoS | Origen | 1→1 con puerto destino fijo |
| UDP Scan | Espacio de red/destino | 1→muchos con barrido de IPs/puertos |
| scan11 | Servicios del host objetivo | 1→1 con barrido vertical de puertos |
| NerisBotnet | Red distribuida | muchos→1 sincronizado/C2 |

---

## 17. Reglas de detección propuestas

A partir del análisis, se proponen las siguientes reglas para detectar `scan11`.

### 17.1 Regla de dispersión vertical

```text
unique_dst_ports(src_ip, dst_ip) / Δt > θ
```

Esta regla detecta cuando una misma IP origen contacta con muchos puertos de una misma IP destino en un intervalo temporal reducido.

---

### 17.2 Regla de firma atómica TCP

```text
protocol == TCP
AND duration ≈ 0.000s
AND packets == 1
AND bytes ≈ 44
```

Esta regla identifica intentos TCP sintéticos de baja duración y bajo volumen.

---

### 17.3 Regla de incompletitud TCP

```text
Predominio de SYN
AND ausencia de flujos de transferencia de datos
```

Esta regla permite distinguir un escaneo SYN de conexiones TCP legítimas.

---

## 18. Regla general derivada

La regla de detección puede expresarse así:

```text
Si existe un grupo TCP con:
- mismo src_ip
- mismo dst_ip
- muchos dst_port únicos
- dst_port secuenciales o altamente diversos
- duración cercana a cero
- un paquete por flujo
- bytes constantes alrededor de 44
- predominio de SYN
- alta concentración temporal

entonces clasificar como posible TCP Vertical Scan.
```

---

## 19. Limitaciones

El análisis presenta varias limitaciones:

- se basa en tres ventanas temporales previamente extraídas
- no se ha validado todavía con el detector heurístico
- el análisis de flags debe comprobarse programáticamente
- los umbrales de número de puertos por segundo deben ajustarse
- algunos puertos también pueden aparecer en tráfico normal
- escaneos lentos podrían no detectarse con reglas de alta densidad temporal
- el análisis sigue dependiendo de la representatividad de las ventanas

---

## 20. Conclusión

El ataque `scan11` representa una nueva variante dentro del modelo de comportamiento sintético.

No debe clasificarse como DoS, aunque comparta la topología 1→1, porque su objetivo no es saturar un servicio, sino explorar múltiples puertos de un único host.

Tampoco debe confundirse con UDP Scan, ya que no explora múltiples IPs, sino múltiples servicios dentro de un mismo destino y usando TCP.

El patrón queda definido como un escaneo TCP vertical, donde la automatización se localiza en el espacio de servicios del host objetivo.

Este análisis amplía el modelo del TFG y permite cubrir una nueva forma de reconocimiento técnico basada en barrido vertical de puertos.
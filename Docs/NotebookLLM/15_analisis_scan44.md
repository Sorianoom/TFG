# Análisis del ataque scan44

## 1. Objetivo

El objetivo de este análisis es estudiar el comportamiento del ataque `scan44` en el dataset UGR'16 y determinar cómo debe integrarse dentro del modelo de comportamiento sintético.

El análisis de `scan44` permite ampliar la categoría de escaneos TCP observada previamente con `scan11`, incorporando una variante distribuida y coordinada.

---

## 2. Datos utilizados

Se analizaron tres ventanas temporales:

| Archivo | Descripción |
|---|---|
| `scan44_window_1.csv` | Primera ventana scan44 |
| `scan44_window_2.csv` | Segunda ventana scan44 |
| `scan44_window_3.csv` | Tercera ventana scan44 |

También se utilizaron como referencia los perfiles normales de calibración:

- `normal_laboral.csv`
- `normal_nocturno.csv`
- `normal_transicion.csv`

---

## 3. Análisis asistido por LLM

Las tres ventanas `scan44` fueron proporcionadas a NotebookLM para identificar el patrón estructural global del ataque.

El LLM identificó un comportamiento de reconocimiento distribuido y coordinado, diferente de los escaneos simples previamente analizados.

La conclusión principal fue que `scan44` comparte con `scan11` la lógica de escaneo TCP vertical, pero introduce una diferencia clave: la coordinación de múltiples orígenes contra múltiples destinos.

---

## 4. Patrón observado

El patrón observado corresponde a una topología:

```text
muchos orígenes → muchos destinos
```

Esto diferencia `scan44` de `scan11`, que presentaba una estructura:

```text
1 origen → 1 destino
```

En `scan44`, varios nodos de origen ejecutan escaneos verticales de puertos contra varios hosts objetivo.

---

## 5. Identificación de actores

### 5.1 IPs origen

El análisis identifica varios orígenes pertenecientes a la misma subred:

```text
42.219.150.242
42.219.150.243
42.219.150.246
42.219.150.247
```

La aparición de múltiples orígenes coordinados es uno de los rasgos principales del ataque.

---

### 5.2 IPs destino

El ataque se dirige contra varios hosts del ISP, entre ellos:

```text
42.219.154.69
42.219.152.20
42.219.158.16
42.219.156.30
```

Esto indica que el ataque no se centra en un único host, sino en varios objetivos concretos.

---

## 6. Topología del ataque

La estructura de `scan44` puede representarse como:

```text
varios orígenes → varios destinos → muchos puertos por destino
```

Por tanto, el ataque combina:

- escaneo horizontal: porque interactúa con múltiples IPs destino
- escaneo vertical: porque sondea muchos puertos en cada host objetivo

Por este motivo, `scan44` puede interpretarse como un escaneo híbrido coordinado.

---

## 7. Protocolo y puertos

### 7.1 Protocolo

El protocolo utilizado es TCP.

El patrón es compatible con escaneo TCP SYN.

---

### 7.2 Puertos destino

El ataque realiza barridos de puertos destino amplios y secuenciales.

Incluye puertos de servicios comunes, como:

| Puerto | Servicio asociado |
|---:|---|
| 21 | FTP |
| 22 | SSH |
| 23 | Telnet |
| 25 | SMTP |
| 80 | HTTP |
| 443 | HTTPS |
| 445 | SMB |
| 3389 | RDP |

Además, aparecen rangos de puertos altos, como:

```text
1000-1100
10000-10600
```

Esto indica un reconocimiento profundo de servicios en cada host objetivo.

---

### 7.3 Puertos origen

Los puertos origen pueden mantenerse fijos por ráfaga o por par origen-destino.

Ejemplos identificados:

```text
51762
39978
53189
55742
```

La automatización principal no reside en el puerto origen, sino en la coordinación distribuida y el barrido de puertos destino.

---

## 8. Métricas de flujo

Las métricas del ataque presentan entropía extremadamente baja.

### 8.1 Duración

Todos los flujos del ataque presentan duración:

```text
0.000s
```

Esto indica intentos de conexión instantáneos.

---

### 8.2 Paquetes

Cada intento SYN suele estar formado por:

```text
1 paquete
```

---

### 8.3 Bytes

El tamaño típico de las peticiones SYN es:

```text
44 bytes
```

También se observan respuestas RST-ACK de aproximadamente:

```text
40 bytes
```

La repetición de estas métricas indica tráfico sintético generado por herramienta.

---

## 9. Flags TCP

El ataque utiliza principalmente SYN para realizar el sondeo.

También se observan respuestas RST-ACK desde hosts destino, compatibles con puertos cerrados.

Esto refuerza la interpretación de `scan44` como un escaneo TCP SYN distribuido.

---

## 10. Comportamiento temporal

El rasgo más importante de `scan44` es la sincronización.

Cientos de flujos dirigidos a distintos puertos y distintos destinos aparecen en el mismo instante temporal o milisegundo.

Esta sincronización entre varios orígenes sugiere coordinación automatizada.

---

## 11. Diferencias con tráfico normal

El tráfico normal de calibración se caracteriza por:

- diversidad natural de IPs y puertos
- sesiones TCP completas
- variabilidad de duración
- variabilidad de bytes
- presencia de tráfico transaccional
- comportamiento cicloestacionario
- ausencia de barridos masivos coordinados

En cambio, `scan44` presenta:

- múltiples orígenes coordinados
- múltiples destinos específicos
- barrido secuencial de puertos
- duración cero
- un paquete por flujo
- bytes constantes
- predominio de SYN
- sincronización temporal

La diferencia principal es que el tráfico normal es heterogéneo y transaccional, mientras que `scan44` es homogéneo, exploratorio y coordinado.

---

## 12. Diferencias con scan11

`scan44` comparte con `scan11` la lógica de escaneo TCP vertical, pero no representa el mismo patrón.

### scan11

```text
1 origen → 1 destino → muchos puertos
```

### scan44

```text
muchos orígenes → muchos destinos → muchos puertos
```

La diferencia clave es la coordinación distribuida.

| Característica | scan11 | scan44 |
|---|---|---|
| Topología | 1→1 | Muchos→Muchos |
| Orígenes | Un único atacante | Varios orígenes |
| Destinos | Un host | Varios hosts |
| Tipo de escaneo | Vertical | Híbrido distribuido |
| Automatización | Host objetivo / puertos destino | Red coordinada |
| Sincronización | Local | Distribuida |

---

## 13. Diferencias con UDP Scan

Aunque `scan44` comparte con UDP Scan la idea de reconocimiento, ambos ataques presentan diferencias importantes.

| Característica | UDP Scan | scan44 |
|---|---|---|
| Protocolo | UDP | TCP |
| Topología | 1→muchos | Muchos→Muchos |
| Profundidad | Menor por host | Alta por host |
| Métrica típica | 1 paquete, ~433 bytes | 1 paquete, ~44 bytes |
| Respuestas esperadas | ICMP/UDP | RST-ACK |
| Tipo | Escaneo de red | Escaneo híbrido coordinado |

`scan44` no debe confundirse con UDP Scan porque su lógica es TCP, más profunda por host y coordinada entre varios orígenes.

---

## 14. Diferencias con NerisBotnet

`scan44` y NerisBotnet comparten un elemento: la distribución.

Sin embargo, su objetivo técnico es distinto.

### NerisBotnet

Busca coordinación con un Command & Control.

### scan44

Busca reconocimiento de servicios expuestos.

| Característica | NerisBotnet | scan44 |
|---|---|---|
| Objetivo | Coordinación C2 | Reconocimiento |
| Puerto | C2 fijo, como 6667 | Puertos destino variables |
| Métricas | Variables por fase | Entropía nula |
| Topología | Muchos→1 / híbrida | Muchos→Muchos |
| Rasgo clave | Sincronización hacia C2 | Escaneo distribuido de puertos |

---

## 15. Integración en el modelo de comportamiento sintético

El análisis de `scan44` confirma que el modelo debe ampliarse con una familia de reconocimiento de servicios TCP.

La categoría general propuesta es:

```text
TCP Vertical Scan
```

subdividida en:

```text
Single-Source Vertical Scan
Distributed Vertical Scan
```

---

## 16. Modelo ampliado con scan11 y scan44

| Ataque | Categoría | Topología | Automatización |
|---|---|---|---|
| scan11 | Single-Source Vertical Scan | 1→1 | Servicios del host objetivo |
| scan44 | Distributed Vertical Scan | Muchos→Muchos | Red coordinada + servicios destino |

De esta forma, `scan11` y `scan44` quedan agrupados bajo la misma familia lógica, pero con distinta escala de coordinación.

---

## 17. Reglas de detección propuestas

### 17.1 Regla de escaneo vertical distribuido

```text
Si múltiples src_ip generan flujos TCP SYN
hacia múltiples dst_ip
con muchos dst_port únicos por dst_ip
en una ventana temporal reducida,
entonces clasificar como posible Distributed Vertical Scan.
```

---

### 17.2 Regla de correlación de subred

```text
Si varias IPs de un mismo rango /24
generan ráfagas SYN síncronas
hacia diferentes hosts del ISP,
entonces elevar la sospecha de escaneo coordinado.
```

---

### 17.3 Regla de firma atómica TCP

```text
protocol == TCP
AND duration == 0.000s
AND packets == 1
AND bytes ≈ 44
```

---

### 17.4 Regla de dispersión híbrida

```text
unique_dst_ips > 1
AND unique_dst_ports_per_target > θ
AND same_timestamp_ratio elevado
```

---

## 18. Regla general derivada

La regla de detección para `scan44` puede expresarse así:

```text
Si existe una ventana con:
- múltiples IPs origen
- múltiples IPs destino
- protocolo TCP
- duración 0.000s
- 1 paquete por flujo
- bytes constantes alrededor de 44
- predominio de SYN
- muchos puertos destino por cada host
- ráfagas síncronas
- posible relación de subred entre orígenes

entonces clasificar como posible Distributed Vertical Scan.
```

---

## 19. Limitaciones

El análisis presenta varias limitaciones:

- se basa en tres ventanas previamente extraídas
- todavía no se ha validado con el detector heurístico
- el análisis de flags debe comprobarse programáticamente
- es necesario definir umbrales para puertos únicos por destino
- es necesario definir ventanas temporales adecuadas para capturar sincronización
- algunas IPs o puertos podrían aparecer también en background
- escaneos distribuidos lentos podrían ser más difíciles de detectar

---

## 20. Conclusión

El ataque `scan44` representa una variante distribuida y coordinada del escaneo TCP vertical observado en `scan11`.

Mientras `scan11` realiza un escaneo profundo sobre un único host desde un único origen, `scan44` extiende esta lógica a múltiples orígenes y múltiples destinos.

La categoría propuesta es:

```text
Distributed Vertical Scan
```

dentro de una familia general de:

```text
TCP Vertical Scan
```

Este análisis amplía el modelo de comportamiento sintético, incorporando una forma de reconocimiento más compleja, basada en escaneo paralelo y sincronización entre nodos.
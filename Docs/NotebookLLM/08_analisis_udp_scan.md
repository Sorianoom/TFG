# Análisis del ataque UDP Scan

## 1. Objetivo

El objetivo de este análisis es estudiar el comportamiento del ataque `anomaly-udpscan` observado en el dataset UGR'16 y formalizar un modelo de detección basado en comportamiento.

El análisis se centra en identificar patrones estructurales de reconocimiento de red mediante UDP, comparándolos con los perfiles normales de calibración.

El objetivo no es depender únicamente de la etiqueta del dataset, sino determinar qué propiedades del tráfico permiten diferenciar un escaneo UDP de tráfico UDP legítimo, como DNS o NTP.

---

## 2. Datos utilizados

Se analizaron tres ventanas temporales etiquetadas como `anomaly-udpscan`:

| Archivo | Descripción |
|---|---|
| `anomaly-udpscan_window_1.csv` | Primera ventana UDP Scan |
| `anomaly-udpscan_window_2.csv` | Segunda ventana UDP Scan |
| `anomaly-udpscan_window_3.csv` | Tercera ventana UDP Scan |

También se utilizaron como referencia los perfiles normales de calibración:

- `normal_laboral.csv`
- `normal_nocturno.csv`
- `normal_transicion.csv`

---

## 3. Análisis asistido por LLM

Las tres ventanas UDP Scan fueron proporcionadas al LLM para identificar patrones comunes.

Posteriormente, el patrón detectado se comparó con los perfiles normales de calibración.

El LLM identificó que el ataque presenta una estructura sistemática y automatizada, caracterizada por un origen persistente, un puerto origen fijo, dispersión hacia múltiples destinos y barrido secuencial de puertos destino.

---

## 4. Patrón observado

El patrón identificado corresponde a un escaneo de reconocimiento mediante UDP.

El atacante utiliza una estructura:

```text
1 origen → muchos destinos
```

La IP origen observada en las ventanas analizadas es:

```text
217.156.59.213
```

El puerto origen se mantiene constante:

```text
5061
```

Desde ese origen, el atacante interactúa con múltiples IPs del rango del ISP, probando puertos destino de forma secuencial.

---

## 5. Identificación de actores

### 5.1 IP origen

El origen del ataque es constante en las tres ventanas:

```text
217.156.59.213
```

Esto indica que el escaneo parte de un único nodo externo.

---

### 5.2 IPs destino

A diferencia del DoS, que se concentra en un único destino, el UDP Scan se dispersa hacia múltiples IPs de la red del ISP.

El análisis del LLM identificó que el ataque recorre distintos rangos de direcciones internas:

| Ventana | Rango observado |
|---|---|
| `anomaly-udpscan_window_1.csv` | Rango próximo a `42.219.158.x` - `42.219.159.x` |
| `anomaly-udpscan_window_2.csv` | Rango `42.219.155.x` |
| `anomaly-udpscan_window_3.csv` | Rango `42.219.148.x` |

Esto sugiere un barrido de bloques de direcciones dentro del ISP.

---

## 6. Estructura de puertos

### 6.1 Puerto origen fijo

El atacante utiliza de forma constante el puerto origen:

```text
5061
```

El puerto 5061 suele asociarse a SIP sobre TLS. En este análisis no se asume necesariamente que el ataque sea SIP, pero sí se considera relevante que el puerto origen permanezca fijo mientras varían los destinos y puertos objetivo.

---

### 6.2 Puertos destino secuenciales

El rasgo más importante del ataque es la secuencialidad de los puertos destino.

El atacante prueba de forma ordenada un rango aproximado de puertos:

```text
6031 → 6060
```

Esto implica un barrido vertical de puertos sobre cada IP objetivo.

La estructura observada puede resumirse como:

```text
src_ip fijo + src_port fijo → múltiples dst_ip + dst_port secuencial
```

---

## 7. Comportamiento temporal

Las ventanas analizadas muestran ráfagas de tráfico concentradas temporalmente.

El análisis asistido por LLM identificó que las ventanas se encuentran separadas por intervalos muy cortos, con actividad en torno a:

```text
04:10:22
04:10:24
04:10:26
```

Esto indica que el escaneo se ejecuta en ráfagas rápidas y repetitivas.

La concentración temporal refuerza la hipótesis de tráfico generado por herramienta automatizada.

---

## 8. Métricas de flujo

El UDP Scan presenta baja entropía en sus métricas.

### 8.1 Protocolo

El protocolo utilizado es UDP.

Esto diferencia el ataque del DoS analizado previamente, que se basaba en TCP.

---

### 8.2 Duración

Los flujos presentan duración cercana a cero:

```text
duration = 0.000s
```

Esto indica que los flujos son instantáneos y no corresponden a sesiones prolongadas.

---

### 8.3 Paquetes

Cada flujo suele estar compuesto por un único paquete:

```text
packets = 1
```

---

### 8.4 Bytes

El tamaño de los flujos es muy uniforme, aproximadamente:

```text
~433 bytes
```

En la validación programática, las ventanas UDP Scan presentaron una varianza de bytes muy baja, cercana a 2.

Esto sugiere el envío repetitivo de un payload similar hacia distintos puertos o destinos.

---

## 9. Diferencias con tráfico UDP normal

El tráfico UDP legítimo, como DNS o NTP, puede compartir algunas características con el escaneo:

- duración baja
- pocos paquetes
- tamaño reducido
- ausencia de conexión persistente

Sin embargo, el UDP Scan se diferencia por su estructura.

---

### 9.1 Diferencia frente a DNS

El tráfico DNS normal suele dirigirse al puerto 53 y a servidores conocidos o recurrentes.

En cambio, el UDP Scan:

- no se limita al puerto 53
- barre puertos destino altos
- usa puertos destino secuenciales
- se dirige a múltiples IPs del ISP
- mantiene un tamaño de payload muy uniforme

Por tanto, aunque ambos usen UDP, su comportamiento estructural es distinto.

---

### 9.2 Diferencia en diversidad

El tráfico UDP normal presenta mayor variabilidad en:

- destinos
- tamaños
- puertos
- patrones temporales

El UDP Scan presenta una estructura mucho más rígida:

- mismo origen
- mismo puerto origen
- múltiples destinos
- puertos destino secuenciales
- baja varianza en bytes

---

## 10. Comparación con tráfico normal

Frente a los perfiles normales de calibración, el UDP Scan rompe la diversidad estadística de la red.

El tráfico normal se caracteriza por:

- mezcla de protocolos
- servicios conocidos como DNS, HTTP, HTTPS o NTP
- distribución más heterogénea de IPs
- ausencia de barridos secuenciales de puertos
- mayor variabilidad en bytes y duración

El UDP Scan, en cambio, presenta:

- protocolo UDP dominante
- origen fijo
- puerto origen fijo
- múltiples destinos
- puertos destino secuenciales
- duración cero
- baja varianza de bytes

---

## 11. Validación programática

Las hipótesis generadas por el LLM fueron validadas mediante el script:

```text
scripts/02_attack_analysis/detect_synthetic_behavior.py
```

El detector heurístico identificó correctamente las tres ventanas UDP Scan.

| Ventana | Resultado del detector |
|---|---|
| `anomaly-udpscan_window_1.csv` | UDP Scan |
| `anomaly-udpscan_window_2.csv` | UDP Scan |
| `anomaly-udpscan_window_3.csv` | UDP Scan |

---

## 12. Evidencia observada

| Ventana | Origen detectado | Flujos | IPs destino únicas | Puertos destino únicos | Secuencialidad dst_port | Varianza bytes |
|---|---|---:|---:|---:|---|---:|
| `anomaly-udpscan_window_1.csv` | `217.156.59.213:5061` | 1001 | 48 | 30 | Sí | 2.025 |
| `anomaly-udpscan_window_2.csv` | `217.156.59.213:5061` | 2001 | 134 | 30 | Sí | 1.778 |
| `anomaly-udpscan_window_3.csv` | `217.156.59.213:5061` | 2001 | 69 | 30 | Sí | 1.868 |

La evidencia confirma que el patrón identificado por el LLM es medible en los datos.

---

## 13. Regla de detección derivada

A partir del análisis, se puede formalizar una regla de detección para UDP Scan:

```text
Si existe un grupo UDP con:
- mismo src_ip
- mismo src_port
- múltiples dst_ip
- múltiples dst_port
- dst_port secuencial
- duración cercana a cero
- pocos paquetes por flujo
- baja varianza de bytes

entonces clasificar como posible UDP Scan.
```

Esta regla no depende de una IP concreta, sino de la estructura de exploración.

---

## 14. Relación con el modelo de comportamiento sintético

Dentro del modelo general de comportamiento sintético, el UDP Scan se caracteriza por la localización de la automatización en el espacio de destino.

El atacante no concentra todos los flujos hacia un único servicio, como en DoS, sino que explora sistemáticamente múltiples destinos y puertos.

Esto lo diferencia de:

- DoS, donde la automatización se encuentra en los puertos origen y la concentración hacia un único destino.
- NerisBotnet, donde la automatización se manifiesta como coordinación distribuida entre nodos.

---

## 15. Limitaciones

El análisis presenta varias limitaciones:

- se realiza sobre ventanas previamente extraídas
- no se ejecuta todavía sobre el dataset completo
- el detector es heurístico
- el puerto 5061 aparece como rasgo observado, pero la regla no debe depender exclusivamente de este puerto
- no se analizan respuestas ICMP de forma completa
- los umbrales se ajustan empíricamente

---

## 16. Conclusión

El ataque UDP Scan analizado en UGR'16 se caracteriza por una estrategia de reconocimiento automatizada mediante UDP.

El rasgo más relevante es la combinación de un origen fijo, puerto origen fijo, múltiples destinos, barrido secuencial de puertos destino, duración cero y baja varianza de bytes.

El LLM permitió identificar el patrón estructural del ataque y diferenciarlo del tráfico UDP normal, especialmente DNS.

La validación programática confirmó que las tres ventanas analizadas presentan el patrón esperado, reforzando la utilidad del enfoque combinado LLM + código para generar y verificar hipótesis sobre tráfico de red.
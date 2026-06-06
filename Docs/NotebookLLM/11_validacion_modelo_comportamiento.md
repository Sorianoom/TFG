# Validación del modelo de comportamiento sintético

## 1. Objetivo

El objetivo de este documento es validar experimentalmente el modelo de comportamiento sintético definido inicialmente para los ataques DoS, UDP Scan y NerisBotnet en el dataset UGR'16, y dejar documentada la integración conceptual posterior de nuevas familias de ataque: `scan11`, `scan44` y `anomaly-sshscan`.

La validación se realiza mediante un detector heurístico implementado en Python, que analiza ventanas temporales previamente extraídas y comprueba si los patrones identificados con ayuda del LLM son medibles en los datos.

El objetivo no es construir un IDS completo, sino comprobar si las hipótesis generadas durante el análisis asistido por LLM tienen correspondencia empírica.

---

## 2. Script utilizado

La validación se realizó mediante el script:

```text
scripts/02_attack_analysis/detect_synthetic_behavior.py
```

Este script analiza ventanas CSV almacenadas en:

```text
data/attack_analysis/
```

y genera como salida:

```text
data/attack_analysis/behavior_detection_results.csv
```

---

## 3. Archivos analizados

El detector se ejecutó sobre ventanas de ataque y perfiles normales.

### 3.1 Ventanas DoS

```text
data/attack_analysis/dos/dos_window_1.csv
data/attack_analysis/dos/dos_window_2.csv
data/attack_analysis/dos/dos_window_3.csv
```

### 3.2 Ventanas UDP Scan

```text
data/attack_analysis/anomaly-udpscan/anomaly-udpscan_window_1.csv
data/attack_analysis/anomaly-udpscan/anomaly-udpscan_window_2.csv
data/attack_analysis/anomaly-udpscan/anomaly-udpscan_window_3.csv
```

### 3.3 Ventanas NerisBotnet

```text
data/attack_analysis/nerisbotnet/nerisbotnet_window_1.csv
data/attack_analysis/nerisbotnet/nerisbotnet_window_2.csv
data/attack_analysis/nerisbotnet/nerisbotnet_window_3.csv
```

### 3.4 Perfiles normales

```text
data/attack_analysis/normal/normal_laboral.csv
data/attack_analysis/normal/normal_nocturno.csv
data/attack_analysis/normal/normal_transicion.csv
```

### 3.5 Nuevas ventanas extraídas pendientes de validación programática

Además de los ataques validados inicialmente, se extrajeron nuevas ventanas para ampliar el modelo:

```text
data/attack_analysis/scan11/scan11_window_1.csv
data/attack_analysis/scan11/scan11_window_2.csv
data/attack_analysis/scan11/scan11_window_3.csv

data/attack_analysis/scan44/scan44_window_1.csv
data/attack_analysis/scan44/scan44_window_2.csv
data/attack_analysis/scan44/scan44_window_3.csv

data/attack_analysis/anomaly-sshscan/anomaly-sshscan_window_1.csv
data/attack_analysis/anomaly-sshscan/anomaly-sshscan_window_2.csv
data/attack_analysis/anomaly-sshscan/anomaly-sshscan_window_3.csv
```

También se extrajo una única ventana para `anomaly-spam`:

```text
data/attack_analysis/anomaly-spam/anomaly-spam_window_1.csv
```

Este último caso se considera exploratorio debido al bajo número de muestras disponibles.

---

## 4. Métricas calculadas

El detector calcula métricas agregadas sobre cada ventana.

Entre las métricas principales se incluyen:

- número total de flujos
- etiqueta dominante
- etiquetas de ataque encontradas
- protocolo dominante
- IP origen dominante
- IP destino dominante
- puerto origen dominante
- puerto destino dominante
- número de IPs origen únicas
- número de IPs destino únicas
- número de puertos origen únicos
- número de puertos destino únicos
- duración media
- paquetes medios
- bytes medios
- varianza de bytes
- varianza de duración
- ratio de flujos con duración cercana a cero
- ratio de flujos con pocos paquetes
- ratio de flujos en el mismo timestamp
- concentración de IP origen
- concentración de IP destino
- concentración de puerto destino

Además, para cada tipo de ataque se calculan métricas específicas.

---

## 5. Validación de DoS

El detector busca grupos TCP con:

- misma IP origen
- misma IP destino
- mismo puerto destino
- duración cercana a cero
- pocos paquetes por flujo
- puertos origen secuenciales
- baja varianza de bytes
- concentración temporal

### Resultado

| Ventana | Resultado | Grupo detectado | Flujos | Secuencialidad | Varianza bytes |
|---|---|---|---:|---|---:|
| `dos_window_1.csv` | DoS | `42.219.150.246 → 42.219.158.16:80` | 25 | Sí | 0.00 |
| `dos_window_2.csv` | DoS | `42.219.150.246 → 42.219.158.16:80` | 86 | Sí | 0.00 |
| `dos_window_3.csv` | DoS | `42.219.150.246 → 42.219.158.16:80` | 166 | Sí | 0.00 |

### Interpretación

El modelo detecta correctamente las tres ventanas DoS.

Esto valida las hipótesis principales:

- concentración hacia un único destino
- puerto destino fijo
- duración cercana a cero
- secuencialidad de puertos origen
- baja varianza de bytes

---

## 6. Validación de UDP Scan

El detector busca grupos UDP con:

- misma IP origen
- mismo puerto origen
- múltiples IPs destino
- múltiples puertos destino
- puertos destino secuenciales
- duración cercana a cero
- pocos paquetes por flujo
- baja varianza de bytes

### Resultado

| Ventana | Resultado | Origen detectado | Flujos | IPs destino únicas | Puertos destino únicos | Secuencialidad dst_port | Varianza bytes |
|---|---|---|---:|---:|---:|---|---:|
| `anomaly-udpscan_window_1.csv` | UDP Scan | `217.156.59.213:5061` | 1001 | 48 | 30 | Sí | 2.025 |
| `anomaly-udpscan_window_2.csv` | UDP Scan | `217.156.59.213:5061` | 2001 | 134 | 30 | Sí | 1.778 |
| `anomaly-udpscan_window_3.csv` | UDP Scan | `217.156.59.213:5061` | 2001 | 69 | 30 | Sí | 1.868 |

### Interpretación

El modelo detecta correctamente las tres ventanas UDP Scan.

Esto valida las hipótesis principales:

- origen fijo
- puerto origen fijo
- múltiples destinos
- puertos destino secuenciales
- baja varianza de bytes
- duración cercana a cero

---

## 7. Validación de NerisBotnet

El detector busca grupos distribuidos con:

- múltiples IPs origen
- mismo destino
- mismo puerto destino
- mismo protocolo
- sincronización temporal
- puerto compatible con Command & Control
- baja varianza de bytes dentro del grupo

### Resultado

| Ventana | Resultado | Evidencia |
|---|---|---|
| `nerisbotnet_window_1.csv` | No clasificado | Pocos flujos `nerisbotnet`; sin grupo C2 distribuido suficiente |
| `nerisbotnet_window_2.csv` | No clasificado | Pocos flujos `nerisbotnet`; sin grupo C2 distribuido suficiente |
| `nerisbotnet_window_3.csv` | NerisBotnet | 20 IPs origen hacia `220.194.21.2:6667/TCP` |

### Evidencia de la ventana 3

| Métrica | Valor |
|---|---|
| Destino C2 | `220.194.21.2` |
| Puerto | `6667` |
| Protocolo | TCP |
| Timestamp | `2016-08-01 09:00:15` |
| Flujos detectados | 20 |
| IPs origen únicas | 20 |
| Paquetes medios | 4 |
| Bytes medios | 192 |
| Varianza de bytes | 0.00 |

### Interpretación

El detector solo clasifica la tercera ventana como NerisBotnet.

Este resultado es coherente con el modelo planteado, ya que las dos primeras ventanas no contienen suficiente evidencia estructural de coordinación distribuida.

A diferencia de DoS y UDP Scan, la detección de botnet requiere observar comportamiento colectivo y sincronizado.

---

## 8. Validación sobre tráfico normal

El detector también se ejecutó sobre perfiles normales de calibración.

| Perfil normal | Resultado |
|---|---|
| `normal_laboral.csv` | No clasificado |
| `normal_nocturno.csv` | No clasificado |
| `normal_transicion.csv` | No clasificado |

### Interpretación

Los perfiles normales no fueron clasificados como ataque.

Esto es especialmente importante porque demuestra que el detector no dispara alertas únicamente por la existencia de:

- tráfico UDP
- puertos comunes como 53 u 80
- flujos de baja duración
- ruido de fondo
- variabilidad propia de un ISP

El modelo exige estructura sintética clara para clasificar una ventana.

---

## 9. Resultados globales de la validación inicial

| Tipo de ventana | Ventanas detectadas | Total | Resultado |
|---|---:|---:|---|
| DoS | 3 | 3 | Correcto |
| UDP Scan | 3 | 3 | Correcto |
| NerisBotnet | 1 | 3 | Correcto cuando existe evidencia C2 suficiente |
| Normal | 0 | 3 | Sin falsos positivos |

---

## 10. Relación con las hipótesis generadas por LLM

La validación confirma que varias hipótesis generadas durante el análisis asistido por LLM son medibles en las trazas reales.

| Hipótesis | Validación |
|---|---|
| DoS presenta concentración hacia un único destino | Confirmada |
| DoS presenta puertos origen secuenciales | Confirmada |
| UDP Scan presenta puerto origen fijo y destino secuencial | Confirmada |
| UDP Scan no debe confundirse con DNS normal | Confirmada |
| NerisBotnet requiere evidencia distribuida C2 | Confirmada parcialmente |
| El tráfico normal mantiene diversidad suficiente para no clasificarse como ataque | Confirmada |

---

## 11. Interpretación técnica de la validación inicial

Los resultados muestran que los ataques DoS y UDP Scan presentan patrones sintéticos muy claros.

Ambos se caracterizan por:

- baja duración
- baja varianza
- repetición estructural
- comportamiento mecanizado

Sin embargo, difieren en la localización de la automatización:

- DoS: automatización en el origen
- UDP Scan: automatización en el espacio de destino

NerisBotnet requiere un análisis distinto, ya que la estructura no aparece necesariamente en un único flujo, sino en la coordinación entre múltiples nodos.

---

## 12. Nuevas categorías integradas conceptualmente

Tras la validación inicial de DoS, UDP Scan y NerisBotnet, se analizaron nuevas familias de ataque mediante el mismo enfoque asistido por LLM.

Estas nuevas familias son:

- `scan11`
- `scan44`
- `anomaly-sshscan`

A diferencia de DoS y UDP Scan, estas categorías todavía no han sido validadas formalmente mediante el detector heurístico, pero sí han sido integradas conceptualmente en el modelo de comportamiento sintético.

---

## 13. scan11: Single-Source Vertical Scan

El ataque `scan11` se interpreta como un escaneo TCP vertical de fuente única.

Su patrón estructural es:

```text
1 origen → 1 destino → muchos puertos
```

La automatización se localiza en el barrido de servicios del host objetivo.

### Indicadores principales

- protocolo TCP
- único origen
- único destino
- múltiples puertos destino
- duración 0.000s
- un paquete por flujo
- bytes reducidos, aproximadamente 44 bytes
- predominio de intentos de conexión incompletos
- comportamiento de reconocimiento, no de saturación

### Estado

`scan11` queda integrado conceptualmente en el modelo como:

```text
Single-Source Vertical Scan
```

Pendiente de validación programática mediante adaptación del detector heurístico.

---

## 14. scan44: Distributed Vertical Scan

El ataque `scan44` se interpreta como una variante distribuida del escaneo TCP vertical.

Su patrón estructural es:

```text
muchos orígenes → muchos destinos → muchos puertos por destino
```

La automatización se localiza en la coordinación distribuida de varios orígenes y en el barrido de servicios de múltiples hosts.

### Indicadores principales

- protocolo TCP
- múltiples IPs origen
- múltiples IPs destino
- múltiples puertos destino por host
- duración 0.000s
- un paquete por flujo
- bytes reducidos
- sincronización temporal
- comportamiento de reconocimiento distribuido

### Estado

`scan44` queda integrado conceptualmente en el modelo como:

```text
Distributed Vertical Scan
```

Pendiente de validación programática mediante adaptación del detector heurístico.

---

## 15. anomaly-sshscan: SSH Horizontal Scan

El ataque `anomaly-sshscan` se interpreta como un escaneo TCP horizontal especializado en SSH.

Su patrón estructural es:

```text
1 origen → muchos destinos → puerto fijo 22
```

La automatización se localiza en la selección horizontal de IPs destino.

### Indicadores principales

- protocolo TCP
- mismo origen
- múltiples destinos externos
- puerto destino fijo 22
- duración 0.000s
- un paquete por flujo
- bytes entre 40 y 44
- ausencia de sesiones SSH completas
- posible comportamiento de nodo interno comprometido

### Estado

`anomaly-sshscan` queda integrado conceptualmente en el modelo como:

```text
SSH Horizontal Scan
```

Pendiente de validación programática mediante adaptación del detector heurístico.

---

## 16. Estado de validación ampliado

| Tipo | Ventanas analizadas | Validación programática | Estado |
|---|---:|---|---|
| DoS | 3 | Sí | Validado |
| UDP Scan | 3 | Sí | Validado |
| NerisBotnet | 3 | Parcial | Validado con matices |
| Normal | 3 | Sí | Sin falsos positivos |
| scan11 | 3 | No | Integrado conceptualmente |
| scan44 | 3 | No | Integrado conceptualmente |
| anomaly-sshscan | 3 | No | Integrado conceptualmente |
| anomaly-spam | 1 | No | Caso exploratorio de baja evidencia |

---

## 17. Trabajo pendiente de validación

Las nuevas categorías requieren adaptar el detector heurístico para medir sus invariantes estructurales.

### 17.1 Para scan11

```text
mismo src_ip
mismo dst_ip
muchos dst_port únicos
TCP
duration == 0.000s
packets == 1
bytes ≈ 44
```

### 17.2 Para scan44

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

### 17.3 Para anomaly-sshscan

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

## 18. Limitaciones de la validación

La validación presenta varias limitaciones:

- se realiza sobre ventanas previamente extraídas
- no se aplica todavía sobre el dataset completo
- el detector es heurístico
- los umbrales fueron ajustados empíricamente
- NerisBotnet requiere ventanas con suficiente contexto distribuido
- las nuevas categorías de escaneo TCP todavía no están implementadas en el detector
- no se realiza aprendizaje automático
- no se pretende construir un IDS final
- `anomaly-spam` solo dispone de una ventana, por lo que se tratará como caso exploratorio

---

## 19. Conclusión

La validación experimental confirma que las hipótesis generadas mediante LLM pueden transformarse en reglas medibles sobre tráfico NetFlow.

El detector heurístico valida correctamente los patrones DoS y UDP Scan en todas las ventanas analizadas, y detecta NerisBotnet cuando existe evidencia suficiente de coordinación C2.

El análisis sobre perfiles normales no genera falsos positivos, lo que refuerza la utilidad del enfoque basado en comportamiento.

Además, el análisis asistido por LLM permitió ampliar conceptualmente el modelo con nuevas familias de escaneo:

- `scan11` como Single-Source Vertical Scan
- `scan44` como Distributed Vertical Scan
- `anomaly-sshscan` como SSH Horizontal Scan

Estas nuevas categorías quedan pendientes de validación programática, pero ya están formalizadas mediante invariantes estructurales claros.

Este resultado apoya la metodología del trabajo: utilizar LLMs para generar explicaciones e hipótesis, y validar posteriormente dichas hipótesis mediante código.
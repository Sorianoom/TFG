# Especificación técnica para detector heurístico ampliado con Claude Code

## 1. Objetivo

El objetivo de este documento es definir una especificación técnica para ampliar el detector heurístico de comportamiento sintético desarrollado en el TFG.

La especificación se basa en los resultados multifuente obtenidos con NotebookLM para los ataques:

* `dos`
* `anomaly-udpscan`
* `nerisbotnet`
* `scan11`
* `scan44`
* `anomaly-sshscan`
* `anomaly-spam`

El objetivo no es construir un IDS completo, sino validar programáticamente si los patrones descritos por NotebookLM son medibles en las ventanas reales del dataset UGR'16.

---

## 2. Entrada del detector

El detector debe analizar ventanas CSV almacenadas en:

```text
data/attack_analysis/
```

y/o en los paquetes generados para NotebookLM:

```text
data/notebooklm_attack_packages/
```

Cada ventana contiene flujos NetFlow con campos equivalentes a:

```text
timestamp
duration
src_ip
dst_ip
src_port
dst_port
protocol
flags
tos
packets
bytes
label
```

La implementación debe adaptarse a la estructura real de columnas del proyecto.

---

## 3. Salida esperada

El detector debe generar un CSV de resultados con una fila por ventana analizada.

Archivo sugerido:

```text
data/attack_analysis/behavior_detection_results_extended.csv
```

Campos mínimos recomendados:

```text
file
attack_expected
attack_detected
predicted_category
confidence_level
total_flows
attack_label_rows
dominant_label
dominant_protocol
unique_src_ips
unique_dst_ips
unique_src_ports
unique_dst_ports
avg_duration
avg_packets
avg_bytes
bytes_variance
duration_variance
zero_duration_ratio
low_packet_ratio
top_src_ip
top_dst_ip
top_src_port
top_dst_port
top_flags
evidence_summary
limitations
```

Además, puede incluir campos específicos por familia de ataque si son necesarios para explicar mejor la detección.

---

## 4. Métricas generales que debe calcular

Para cada ventana, el detector debe calcular como mínimo:

* total de flujos
* distribución de etiquetas
* protocolo dominante
* IPs origen únicas
* IPs destino únicas
* puertos origen únicos
* puertos destino únicos
* duración media
* paquetes medios
* bytes medios
* varianza de duración
* varianza de bytes
* ratio de duración cercana a cero
* ratio de flujos con pocos paquetes
* flags dominantes
* timestamps dominantes
* concentración de IP origen
* concentración de IP destino
* concentración de puerto destino
* número de flujos por segundo
* máximo de flujos en un mismo timestamp
* cardinalidad de puertos destino por par `src_ip/dst_ip`
* cardinalidad de IPs destino por `src_ip`
* cardinalidad de IPs origen por `dst_ip`
* secuencialidad de puertos origen
* secuencialidad de puertos destino

---

## 5. Reglas conceptuales por ataque

### 5.1 DoS

### Categoría

`Distributed TCP Flood / TCP DoS`

### Patrón esperado

Ataque de inundación TCP dirigido principalmente al puerto 80, con flujos de muy corta duración, baja variabilidad métrica y secuencialidad en puertos origen.

### Señales fuertes

* protocolo TCP
* puerto destino dominante 80
* duración cercana a cero
* 1 o 2 paquetes por flujo
* bytes repetitivos, especialmente 40, 160 o 200
* puertos origen secuenciales
* ráfagas temporales densas
* flags de control TCP como SYN, RESET/SYN o ACK/SYN

### Métricas a validar

* ratio de flujos TCP
* concentración en `dst_port == 80`
* secuencialidad de `src_port`
* ratio de `duration <= 0.01`
* varianza de bytes baja
* flujos por timestamp
* número de IPs origen implicadas
* número de IPs destino implicadas

### Criterio conceptual

Clasificar como DoS si una ventana presenta alta concentración TCP hacia un puerto destino fijo, baja duración, baja varianza de bytes y secuencialidad clara en puertos origen.

El detector no debe depender únicamente del puerto 80. El puerto puede utilizarse como evidencia fuerte, pero la clasificación debe basarse en la combinación de concentración, baja duración, baja variabilidad y secuencialidad.

---

## 5.2 anomaly-udpscan

### Categoría

`UDP Hybrid Scan / UDP Low-Entropy Scan`

### Patrón esperado

Escaneo UDP desde una IP origen dominante hacia múltiples IPs destino y múltiples puertos destino, con flujos atómicos y barrido secuencial de puertos.

### Señales fuertes

* protocolo UDP
* IP origen dominante
* puertos origen fijos por ráfaga, especialmente 5061, 5062, 5066 o 5068
* múltiples IPs destino
* múltiples puertos destino
* puertos destino secuenciales
* `duration == 0`
* `packets == 1`
* bytes aproximadamente entre 428 y 436
* baja varianza de bytes

### Métricas a validar

* `unique_dst_ips` por `src_ip`
* `unique_dst_ports` por `src_ip`
* secuencialidad de `dst_port`
* ratio de `packets == 1`
* ratio de `duration == 0`
* varianza de bytes
* concentración de `src_ip`
* `flows_per_second` por `src_ip`

### Criterio conceptual

Clasificar como UDP Scan si una IP origen genera muchos flujos UDP de baja entropía hacia múltiples destinos y puertos destino secuenciales.

El patrón no debe confundirse con tráfico DNS normal. La diferencia principal no es solo el uso de UDP, sino la combinación de origen estable, dispersión de destinos, barrido de puertos y baja variabilidad métrica.

---

## 5.3 scan11

### Categoría

`Single-Source Vertical Scan`

### Patrón esperado

Escaneo vertical TCP SYN desde un único origen hacia un único destino, recorriendo muchos puertos destino.

### Señales fuertes

* protocolo TCP
* topología 1→1 a nivel IP
* muchos `dst_port` únicos para el mismo par `src_ip/dst_ip`
* `duration == 0`
* `packets == 1`
* bytes aproximadamente 44
* flag SYN dominante
* ráfagas de alta densidad temporal
* puerto origen fijo por ráfaga, pero no necesariamente fijo globalmente

### Métricas a validar

* `unique_dst_ports` por par `src_ip/dst_ip`
* ratio TCP
* ratio SYN
* ratio de `duration == 0`
* ratio de `packets == 1`
* `bytes_mode` o `bytes_mean` cercano a 44
* varianza de bytes baja
* flujos por timestamp
* concentración en una única pareja `src_ip/dst_ip`

### Criterio conceptual

Clasificar como Single-Source Vertical Scan si un único origen realiza un barrido masivo de puertos TCP sobre un único host destino con flujos SYN atómicos.

No debe confundirse con DoS aunque ambos puedan presentar topología 1→1. La diferencia principal es que en DoS el puerto destino tiende a ser fijo, mientras que en scan11 existe alta diversidad de puertos destino sobre un mismo host.

---

## 5.4 scan44

### Categoría

`Distributed Vertical Scan`

### Patrón esperado

Escaneo vertical TCP distribuido, donde varios orígenes coordinados realizan barridos de puertos sobre varios destinos.

### Señales fuertes

* protocolo TCP
* múltiples `src_ip`
* múltiples `dst_ip`
* muchos `dst_port` únicos por `dst_ip`
* `duration == 0`
* `packets == 1`
* bytes aproximadamente 44 en SYN
* respuestas de 40 bytes RST/ACK en algunos casos
* sincronización temporal entre varios orígenes
* posible pertenencia de los orígenes a una misma subred
* ráfagas periódicas o simultáneas

### Métricas a validar

* `unique_src_ips`
* `unique_dst_ips`
* `unique_dst_ports` por `dst_ip`
* `unique_dst_ports` por par `src_ip/dst_ip`
* ratio TCP
* ratio SYN
* ratio de `duration == 0`
* ratio de `packets == 1`
* `bytes_mode` cercano a 44
* número de `src_ip` activas en el mismo timestamp
* agrupación de `src_ip` por prefijo `/24`
* flujos por segundo

### Criterio conceptual

Clasificar como Distributed Vertical Scan si varios orígenes generan escaneos TCP SYN de baja entropía, sincronizados temporalmente y dirigidos a múltiples destinos con muchos puertos destino por host.

Este patrón puede entenderse como una extensión distribuida de scan11. La diferencia principal es que la automatización no reside solo en el barrido vertical de puertos, sino también en la coordinación entre varios orígenes.

---

## 5.5 anomaly-sshscan

### Categoría

`Low-and-Slow SSH Horizontal Scan`

### Patrón esperado

Sondeo horizontal de baja intensidad desde una IP interna hacia múltiples destinos externos en el puerto 22.

### Señales fuertes

* protocolo TCP
* `src_ip` dominante
* `dst_port == 22`
* múltiples `dst_ip`
* `duration == 0`
* `packets == 1`
* bytes entre 40 y 44
* flags RST o flags de control TCP
* bajo volumen
* persistencia temporal del mismo origen

### Métricas a validar

* `unique_dst_ips` por `src_ip` hacia `dst_port == 22`
* ratio de `duration == 0`
* ratio de `packets == 1`
* bytes menores o iguales a 44
* flags dominantes
* número de ventanas en las que aparece el mismo `src_ip`
* comparación con SSH legítimo si existe
* ratio de sesiones SSH completas frente a intentos incompletos

### Criterio conceptual

Clasificar como SSH Horizontal Scan si una IP origen mantiene intentos TCP incompletos hacia puerto 22 en múltiples destinos, aunque el volumen sea bajo.

### Nota importante

Este ataque no debe detectarse únicamente por volumen. Es un patrón low-and-slow. Requiere análisis de persistencia e incompletitud, no solo umbrales altos de flujos.

El hecho de que el origen sea interno puede interpretarse como indicio de un nodo comprometido o de comportamiento anómalo saliente, pero esa interpretación debe tratarse como hipótesis si no se valida con más contexto.

---

## 5.6 NerisBotnet

### Categoría

`Botnet multivector orquestada / Distributed C2`

### Patrón esperado

Actividad coordinada de un clúster de IPs internas que ejecutan ráfagas sincronizadas en varios protocolos y servicios, incluyendo SMTP, IRC/C2 y UDP.

### Señales fuertes

* múltiples `src_ip` actuando de forma sincronizada
* timestamps iguales o muy próximos
* métricas idénticas entre nodos
* SMTP puerto 25 con 6 paquetes y 288 bytes
* IRC puerto 6667 con 4 paquetes y 192 bytes
* UDP con puerto origen 2077
* flujos con bytes y duración muy repetitivos
* comportamiento multivector

### Métricas a validar

* número de `src_ip` distintas por timestamp
* grupos con mismos bytes, packets, duration y dst_port
* correlación entre IPs origen y servicios
* detección de clústeres de bots
* varianza de bytes por grupo
* varianza de duración por grupo
* presencia de puertos 25, 6667, 53 y 2077
* periodicidad de ráfagas

### Criterio conceptual

Clasificar como NerisBotnet si existe un clúster de múltiples IPs origen ejecutando acciones similares de forma sincronizada, con baja varianza métrica y posibles patrones C2 o spam.

### Nota importante

Este ataque no debe detectarse como flujo individual. La señal está en la correlación entre nodos.

NerisBotnet puede no aparecer claramente en todas las ventanas. Si una ventana contiene pocos flujos de la etiqueta o no muestra coordinación suficiente, el detector debe registrar evidencia insuficiente en lugar de forzar una clasificación.

---

## 5.7 anomaly-spam

### Categoría

`SMTP Spam Burst / Low-Entropy SMTP Campaign`

### Patrón esperado

Campaña de spam de bajo volumen basada en conexiones TCP hacia puerto 25, con métricas de paquetes y bytes muy repetitivas.

### Señales fuertes

* protocolo TCP
* puerto destino 25
* origen externo o bloque de origen externo
* múltiples `dst_ip`
* flujos con 8-13 paquetes
* bytes repetitivos como 763, 815, 841, 893, 3136 o 3143
* flags `.AP.SF` o `.APRS.`
* baja varianza de bytes y paquetes
* ratio de ataque bajo

### Métricas a validar

* flujos TCP hacia `dst_port == 25`
* `unique_dst_ips` por `src_ip`
* varianza de bytes por `src_ip`
* varianza de paquetes por `src_ip`
* repetición de tuplas `packets/bytes`
* inter-arrival time entre flujos
* concentración por bloque de IP origen

### Criterio conceptual

Clasificar como anomaly-spam si existe un patrón SMTP horizontal de bajo volumen con repetición fuerte de tamaño y paquetes hacia múltiples destinos.

### Nota importante

Este caso debe tratarse como exploratorio o de baja evidencia si el número de muestras disponibles es bajo.

El detector puede generar una categoría de baja confianza o evidencia parcial para anomaly-spam, pero no debe utilizarlo como validación fuerte del modelo si las muestras son escasas.

---

# 6. Prioridad de implementación

Claude Code debe implementar primero las categorías más robustas:

1. `scan11`
2. `scan44`
3. `anomaly-udpscan`
4. `dos`
5. `nerisbotnet`
6. `anomaly-sshscan`
7. `anomaly-spam`

Motivo:

* `scan11`, `scan44`, `anomaly-udpscan` y `dos` tienen firmas métricas muy claras.
* `nerisbotnet` requiere correlación distribuida.
* `anomaly-sshscan` requiere persistencia temporal y detección de bajo volumen.
* `anomaly-spam` tiene baja evidencia y mayor riesgo de confusión con tráfico legítimo.

---

# 7. Requisitos de diseño del código

El detector debe estar modularizado.

Funciones recomendadas:

```text
load_window(path)
compute_general_metrics(df)
detect_dos(df)
detect_udp_scan(df)
detect_single_source_vertical_scan(df)
detect_distributed_vertical_scan(df)
detect_ssh_horizontal_scan(df)
detect_nerisbotnet(df)
detect_spam_campaign(df)
run_detection_on_folder(input_dir)
save_results(results, output_path)
```

Cada función de detección debe devolver una estructura similar a:

```text
detected: bool
score/confidence
evidence: dict
limitations: list
```

El detector debe permitir ajustar umbrales fácilmente mediante constantes al inicio del script.

---

# 8. Reglas de decisión

El detector no debe depender de una única métrica aislada.

Debe combinar:

* topología
* protocolo
* puertos
* duración
* paquetes
* bytes
* flags
* concentración
* dispersión
* secuencialidad
* sincronización temporal

Ejemplo:

```text
duration == 0
```

no debe bastar para clasificar un ataque.

Pero:

```text
duration == 0
packets == 1
bytes ≈ 44
TCP SYN
muchos dst_port únicos
mismo src_ip y dst_ip
```

sí puede ser evidencia fuerte de scan11.

La clasificación debe intentar devolver:

* categoría detectada
* nivel de confianza
* evidencia concreta
* limitaciones de la ventana

---

# 9. Limitaciones que debe respetar Claude Code

El detector:

* no debe presentarse como IDS completo
* no debe entrenar modelos de Machine Learning
* no debe usar la etiqueta como criterio principal
* no debe depender de IPs concretas como regla final
* puede usar IPs concretas solo como evidencia de validación
* debe funcionar sobre ventanas ya extraídas
* debe generar resultados interpretables
* debe permitir ajustar umbrales fácilmente
* debe registrar evidencia insuficiente cuando no haya señal bastante
* debe conservar el detector anterior sin romperlo

---

# 10. Instrucciones directas para Claude Code

A partir de esta especificación, implementa o adapta el detector heurístico existente.

## Objetivo

Validar programáticamente si las hipótesis generadas mediante NotebookLM son medibles en las ventanas reales del dataset UGR'16.

No construyas un IDS completo.

No entrenes un modelo de Machine Learning.

No uses las etiquetas como criterio de detección, salvo para evaluar posteriormente si la clasificación coincide con la etiqueta esperada.

## Requisitos del detector

El detector debe:

1. recorrer las carpetas de ataque dentro de:

```text
data/attack_analysis/
```

2. analizar ventanas CSV
3. calcular métricas generales
4. aplicar detectores heurísticos por familia
5. devolver la categoría detectada
6. guardar un CSV de resultados
7. incluir evidencia textual o estructurada que explique cada detección
8. registrar limitaciones cuando la evidencia sea insuficiente

Archivo sugerido:

```text
scripts/02_attack_analysis/detect_synthetic_behavior_extended.py
```

Salida sugerida:

```text
data/attack_analysis/behavior_detection_results_extended.csv
```

El código debe estar escrito de forma clara, modular y mantenible.

Prioriza interpretabilidad sobre complejidad.

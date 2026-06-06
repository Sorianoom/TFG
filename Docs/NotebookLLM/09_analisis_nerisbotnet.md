# Análisis del ataque NerisBotnet

## 1. Objetivo

El objetivo de este análisis es estudiar el comportamiento de las ventanas etiquetadas como `nerisbotnet` en el dataset UGR'16.

A diferencia de los ataques DoS y UDP Scan, NerisBotnet no presenta únicamente un patrón simple de concentración o exploración. Su comportamiento es más complejo, ya que puede combinar fases de probing, comunicación distribuida y coordinación mediante canales de Command & Control.

El análisis se centra en identificar patrones estructurales globales y no en describir cada línea de forma individual.

---

## 2. Datos utilizados

Se analizaron tres ventanas temporales:

| Archivo | Descripción |
|---|---|
| `nerisbotnet_window_1.csv` | Primera ventana NerisBotnet |
| `nerisbotnet_window_2.csv` | Segunda ventana NerisBotnet |
| `nerisbotnet_window_3.csv` | Tercera ventana NerisBotnet |

También se utilizaron como referencia los perfiles normales de calibración:

- `normal_laboral.csv`
- `normal_nocturno.csv`
- `normal_transicion.csv`

Estas ventanas contienen tráfico de fondo mezclado con tráfico etiquetado como `nerisbotnet`, por lo que el análisis debe centrarse en identificar subestructuras relevantes dentro de la ventana.

---

## 3. Análisis asistido por LLM

Las ventanas NerisBotnet fueron proporcionadas al LLM para identificar patrones comunes de comportamiento.

El LLM interpretó NerisBotnet como un comportamiento distribuido y coordinado, diferente a los ataques sintéticos simples previamente analizados.

La hipótesis principal generada fue que la automatización no reside en un único origen ni en el barrido de puertos, sino en la coordinación temporal de múltiples nodos.

---

## 4. Patrón estructural observado

El comportamiento observado se puede describir como una topología híbrida.

El botnet puede presentar dos patrones:

```text
1 origen → muchos destinos
```

y también:

```text
muchos orígenes → 1 destino
```

Esto lo diferencia claramente de los ataques anteriores:

- DoS: `1 origen → 1 destino`
- UDP Scan: `1 origen → muchos destinos`
- NerisBotnet: estructura híbrida y distribuida

---

## 5. Identificación de roles

### 5.1 Fase 1→Muchos

En algunas ventanas aparece una IP externa interactuando con múltiples direcciones internas del ISP.

El LLM identificó como ejemplo la IP:

```text
216.236.161.251
```

Este comportamiento puede interpretarse como una fase de probing, interacción inicial o intento de propagación.

---

### 5.2 Fase Muchos→1

La estructura más relevante aparece cuando múltiples IPs internas se comunican de forma sincronizada hacia un único destino externo.

En la tercera ventana se observa una comunicación distribuida hacia:

```text
220.194.21.2:6667/TCP
```

Este patrón es compatible con comunicación hacia un canal de Command & Control.

---

## 6. Estructura de comunicación

### 6.1 Puerto 6667

El puerto más relevante del análisis es:

```text
6667
```

Este puerto está tradicionalmente asociado a IRC, un protocolo utilizado históricamente por botnets para comunicación de Command & Control.

En la ventana 3, múltiples IPs internas se comunican con el mismo destino externo mediante este puerto.

---

### 6.2 Puerto 4506

El análisis asistido por LLM también identificó el puerto:

```text
4506
```

como posible canal de coordinación en otras muestras del comportamiento NerisBotnet.

En este documento se mantiene como observación del análisis LLM, aunque la validación programática principal se centra en la evidencia C2 observada en la tercera ventana.

---

### 6.3 Puerto 53413

También se identificó tráfico UDP hacia el puerto:

```text
53413
```

Este patrón aparece asociado a posibles fases de probing o interacción externa hacia múltiples nodos internos.

---

## 7. Métricas de flujo

El botnet presenta métricas variables según la fase de actividad.

A diferencia de DoS y UDP Scan, no siempre tiene entropía uniformemente baja en toda la ventana.

### 7.1 Fase de coordinación C2

En la ventana 3, el patrón C2 detectado presenta flujos homogéneos:

```text
packets = 4
bytes = 192
```

La validación programática detectó:

```text
bytes_var = 0.00
```

Esto indica que los nodos ejecutan una acción coordinada con métricas idénticas.

---

### 7.2 Fase de probing

En otras zonas de las ventanas aparecen flujos UDP pequeños, con pocos paquetes y tamaños reducidos.

Estos flujos pueden asociarse a probing o interacción previa, pero no se clasifican automáticamente como botnet si no existe evidencia distribuida suficiente.

---

### 7.3 Duración

En varias trazas se observan duraciones bajas o cercanas a cero, pero en NerisBotnet la duración no es el único criterio relevante.

La clave no está solo en la duración, sino en la sincronización entre múltiples nodos.

---

## 8. Comportamiento temporal

El rasgo más distintivo de NerisBotnet es la sincronización temporal.

En la tercera ventana se observa que múltiples IPs internas contactan con el mismo destino externo en el mismo instante temporal.

El detector identificó el siguiente grupo:

```text
20 IPs origen → 220.194.21.2:6667/TCP
timestamp: 2016-08-01 09:00:15
```

Este patrón indica que los nodos no actúan de forma independiente, sino coordinada.

---

## 9. Diferencias con tráfico normal

El tráfico normal del ISP se caracteriza por:

- diversidad de IPs
- diversidad de servicios
- variabilidad en tamaños y duraciones
- independencia estadística entre usuarios
- ausencia de sincronización masiva hacia un mismo C2

En cambio, NerisBotnet presenta:

- múltiples nodos actuando simultáneamente
- mismo destino externo
- mismo puerto C2
- métricas de flujo idénticas
- sincronización temporal

La diferencia clave no es solo el volumen, sino la pérdida de independencia entre nodos.

---

## 10. Diferencias con DoS y UDP Scan

### 10.1 Diferencia con DoS

El DoS observado se caracteriza por:

```text
1 origen → 1 destino
```

El ataque concentra flujos desde un origen hacia un objetivo.

NerisBotnet, en cambio, puede mostrar:

```text
muchos orígenes → 1 destino
```

La actividad individual de cada nodo puede ser baja, pero el patrón colectivo es anómalo.

---

### 10.2 Diferencia con UDP Scan

El UDP Scan se caracteriza por:

```text
1 origen → muchos destinos
```

con barrido secuencial de puertos destino.

NerisBotnet no se define principalmente por la secuencialidad de puertos, sino por la coordinación de nodos y el uso de puertos persistentes de C2.

---

## 11. Validación programática

Las hipótesis generadas por el LLM fueron validadas mediante el script:

```text
scripts/02_attack_analysis/detect_synthetic_behavior.py
```

El detector clasificó como NerisBotnet únicamente la tercera ventana.

| Ventana | Resultado del detector |
|---|---|
| `nerisbotnet_window_1.csv` | No clasificado |
| `nerisbotnet_window_2.csv` | No clasificado |
| `nerisbotnet_window_3.csv` | NerisBotnet |

Este resultado es coherente con la evidencia disponible: las dos primeras ventanas contienen muy pocos flujos etiquetados como `nerisbotnet`, mientras que la tercera sí contiene una estructura distribuida C2 clara.

---

## 12. Evidencia observada

En la tercera ventana, el detector encontró:

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

Esta evidencia confirma el patrón de coordinación distribuida.

---

## 13. Regla de detección derivada

A partir del análisis, se puede formalizar una regla para NerisBotnet:

```text
Si existe un grupo de flujos con:
- múltiples src_ip
- mismo dst_ip
- mismo dst_port
- mismo protocolo
- mismo timestamp o intervalo temporal muy reducido
- puerto asociado a C2
- baja varianza en bytes
- métricas homogéneas entre nodos

entonces clasificar como posible comportamiento botnet/C2.
```

A diferencia de DoS y UDP Scan, esta regla requiere observar comportamiento colectivo.

---

## 14. Relación con el modelo de comportamiento sintético

Dentro del modelo de comportamiento sintético, NerisBotnet se caracteriza por:

```text
automatización distribuida en red
```

La automatización no reside en un único origen ni en el barrido del destino.

La estructura del ataque aparece en la coordinación entre múltiples nodos que actúan como una entidad lógica.

Esto lo diferencia de:

- DoS: automatización en el origen.
- UDP Scan: automatización en el espacio de destino.
- NerisBotnet: automatización en la distribución y sincronización de nodos.

---

## 15. Limitaciones

El análisis presenta varias limitaciones:

- las ventanas contienen mezcla de background y ataque
- las ventanas 1 y 2 contienen poca evidencia etiquetada como `nerisbotnet`
- el detector solo clasifica cuando existe evidencia C2 clara
- no se analiza todavía la periodicidad a largo plazo del beaconing
- no se ejecuta aún sobre el dataset completo
- el detector es heurístico y depende de reglas estructurales

Estas limitaciones son especialmente relevantes en botnets, donde el comportamiento puede ser más disperso y menos evidente que en ataques sintéticos simples.

---

## 16. Conclusión

El análisis de NerisBotnet revela un comportamiento más complejo que DoS y UDP Scan.

Mientras que DoS y UDP Scan presentan patrones locales claros, NerisBotnet requiere observar relaciones distribuidas entre múltiples nodos.

La evidencia más sólida aparece en la tercera ventana, donde 20 IPs internas contactan simultáneamente con `220.194.21.2:6667/TCP`, con métricas homogéneas.

El LLM permitió formular la hipótesis de coordinación distribuida, y el detector heurístico permitió validarla en la tercera ventana.

Este análisis demuestra que el uso de LLMs puede ser especialmente útil para interpretar amenazas complejas, siempre que sus conclusiones se contrasten posteriormente con evidencia programática.
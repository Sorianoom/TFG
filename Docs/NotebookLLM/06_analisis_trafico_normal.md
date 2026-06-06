# Análisis de tráfico normal

## 1. Objetivo

El objetivo de este análisis es establecer una línea base de normalidad del tráfico de red en el dataset UGR'16.

Para ello se utilizaron perfiles extraídos del conjunto de calibración, correspondiente a tráfico de fondo capturado en un ISP español mediante NetFlow v9.

El análisis de tráfico normal es necesario para poder comparar posteriormente las ventanas de ataque y detectar desviaciones respecto al comportamiento esperado de la red.

---

## 2. Archivos analizados

Se analizaron tres perfiles normales:

| Archivo | Perfil representado |
|---|---|
| `normal_laboral.csv` | Tráfico en horario laboral |
| `normal_nocturno.csv` | Tráfico en horario nocturno |
| `normal_transicion.csv` | Tráfico en horario de transición |

Estos perfiles fueron proporcionados al LLM para que identificara patrones generales de comportamiento normal.

---

## 3. Análisis asistido por LLM

El LLM analizó los perfiles normales de calibración y describió el comportamiento general de cada uno de ellos.

La respuesta generada identificó diferencias entre perfiles laborales, nocturnos y de transición, destacando la existencia de cicloestacionariedad en el tráfico del ISP.

El análisis no buscaba detectar ataques, sino caracterizar el tráfico legítimo de fondo.

---

## 4. Comportamiento general de cada perfil

### 4.1 Horario laboral

El perfil laboral presenta una alta densidad de flujos por segundo y una actividad diversificada.

El LLM lo interpreta como un comportamiento compatible con uso empresarial o administrativo, donde aparecen simultáneamente distintos tipos de tráfico:

- navegación web
- correo electrónico
- consultas a servicios
- conexiones a bases de datos
- tráfico interactivo TCP

Este perfil se caracteriza por mayor diversidad de servicios y mayor actividad humana directa.

---

### 4.2 Horario nocturno

El perfil nocturno muestra una reducción en la variedad de tráfico.

Aunque sigue existiendo actividad de red, el comportamiento se interpreta como menos interactivo y más asociado a procesos automáticos o de mantenimiento.

Se observan ráfagas de flujos UDP cortos y repetitivos, especialmente compatibles con servicios de infraestructura como:

- DNS
- NTP
- telemetría
- mantenimiento automático

Este perfil es importante porque demuestra que no todo tráfico UDP breve debe considerarse malicioso.

---

### 4.3 Horario de transición

El perfil de transición presenta un comportamiento híbrido entre el horario laboral y el uso residencial o no laboral.

El LLM identificó que se mantiene un volumen elevado de tráfico web, especialmente HTTP/S, pero con una cadencia diferente respecto al horario laboral.

Este perfil puede incluir:

- navegación web
- descargas
- actualizaciones
- servicios de ocio
- tráfico de finalización de jornada

---

## 5. Diferencias entre perfiles

La diferencia principal entre los perfiles está relacionada con la cicloestacionariedad del tráfico.

El tráfico no se comporta igual durante todo el día. La red presenta variaciones naturales en función del horario.

| Perfil | Característica principal |
|---|---|
| Laboral | Mayor diversidad de servicios e interacción humana |
| Nocturno | Mayor proporción de procesos automáticos y UDP corto |
| Transición | Mezcla entre tráfico laboral y tráfico residencial |

Estas diferencias son relevantes porque un comportamiento puede ser normal en un horario y sospechoso en otro.

Por ejemplo, una ráfaga UDP nocturna hacia DNS puede ser normal, mientras que un volumen elevado de tráfico SMTP o conexiones repetitivas hacia un único destino en horario anómalo podría ser sospechoso.

---

## 6. Puertos, protocolos y métricas predominantes

### 6.1 Protocolos

El análisis identificó que TCP domina en servicios interactivos, mientras que UDP aparece de forma recurrente en servicios de infraestructura.

| Protocolo | Uso habitual |
|---|---|
| TCP | Web, correo, conexiones interactivas |
| UDP | DNS, NTP, servicios automáticos |
| ICMP | Casos puntuales de control o diagnóstico |

---

### 6.2 Puertos predominantes

Los puertos más relevantes identificados fueron:

| Puerto | Servicio asociado |
|---:|---|
| 80 | HTTP |
| 443 | HTTPS |
| 25 | SMTP |
| 110 | POP3 |
| 53 | DNS |
| 123 | NTP |
| 3306 | MySQL |

La presencia de estos puertos se considera coherente con tráfico de fondo de un ISP.

---

### 6.3 Tamaño y duración de los flujos

El LLM destacó que la mayoría de los flujos normales tienden a ser pequeños, con pocos paquetes y tamaños moderados.

Sin embargo, también pueden aparecer flujos de background de gran tamaño, asociados a transferencias prolongadas o servicios legítimos.

Esto es importante porque el volumen elevado por sí solo no implica necesariamente un ataque.

---

## 7. Rasgos considerados normales

A partir del análisis de los perfiles, se identifican los siguientes rasgos como normales dentro de la red:

### 7.1 Periodicidad temporal

El tráfico sigue ciclos predecibles relacionados con:

- día y noche
- horario laboral
- fines de semana
- transiciones entre franjas horarias

Esta periodicidad es una característica fundamental del dataset UGR'16.

---

### 7.2 Diversidad de servicios

El tráfico normal presenta diversidad de protocolos, puertos, IPs y duraciones.

No se concentra de forma rígida en un único patrón.

---

### 7.3 Uso recurrente de puertos estándar

La presencia frecuente de puertos como 80, 443, 25, 110 y 53 es coherente con tráfico de fondo.

---

### 7.4 Patrones TCP habituales

En tráfico normal aparecen combinaciones de flags compatibles con conexiones establecidas o respuestas rápidas, como:

- `.AP.SF`
- `.A....`

Estos patrones contrastan con ráfagas anómalas dominadas por SYN, RST o combinaciones repetitivas.

---

### 7.5 Distribución de IPs

El tráfico normal tiende a mostrar una distribución variada de IPs origen y destino.

No suele observarse una saturación repentina hacia un único nodo, puerto o servicio.

---

## 8. Señales de desviación respecto a la normalidad

El análisis permitió identificar posibles señales de anomalía.

### 8.1 Ruptura de la periodicidad

Un volumen elevado de tráfico fuera de su horario habitual puede indicar comportamiento anómalo.

Ejemplo:

- tráfico SMTP masivo durante la madrugada
- tráfico laboral intenso en horario nocturno
- ráfagas inusuales durante fines de semana

---

### 8.2 Concentración inusual

Un incremento súbito de flujos hacia una única IP o puerto puede indicar ataque o exploración.

Este patrón contrasta con la distribución más diversa del tráfico normal.

---

### 8.3 Anomalías de volumen

Flujos con paquetes o bytes muy alejados del perfil habitual pueden ser sospechosos si aparecen de forma repetida o concentrada.

No obstante, el volumen debe interpretarse con cuidado, ya que pueden existir flujos legítimos grandes.

---

### 8.4 Flags incoherentes

Un aumento de flags de control, como SYN o RST, puede indicar intentos fallidos, escaneo o inundación.

La desviación se vuelve más relevante si aparece en ráfagas repetitivas y con baja variabilidad.

---

## 9. Relación con análisis posteriores

Este análisis de normalidad sirvió como base para comparar posteriormente los ataques:

- DoS
- UDP Scan
- NerisBotnet

La comparación permitió identificar que los ataques sintéticos rompen la diversidad normal del tráfico mediante patrones más rígidos, repetitivos y de baja entropía.

En particular:

- DoS rompe la normalidad mediante concentración hacia un único destino.
- UDP Scan rompe la normalidad mediante barrido secuencial de puertos destino.
- NerisBotnet rompe la normalidad mediante coordinación distribuida entre múltiples nodos.

---

## 10. Conclusión

El análisis de los perfiles normales permite establecer una línea base de comportamiento del ISP.

Esta línea base se caracteriza por:

- cicloestacionariedad
- diversidad de servicios
- variabilidad en métricas de flujo
- distribución amplia de IPs
- presencia de protocolos y puertos estándar

El LLM resultó útil para describir estos patrones de forma estructurada y para identificar señales potenciales de desviación.

Este análisis confirma que la detección de ataques no debe basarse en una única traza aislada, sino en la comparación contextual entre ventanas temporales y perfiles normales de referencia.
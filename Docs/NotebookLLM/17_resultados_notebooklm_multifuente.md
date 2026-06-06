# Resultados multifuente obtenidos con NotebookLM

## 1. Objetivo

Este documento consolida los resultados obtenidos mediante NotebookLM tras cargar paquetes completos de fuentes por ataque. Cada paquete incluye fuentes centradas en trazas del ataque, ventanas completas por filas, ventanas temporales de 10 segundos, resúmenes de ventanas de 60 segundos y contexto metodológico.

El objetivo de esta fase no es generar código ni construir directamente un detector, sino extraer conocimiento técnico estructurado que pueda utilizarse posteriormente como especificación para la validación programática con Python.

## 2. Metodología

Para cada ataque se ejecutaron tres prompts principales:

1. Análisis estructural completo.
2. Comparación con background y tráfico normal.
3. Síntesis técnica para validación posterior.

Los ataques analizados fueron:

- `scan11`
- `scan44`
- `anomaly-sshscan`
- `dos`
- `anomaly-udpscan`
- `nerisbotnet`
- `anomaly-spam`

## 3. Nota metodológica

Las respuestas de NotebookLM se consideran hipótesis técnicas y análisis asistidos por LLM. No deben aceptarse como validación empírica final. Las afirmaciones relevantes deben contrastarse posteriormente mediante scripts Python sobre las ventanas reales.

En particular, se debe diferenciar entre observaciones directamente presentes en las fuentes, interpretaciones técnicas razonables e hipótesis pendientes de validación.

---

# scan11

Directorio de resultados:

```text
data\notebooklm_outputs\scan11
```

## Análisis estructural

`scan11`


Este análisis técnico profundiza en el comportamiento de red del ataque 
**scan11**, basándose en la correlación de trazas aisladas, ventanas locales y 
resúmenes estadísticos de gran escala.

### 1. Resumen ejecutivo del patrón observado
El ataque **scan11** se define como un **escaneo vertical de puertos TCP SYN 
interno de alta densidad y baja entropía** [1, 2]. Se trata de una actividad de
reconocimiento masiva donde un único host origen sondea sistemáticamente miles 
de puertos en un único host destino dentro del mismo ISP [1, 3, 4]. El patrón 
es puramente sintético: flujos instantáneos con métricas de red idénticas (1 
paquete, 44 bytes), lo que indica una automatización mediante herramientas 
especializadas [1, 2].

### 2. Topología de comunicación
*   **IPs origen relevantes:** Un único actor dominante: `42.219.150.246` [1, 
3, 4].
*   **IPs destino relevantes:** Un único objetivo focalizado: `42.219.154.69` 
[1, 3, 4].
*   **Patrón:** Estrictamente **1 $\rightarrow$ 1** a nivel de capa de red 
(IP), pero **1 $\rightarrow$ muchos** a nivel de capa de transporte (puertos) 
[1, 5].
*   **Concentración:** Concentración absoluta en el par de IPs mencionado, sin 
dispersión hacia otros nodos de la red en las ventanas analizadas [3, 6, 7].

### 3. Actores principales
*   **IP origen dominante:** `42.219.150.246`. Actúa como el **escáner** [3, 
4].
*   **IP destino dominante:** `42.219.154.69`. Actúa como la 
**víctima/objetivo** [3, 4].
*   **Relación con el ISP:** Ambas direcciones pertenecen al rango 
`42.219.0.0/16`, lo que indica un **tráfico interno** [1, 8, 9]. El ataque 
ocurre entre clientes o sistemas dentro de la propia infraestructura del ISP, 
no desde una red externa.
*   **Papel probable:** El origen es un nodo comprometido o una herramienta de 
auditoría realizando un mapeo exhaustivo de servicios [1, 2].

### 4. Protocolos y puertos
*   **Protocolo predominante:** **TCP** de forma exclusiva para la firma del 
ataque [1, 3].
*   **Puertos origen:** Utiliza **puertos efímeros fijos por ráfaga**. Se 
observan puertos como `40504`, `57696`, `43586`, `61073` o `48374` [1, 10-13]. 
Cada puerto origen se mantiene constante mientras escanea cientos de puertos 
destino en milisegundos [1, 14].
*   **Puertos destino:** Realiza un **barrido exhaustivo** que abarca:
    *   Puertos bajos/bien conocidos (ej. 21, 53, 80, 110, 443) [1, 10, 15, 
16].
    *   Puertos de troyanos/backdoors (ej. 31337) [8, 17].
    *   Puertos altos y dinámicos (ej. 44442, 50002, 64680) [15, 18, 19].
*   **Patrón de escaneo:** **Vertical puro** [2]. No busca un servicio concreto
en muchas máquinas, sino todos los servicios posibles en una sola máquina.

### 5. Métricas de flujo
Los flujos presentan una firma de **baja entropía extrema**, indicativa de 
tráfico sintético [2]:
*   **Duración:** **0.000 segundos** (registros de conexión instantánea) [1, 
20].
*   **Paquetes:** Exactamente **1 paquete** por flujo [1, 20].
*   **Bytes:** Exactamente **44 bytes** por flujo [1].
*   **TCP Flags:** Únicamente el flag **SYN** (`....S.`) [1, 3].
*   **Varianza:** La varianza en duración y tamaño de paquete para el tráfico 
etiquetado como ataque es **nula** [1, 2].

### 6. Comportamiento temporal
*   **Ráfagas (Bursts):** El ataque opera en ráfagas masivas concentradas en 
segundos específicos [1, 3].
*   **Timestamps dominantes:** Segundos con picos de más de 2000 flujos (ej. 
`08:39:48`, `08:41:11`, `08:42:19`) [3, 6, 21].
*   **Simultaneidad:** Cientos de intentos de conexión ocurren en el mismo 
milisegundo, saturando la capacidad de procesamiento de logs si no se agrupan 
[1, 9, 15].
*   **Periodicidad:** El ataque es sostenido. Empieza con una presencia baja 
(ratio 0.02) y escala rápidamente hasta representar el 14% de la carga total de
la red en ventanas posteriores de 60s [20, 22, 23].

### 7. Señales de automatización
*   **Generación por herramienta:** La combinación de SYN-only, 44 bytes y 
duración 0 es la firma clásica de un **SYN Stealth Scan** (probablemente Nmap o
similar) [1, 2].
*   **Localización:** La automatización reside completamente en el **origen** 
(`42.219.150.246`), que gestiona la apertura secuencial o paralela de sockets a
una velocidad imposible para un humano [1, 15].
*   **Estructura de puertos:** El cambio de puerto origen para cada bloque de 
escaneo destino sugiere un motor de escaneo que cicla sus propios recursos 
efímeros [11, 24, 25].

### 8. Variaciones entre fuentes
*   **Fuentes centradas:** Muestran el patrón de ataque "limpio" y confirman la
IP origen y destino fijas [1, 15].
*   **Ventanas rows_2000:** Permiten observar el ataque inmerso en el 
**background**. Se ve cómo el escaneo vertical de scan11 coexiste con tráfico 
DNS (puerto 53 UDP) y HTTP/S legítimo, además de otros escaneos menores (ej. 
blacklist externos buscando puerto 23) [5, 26, 27].
*   **Ventanas time_10s:** Revelan la **densidad local**. En solo 10 segundos, 
scan11 puede generar más de 5000 flujos, dominando visualmente el log sobre el 
tráfico real [9, 28, 29].
*   **Resúmenes time_60s:** Aportan el **impacto estadístico**. Muestran cómo 
la duración media de *toda la red* cae drásticamente debido a la inyección de 
miles de flujos de duración 0 del ataque [22, 23].

### 9. Invariantes robustos
*   La tupla **(IP Origen: 150.246, IP Destino: 154.69)** [1, 3, 4].
*   La métrica **(1 pkt, 44 bytes, flag SYN)** [1].
*   La **duración cero** constante en todos los flujos del ataque [1, 20].

### 10. Rasgos débiles o no constantes
*   **Puerto origen:** Varía entre ráfagas. No es un identificador fiable a 
largo plazo, solo es constante durante bloques cortos de tiempo [1, 10-12].
*   **Secuencialidad de puertos destino:** Aunque el barrido es masivo, en 
algunas trazas los puertos no parecen estrictamente consecutivos en el tiempo 
(pueden seguir una lista de "puertos más comunes" antes de pasar al barrido 
lineal) [1, 15, 16].

### 11. Interpretación técnica
El comportamiento representa una fase de **Reconocimiento Activo/Enumeración de
Servicios**. El objetivo es identificar vectores de entrada específicos en un 
host concreto (`42.219.154.69`) [1, 2]. Al ser un escaneo SYN, no llega a 
completar la negociación TCP (Three-way handshake), lo que permite al atacante 
ser más rápido y menos ruidoso para sistemas de logging antiguos (aunque aquí 
es obvio por el volumen) [1, 2].

### 12. Limitaciones
*   **Visibilidad unidireccional:** Los logs analizados solo muestran los 
intentos de conexión (SYN). No vemos la respuesta de la víctima (SYN-ACK o 
RST), por lo que es imposible saber qué puertos estaban realmente abiertos 
desde estas fuentes [1, 15].
*   **Sesgo de ISP:** Al ser tráfico interno, podríamos estar ante una tarea de
mantenimiento o escaneo de seguridad autorizado que ha sido etiquetado como 
ataque, aunque su firma técnica sea idéntica a una intrusión [1, 2].
*   **Validación necesaria:** Se requiere código para determinar si el orden de
los puertos destino sigue algún algoritmo de aleatorización o si es puramente 
incremental.

### 13. Conclusión
El patrón final de **scan11** es un **escaneo vertical TCP SYN masivo, 
focalizado e interno**. Encaja perfectamente en el **modelo de comportamiento 
sintético** debido a su uniformidad técnica absoluta y su alta densidad 
temporal [2, 30]. Este ataque no modifica el modelo sintético actual, sino que 
lo valida como un caso de uso ideal: un comportamiento que es invisible si se 
mira un flujo individual, pero extremadamente anómalo y fácil de aislar cuando 
se analiza la estructura de la ventana (entropía nula frente a varianza de 
background) [2, 20].

---

## Comparación con background

`scan11`


Basado en el análisis de las fuentes que abarcan desde trazas aisladas hasta 
resúmenes estadísticos de 60 segundos, presento la comparación técnica entre el
ataque **scan11** y el tráfico de red normal/background.

### 1. Rasgos del ataque vs. Background
*   **Determinismo vs. Estocasticidad:** El ataque scan11 es puramente 
determinista y sintético; presenta una **entropía nula** en métricas de tamaño 
y duración (siempre 1 paquete, 44 bytes, 0.000s) [1-3]. El background es 
estocástico, con duraciones que varían desde milisegundos hasta más de 90 
segundos y tamaños de flujos desde pocos bytes hasta megabytes [4-6].
*   **Densidad Vertical:** El ataque inyecta miles de flujos dirigidos a una 
única IP destino explorando un rango masivo de puertos en segundos [7, 8]. El 
background, aunque contiene automatización (DNS, escaneos horizontales de 
internet), no muestra tal concentración vertical hacia un solo host interno [5,
9].

### 2. Rasgos comunes (Insuficientes para detección aislada)
*   **Flag TCP SYN:** El uso de paquetes SYN es parte del tráfico legítimo para
iniciar conexiones [3, 7].
*   **Flujos de 1 paquete / Duración 0:** En una red ISP real, es común ver 
flujos fallidos, descartes de firewall o ruidos de red (ej. intentos de 
conexión a puertos cerrados) que registran un solo paquete y duración nula [10,
11].
*   **IPs internas:** Al ser ambas IPs del mismo ISP, el flujo por sí solo 
parece tráfico entre clientes [12, 13].

### 3. Métricas con mayor desviación
*   **Puertos Destino:** Muestra la mayor desviación estructural. En el ataque,
la diversidad de puertos destino es artificialmente alta para un solo par de 
IPs (barrido vertical) [2, 14, 15].
*   **Duración y Tamaño:** Mientras que el background tiene una varianza de 
bytes masiva (orden de $10^{12}$), los flujos del ataque tienen **varianza 
cero** [10, 16].
*   **Timestamps:** El ataque rompe la distribución temporal normal creando 
picos de simultaneidad donde miles de flujos comparten el mismo segundo exacto 
(ej. segundos con más de 2200 flujos) [7, 17].

### 4. Cambios en la diversidad
*   **Diversidad de IPs:** Cae drásticamente. En una ventana de 60s normal hay 
~11,000 IPs origen; el ataque añade 14,000 flujos desde **una sola IP**, 
sesgando la distribución de cardinalidad [10, 18].
*   **Diversidad de Puertos:** Aumenta artificialmente en el lado del destino 
(verticalidad), pero disminuye en el origen (puerto efímero fijo por ráfaga) 
[2, 7].
*   **Diversidad de Protocolos:** Nula. El ataque es 100% TCP SYN, mientras que
el background reparte su carga entre TCP (~67%), UDP (~31%) e ICMP [7, 10].

### 5. Ruptura de la cicloestacionariedad
El ataque **rompe la cicloestacionariedad** de la red. Al representar hasta el 
14% de la carga total en ventanas de 60s, distorsiona las medias globales: la 
duración media de *toda la red* baja de forma anómala debido a la inyección 
masiva de registros con duración 0.000 [11, 18].

### 6. Posibles confusiones
*   **DNS:** No hay confusión; DNS usa predominantemente UDP y puertos fijos 
(53), mientras que scan11 es TCP vertical [7].
*   **HTTP/HTTPS:** El tráfico legítimo web es multi-paquete, con flags 
`.AP.SF` y tamaños variables [19, 20]. Scan11 solo usa SYN (`....S.`) [3].
*   **Escaneo Benigno:** Podría confundirse con una auditoría interna 
autorizada o un "keep-alive" agresivo de alguna aplicación mal configurada si 
solo se mira un flujo [12, 21].
*   **Ruido de Red:** El ruido externo (bots buscando puertos 23 o 445) suele 
ser **horizontal** (muchas IPs destino, un solo puerto); scan11 es 
estrictamente **vertical** [7, 22].

### 7. Señales fiables de separación
La señal más robusta es la **Tupla de Baja Entropía**: `(IP_Src fija + IP_Dst 
fija + verticalidad de puertos + SYN + 44 bytes + dur:0)`. La repetición exacta
de estos seis campos miles de veces en una ventana temporal corta es 
estadísticamente imposible en tráfico legítimo [1, 2, 16].

### 8. Señales débiles aisladas
*   El **puerto origen**: cambia entre ráfagas, por lo que no sirve como firma 
estática [12, 23].
*   El **puerto destino individual**: el ataque toca puertos comunes (80, 443),
por lo que ver una conexión al puerto 80 no indica ataque por sí mismo [24, 
25].

### 9. Aporte de evidencia por ventana
*   **Centered_sources:** Aporta la **firma técnica** pura [1].
*   **Rows_2000:** Aporta la **evidencia de coexistencia**, permitiendo ver 
cómo el ataque sobresale visualmente sobre el background [26, 27].
*   **Time_10s:** Aporta la **evidencia de ráfaga**, mostrando la saturación 
temporal [6, 28].
*   **Time_60s summaries:** Aporta la **evidencia estadística**, demostrando el
impacto en las métricas agregadas de la red [10, 11].

### 10. Limitaciones de la comparación
*   **Falta de respuestas:** Solo vemos el tráfico saliente (SYN). No sabemos 
si el host destino respondió o si el escaneo fue bloqueado, lo que limita el 
análisis de éxito del ataque [21].
*   **Sesgo de Protocolo:** Al centrarse en SYN, no podemos evaluar si hay 
otras fases del ataque (ej. explotación) ocultas en flujos legítimos 
establecidos [13].
*   **Contexto de ISP:** Al ser IPs internas, sin información de inventario del
ISP, no se puede descartar al 100% una herramienta de gestión de red 
comportándose de forma similar a un escáner [12].

### Conclusión
La diferencia fundamental es que el tráfico normal maximiza la **varianza y la 
utilidad** (intercambio de datos), mientras que scan11 maximiza la **densidad y
la uniformidad** (reconocimiento). El ataque es una "línea recta" técnica 
inyectada en medio de un "bosque" heterogéneo de flujos reales [10, 13].

Conversation: e42d8dc5-1dcc-4589-b4cd-1ad2185a33a1 (turn 1)

---

## Síntesis para validación

`scan11`


Esta es la síntesis técnica final del ataque **scan11**, estructurada para 
servir como especificación en una fase de validación programática.

### 1. Nombre del ataque analizado
**scan11** [1, 2].

### 2. Categoría técnica propuesta
**Reconocimiento Vertical Activo (Vertical Port Scan)** de alta densidad y baja
entropía [2, 3].

### 3. Descripción breve del patrón
El ataque consiste en un sondeo exhaustivo y automatizado de una amplia gama de
puertos TCP en un único host objetivo [4-6]. Se caracteriza por ráfagas masivas
de paquetes **SYN** con métricas de red idénticas, lo que revela un 
comportamiento puramente sintético diseñado para la enumeración de servicios 
[3, 7, 8].

### 4. Topología
*   **Patrón:** Estrictamente **1 $\rightarrow$ 1** a nivel de capa de red 
(IP), pero **1 $\rightarrow$ muchos** a nivel de transporte (puertos) [4, 9].
*   **Concentración:** Máxima concentración espacial (un solo par de IPs) y 
temporal (miles de flujos por segundo) [10, 11].
*   **Rol de IPs:** 
    *   **Origen (`42.219.150.246`):** Host escáner interno al ISP [4, 10, 12].
    *   **Destino (`42.219.154.69`):** Host objetivo único [4, 7, 12].

### 5. Métricas principales observadas
*   **Protocolo:** **TCP** de forma exclusiva en los flujos del ataque [4, 10].
*   **Puertos origen:** Puertos efímeros que permanecen **fijos por ráfaga** 
(ej. `56237`, `40504`, `57696`, `43586`, `61073`, `34190`, `40356`, `57687`) 
[4, 5, 13-18].
*   **Puertos destino:** Barrido vertical masivo que abarca desde puertos bajos
(21, 23, 80) hasta puertos dinámicos altos (65000+) [4, 6, 18-21].
*   **Duración:** **0.000 segundos** (constante) [4, 5, 13, 18].
*   **Paquetes:** **1 solo paquete** por flujo [4, 5, 13, 18].
*   **Bytes:** **44 bytes** por flujo (constante en el ataque) [4, 5, 13, 18].
*   **Flags:** Flag **SYN** (`....S.`) predominante; se observan casos aislados
de `.A....` marcados como scan11 pero el núcleo es SYN [4, 5, 8, 13, 18].
*   **Timestamps:** Agrupación en segundos específicos con picos de más de 
**2200 flujos por segundo** [7, 10, 11].

### 6. Invariantes fuertes
*   **Tupla técnica nula:** La combinación de **1 paquete, 44 bytes y duración 
0.000s** aparece en todos los flujos del ataque [4, 13, 18]. Es robusta porque 
la varianza estadística de estos campos dentro del ataque es cero [22-24].
*   **Identidad de los actores:** Las IPs origen (`150.246`) y destino 
(`154.69`) no cambian a lo largo de todas las ventanas analizadas [4, 10, 12].
*   **Focalización interna:** Ambas IPs pertenecen al rango `42.219.0.0/16`, 
confirmando que es un ataque de origen interno [4, 9].

### 7. Invariantes secundarios
*   **Puerto origen estático local:** El puerto origen se mantiene igual 
durante bloques de cientos de conexiones antes de rotar [5, 13, 15, 16].
*   **Flag SYN:** Aunque es común en tráfico normal, su repetición con métricas
de 44 bytes y duración 0 es una firma secundaria fuerte [4, 8, 18].

### 8. Señales de automatización
*   **Localización:** La automatización reside en el host origen [3].
*   **Estructura sintética:** La generación de flujos de exactamente 44 bytes 
es la firma típica de herramientas como **Nmap** (SYN Stealth Scan) 
[Interpretación técnica].
*   **Densidad temporal:** La capacidad de inyectar miles de intentos de 
conexión en el mismo segundo es imposible para un usuario humano [10, 11].

### 9. Diferencias con background
*   **Entropía:** El background es heterogéneo (varianza de bytes de orden 
$10^{12}$); el ataque es determinista (varianza cero) [22, 24].
*   **Estructura de puertos:** El background usa puertos de forma funcional 
(ej. DNS en 53 UDP, Web en 80/443 TCP con intercambio de datos); el ataque usa 
puertos de forma estructural (barrido vertical sin datos) [4, 8, 10].
*   **Duración:** El ratio de duración cero en la red sube del nivel normal 
hasta el 50% cuando el ataque está activo [22, 24, 25].

### 10. Posibles confusiones
*   **Auditorías benignas:** Un escaneo de vulnerabilidades autorizado tendría 
la misma firma técnica [Interpretación técnica].
*   **Ruido de red/Escaneos externos:** Los escaneos externos suelen ser 
**horizontales** (muchas IPs, pocos puertos); scan11 se diferencia por su 
verticalidad absoluta [4, 10].
*   **Keep-alives mal configurados:** Podrían generar flujos cortos, pero no 
con un barrido de miles de puertos destino distintos [Interpretación técnica].

### 11. Evidencia suficiente (Observaciones)
*   Identidad de las IPs origen y destino [4, 10].
*   Métricas de flujo constantes (1 pkt, 44 bytes, 0 dur) [4, 5, 18].
*   Naturaleza TCP SYN del ataque [4, 8, 13].
*   Impacto masivo en la cardinalidad de puertos de la ventana temporal [7, 10,
11].

### 12. Evidencia insuficiente (Hipótesis)
*   **Herramienta exacta:** Aunque parece Nmap, no se puede confirmar sin 
inspección de carga útil (payload), no disponible en estas fuentes 
[Interpretación técnica].
*   **Éxito del ataque:** Al no ver las respuestas (`SYN-ACK` o `RST`), no se 
sabe qué servicios fueron descubiertos como abiertos [3, 14].

### 13. Requisitos para validación posterior (Especificación para código)
*   **Métrica de verticalidad:** Contar `Dest_Ports` únicos por cada par 
`(Src_IP, Dst_IP)` en ventanas de 60s [Requisito propuesto].
*   **Filtro de Entropía:** Identificar grupos de flujos donde `std(bytes) == 
0` y `std(duration) == 0` [Requisito propuesto].
*   **Umbral de densidad:** Activar alerta si un par de IPs genera más de `X` 
flujos (ej. >500) en menos de 10 segundos [Requisito propuesto].
*   **Análisis temporal:** Verificar si el puerto origen se mantiene constante 
durante ráfagas de alta frecuencia de puertos destino [Requisito propuesto].

### 14. Encaje en el modelo de comportamiento sintético
Encaja perfectamente en la categoría de **Ataque Sintético de Reconocimiento** 
[2, 3]. No requiere una categoría nueva, pero sirve como el "Gold Standard" de 
baja entropía: es el ejemplo más claro de cómo un comportamiento automático 
rompe la diversidad estadística natural de una red ISP [22-24].

### 15. Conclusión final
El **scan11** es un **escaneo vertical TCP SYN masivo e interno** ejecutado por
`42.219.150.246` contra `42.219.154.69`, caracterizado por una firma técnica 
invariable de **1 paquete y 44 bytes**, diseñado para mapear la superficie de 
exposición del objetivo con mínima entropía y máxima velocidad [4, 5, 18]

Conversation: e42d8dc5-1dcc-4589-b4cd-1ad2185a33a1 (turn 1)

---


# scan44

Directorio de resultados:

```text
data\notebooklm_outputs\scan44
```

## Análisis estructural

`scan44`


Este análisis técnico profundo del ataque **scan44** se basa en las trazas de 
red y resúmenes estadísticos proporcionados en las fuentes del dataset UGR'16.

### 1. Resumen ejecutivo del patrón observado
El patrón identificado corresponde a un **escaneo de puertos masivo y 
distribuido** de tipo **TCP SYN Scan** [1, 2]. Se caracteriza por ráfagas 
extremadamente densas de flujos de un solo paquete dirigidos a una amplia gama 
de puertos destino en objetivos específicos [1, 3]. El ataque no es un barrido 
aleatorio, sino una exploración sistemática de servicios organizada en parejas 
de IP origen-destino que operan en paralelo [2, 4].

### 2. Topología de comunicación
*   **IPs origen relevantes:** Se observan aproximadamente **4 a 5 IPs origen 
dominantes** concentradas en el rango `42.219.150.24x` (específicamente `.242`,
`.243`, `.246`, `.247`) [2, 4-6].
*   **IPs destino relevantes:** Un número similar de objetivos principales (4 a
5 IPs) en rangos como `42.219.156.30`, `42.219.154.69`, `42.219.152.20` y 
`42.219.158.16` [2, 4].
*   **Tipo de patrón:** Es **muchos-a-muchos** a nivel agregado, pero se 
descompone en sesiones simultáneas **1→1** donde cada origen se especializa en 
un destino durante una ráfaga [1, 2, 7, 8].
*   **Concentración/Dispersión:** Existe una **alta concentración** en las 
parejas de IP implicadas, pero una **dispersión total** en el espacio de 
puertos destino [1, 4].

### 3. Actores principales
*   **IPs origen dominantes:** `42.219.150.242`, `42.219.150.243`, 
`42.219.150.246` y `42.219.150.247` [2, 4].
*   **IPs destino dominantes:** `42.219.156.30`, `42.219.154.69`, 
`42.219.152.20` y `42.219.158.16` [2, 5, 9].
*   **Papel probable:** Los orígenes actúan como **nodos de escaneo** y los 
destinos como **objetivos de reconocimiento** de servicios.
*   **Ubicación:** Los orígenes y destinos comparten el prefijo 
`42.219.xxx.xxx`. **Interpretación técnica:** Esto sugiere un ataque que ocurre
dentro de la infraestructura del mismo ISP o entre redes muy cercanas 
lógicamente, lo que permite altas velocidades de escaneo.

### 4. Protocolos y puertos
*   **Protocolo predominante:** **TCP** de forma casi exclusiva para el tráfico
etiquetado como ataque [1, 2].
*   **Puertos origen relevantes:** Varían por ráfaga; a veces se usa un 
**puerto fijo** para miles de conexiones (ej. `53189`, `38252`, `35488`) [1, 7,
10] y otras veces cambian ligeramente, pero manteniendo consistencia dentro de 
la ráfaga [11, 12].
*   **Puertos destino relevantes:** Se observa un **barrido masivo** que abarca
desde puertos bajos (ej. `7`, `21`, `80`, `110`) hasta puertos altos y 
dinámicos (ej. `32768`, `44442`, `65129`) [1, 13-15].
*   **Estructura del barrido:** Es un **escaneo vertical** (muchos puertos a 
una IP) ejecutado en **paralelo** por varios nodos [1, 7, 8, 16]. No siempre es
estrictamente secuencial, lo que indica el uso de herramientas de escaneo 
modernas que aleatorizan o agrupan puertos por categorías [1, 17, 18].

### 5. Métricas de flujo
*   **Duración:** Consistentemente **0.000 segundos** [1, 3, 19].
*   **Paquetes:** Exactamente **1 paquete** por flujo en la dirección 
origen→destino [1, 19, 20].
*   **Bytes:** Exactamente **44 bytes** para el paquete SYN [1, 19].
*   **Flags TCP:** Predomina el flag **SYN** (`....S.`) desde el atacante [1]. 
Se observan respuestas **ACK/RST** (`.A.R..`) de **40 bytes** desde los 
destinos, indicando puertos cerrados [2, 21, 22].
*   **Baja entropía:** La uniformidad en tamaño (44 bytes), duración (0s) y 
volumen (1 pq) es una **señal de bajísima entropía**, típica de herramientas 
automáticas [1, 19, 23].

### 6. Comportamiento temporal
*   **Ráfagas:** El ataque se organiza en **ráfagas intensas** de 
aproximadamente 1000 flujos en un solo segundo [1, 4].
*   **Periodicidad:** Se observa un intervalo de **20 segundos** entre ráfagas 
de una misma pareja de IPs (ej. de 08:49:44 a 08:50:05, luego 08:50:25) [1, 2, 
21, 24].
*   **Simultaneidad:** Múltiples orígenes lanzan sus ráfagas en el mismo 
segundo o con diferencias mínimas, sugiriendo una **coordinación centralizada**
[2, 25-27].

### 7. Señales de automatización
*   **Elementos generados por herramienta:** La capacidad de generar miles de 
flujos TCP con timestamps idénticos es imposible para un humano [1, 7].
*   **Localización:** La automatización reside en los **nodos origen**, que 
actúan como motores de escaneo programados para iterar sobre listas de puertos 
predefinidas o rangos completos [1, 17].
*   **Estructura de puertos:** La mezcla de puertos bien conocidos con puertos 
altos en una sola ráfaga instantánea confirma el uso de scripts o herramientas 
como `nmap` o similares con perfiles de escaneo agresivo [13, 20, 28].

### 8. Variaciones entre fuentes
*   **Fuentes centradas:** Muestran el patrón de ataque "puro", facilitando la 
identificación de las IP atacantes y el tamaño del paquete (44 bytes) [1, 7, 
16].
*   **Ventanas rows_2000:** Permiten ver que el ataque domina bloques enteros 
de tráfico, pero ocasionalmente se mezcla con background (DNS, HTTP) [29, 30].
*   **Ventanas time_10s:** Revelan la **estructura de ráfagas**: segundos de 
silencio seguidos de ráfagas masivas de escaneo [3, 31, 32].
*   **Resúmenes time_60s:** Aportan la visión macro; muestran cómo el ratio de 
ataque crece desde el 8% hasta el 45% del tráfico total a medida que la 
actividad se intensifica en el tiempo [19, 33-36].

### 9. Invariantes robustos
*   **Tamaño del paquete SYN:** Siempre 44 bytes [1, 19].
*   **Duración del flujo:** Siempre 0.000 segundos [1, 19].
*   **Flag TCP:** Siempre SYN para la petición [1].
*   **Bloques de IPs:** Los orígenes `42.219.150.24x` son constantes en todas 
las ventanas [2, 4, 5, 9].

### 10. Rasgos débiles o no constantes
*   **Puerto origen:** A veces es fijo (ej. `53189`) y otras cambia entre 
ráfagas [1, 11, 26].
*   **Orden de puertos destino:** No siempre es secuencial ascendente; a veces 
presenta saltos o desorden aparente dentro del mismo segundo [1, 7, 8].
*   **Volumen de la ráfaga:** El número de puertos escaneados por segundo varía
ligeramente entre ventanas [2, 4, 9].

### 11. Interpretación técnica
*   **Tipo de comportamiento:** Representa una fase de **Reconocimiento Activo 
Distribuido**.
*   **Objetivo:** Identificar servicios vulnerables o vectores de entrada en 
activos críticos del ISP (servidores de correo, web, bases de datos) [13, 28, 
37].
*   **Etiqueta vs. Realidad:** Aunque se etiqueta como "scan44", técnicamente 
es un **SYN Port Sweep vertical y paralelo**. No debe limitarse a un "escaneo" 
genérico, sino a una operación coordinada de mapeo de infraestructura.

### 12. Limitaciones
*   **Sesgo de ventana:** Las fuentes están seleccionadas para mostrar el 
ataque; la duración total real del ataque o su frecuencia en un día completo no
es visible.
*   **Background:** En ventanas densas, algunos escaneos de background (ej. 
hacia puerto 445 o 23) podrían confundirse con el ataque si no se filtran por 
las IP de origen conocidas [32, 38-40].
*   **Validación necesaria:** Se requiere código para confirmar si el TTL o el 
Window Size de los paquetes del ataque son constantes, lo que confirmaría una 
única herramienta de generación.

### 13. Conclusión
*   **Patrón final:** El ataque **scan44** es una serie coordinada de **ráfagas
de TCP SYN Scanning** de 44 bytes y 0s de duración, lanzadas por un grupo 
pequeño de IPs origen (`.242` al `.247`) contra objetivos específicos, rotando 
o barriendo miles de puertos por segundo con intervalos de descanso de ~20 
segundos [1, 2, 24].
*   **Encaje en el modelo:** Encaja perfectamente en un modelo de 
**comportamiento sintético de escaneo vertical distribuido**.
*   **Modificación del modelo:** El análisis sugiere ampliar el modelo para 
incluir la **sincronización temporal exacta** entre múltiples nodos atacantes 
como un rasgo distintivo (coordinación multi-nodo).

---

## Comparación con background

`scan44`


Esta comparativa técnica entre el ataque **scan44** y el tráfico de fondo 
(**background**) permite desglosar la anomalía no solo por su etiqueta, sino 
por su desviación estructural respecto a la normalidad de una red ISP.

### 1. Rasgos diferenciadores claros
*   **Uniformidad de carga útil:** El ataque es estrictamente de **44 bytes** 
para peticiones SYN y **40 bytes** para respuestas RST/ACK [1, 2]. El 
background presenta una distribución de tamaños masiva y errática, desde 
paquetes pequeños de control hasta ráfagas de datos de miles de bytes [3, 4].
*   **Determinismo temporal:** El ataque tiene una **duración de flujo de 0.000
segundos** [1, 5]. En el background, aunque existen flujos cortos (ej. DNS), la
mayoría tienen duraciones variables (ej. 0.300s a >10s) que reflejan 
interacciones reales [6-8].
*   **Densidad por ráfaga:** El ataque genera miles de flujos en un solo 
segundo entre una pareja de IPs [9, 10]. El background, incluso en servicios 
populares como HTTP (80) o HTTPS (443), dispersa sus conexiones en el tiempo 
[11, 12].

### 2. Rasgos comunes (Insuficientes para detección)
*   **Protocolos base:** Tanto el ataque como el tráfico normal usan **TCP** de
forma mayoritaria [9].
*   **Direccionamiento:** Los atacantes y las víctimas comparten el prefijo 
`42.219.x.x` con gran parte del tráfico legítimo del ISP, lo que impide el 
bloqueo por simple geolocalización o reputación de red [3, 9].
*   **Flags TCP:** El uso del flag **SYN** (`....S.`) es común para iniciar 
cualquier conexión legítima. Su presencia aislada no es anómala [13, 14].

### 3. Métricas con mayor desviación
*   **IPs origen/destino:** En el ataque, hay una **hiper-concentración** en 
<10 direcciones que generan casi el 50% del tráfico total en ventanas de 60s 
[15, 16].
*   **Puertos destino:** Presentan la desviación más extrema. Mientras el 
tráfico normal se concentra en puertos estándar (80, 443, 53), el ataque barre 
**decenas de miles de puertos aleatorios o secuenciales** [9, 17].
*   **Flujos por segundo:** El ataque rompe cualquier umbral de "conexiones por
host" del background, pasando de una actividad scattered a una **saturación de 
la tabla de flujos** [18, 19].
*   **Timestamps:** Los timestamps del ataque muestran **simultaneidad 
absoluta** (mismo milisegundo para cientos de flujos), señal de un stack TCP 
manipulado por script [20, 21].

### 4. Cambios en la diversidad
*   **Diversidad de IPs:** **Baja**. El ataque reduce la entropía de la red al 
concentrar el volumen en pocos nodos [22, 23].
*   **Diversidad de puertos:** **Extrema**. Aumenta masivamente la diversidad 
de puertos destino pero reduce la de puertos origen (a menudo fijos por ráfaga)
[9, 24].
*   **Diversidad de protocolos:** **Nula**. El ataque es mono-protocolo (TCP), 
mientras que el background es una mezcla rica de TCP, UDP, ICMP, GRE y ESP [9, 
18].
*   **Diversidad temporal:** **Baja**. Sigue un patrón de "encendido/apagado" 
(ON/OFF) con ráfagas y silencios de 20s [20, 25].

### 5. Ruptura de la cicloestacionariedad
El tráfico ISP normal sigue ciclos de carga predecibles. **scan44 rompe la 
cicloestacionariedad** al introducir picos de tráfico de control (SYN) que no 
corresponden a picos de tráfico de datos. En las ventanas finales, el ataque 
llega a representar el **45.75% de los flujos totales**, alterando 
completamente las estadísticas medias de la red [16, 23].

### 6. Riesgo de confusión
*   **Automatización normal:** Podría confundirse con **balanceadores de carga 
o health checks** agresivos, pero estos suelen limitarse a puertos específicos.
*   **DNS:** El background tiene mucho tráfico UDP/53 [9], pero el ataque es 
TCP, lo que facilita la separación.
*   **SSH legítimo:** El ataque incluye intentos al puerto 22 [26, 27], pero su
duración de 0.0s lo distingue de una sesión SSH real que requiere intercambio 
de llaves.
*   **Otras anomalías:** Se observa actividad "blacklist" y escaneos menores de
background (ej. puerto 445), pero su volumen es residual comparado con la 
agresividad de scan44 [22, 28].

### 7. Señales de separación fiables
La señal más robusta es la **combinación de (SYN + Duración 0.0 + Tamaño 44 
bytes + Alta frecuencia de puertos destino)** vinculada a una sola IP origen. 
Ningún servicio legítimo en los datos de background presenta esta firma 
combinada.

### 8. Señales débiles aisladas
*   **IP origen sospechosa:** Una IP puede estar escaneando lentamente (ruido) 
sin ser scan44.
*   **Paquete de 44 bytes:** Un SYN legítimo puede tener 44 bytes dependiendo 
de las opciones TCP [1].
*   **Puerto destino inusual:** Un solo acceso a un puerto alto puede ser una 
aplicación legítima (ej. P2P o juegos).

### 9. Valor de las ventanas de evidencia
*   **Summaries time_60s:** Son la mejor evidencia de la **escala del ataque** 
y su impacto en la diversidad global [15, 22].
*   **Windows time_10s:** Aportan la mejor visión de la **periodicidad y 
sincronización** [13, 20].
*   **Centered_sources:** Permiten confirmar la **firma exacta del paquete** 
(44 bytes) sin ruido [1, 29].

### 10. Limitaciones de la comparación
*   **Contexto ISP:** Al ser tráfico real, el background ya contiene "ruido" 
(otros escaneos menores, fallos de red) [30].
*   **Visibilidad de carga:** Solo vemos metadatos de flujo (Netflow). No 
podemos analizar el contenido de los paquetes para ver si hay variaciones en el
*sequence number* que confirmarían la herramienta de ataque.
*   **Sesgo de prefijo:** Al estar atacantes y víctimas en el mismo rango del 
ISP, es difícil determinar si el ataque es una botnet interna o una simulación 
de red local [3, 9].

### Conclusión técnica
El ataque **scan44** se separa del tráfico normal por su **comportamiento 
sintético de baja entropía**. Mientras que la "normalidad" de la red se define 
por la diversidad de comportamientos y duraciones, el ataque es una **máquina 
de estados repetitiva** que busca agotar el espacio de puertos con un coste 
computacional mínimo (flujos de un solo paquete). No es un "pico de tráfico", 
es una **alteración de la estructura probabilística de la comunicación** en la 
red.

Conversation: 98eba743-0c94-40fa-8380-8134c0810a52 (turn 1)

---

## Síntesis para validación

`scan44`


Esta síntesis técnica final del ataque **scan44** proporciona la especificación
necesaria para una fase de validación programática, basada en las trazas y 
resúmenes estadísticos analizados.

1.  **Nombre del ataque analizado:** scan44 [1].
2.  **Categoría técnica propuesta:** Reconocimiento Activo Distribuido mediante
Escaneo Vertical de Puertos (TCP SYN Port Sweep) [2-4].
3.  **Descripción breve del patrón:** El ataque consiste en ráfagas 
intermitentes y altamente coordinadas de intentos de conexión TCP SYN de un 
solo paquete, con parámetros de red fijos y baja entropía, barriendo 
masivamente el espacio de puertos destino de servidores específicos [2, 5, 6].
4.  **Topología:**
    *   **Patrón:** Muchos-a-Muchos a nivel agregado; 1→1 durante el tiempo de 
ejecución de cada ráfaga individual [7-9].
    *   **Concentración/Dispersión:** Alta concentración en direcciones IP 
(origen y destino) y dispersión total en puertos destino [6, 7, 10].
    *   **Rol de IPs:** Un grupo de IPs en el rango `42.219.150.242-247` actúa 
como orígenes (sensores/motores de escaneo). Un grupo de IPs objetivo (ej. 
`.156.30`, `.154.69`) actúa como destinos de reconocimiento [2, 7, 8].
5.  **Métricas principales observadas:**
    *   **Protocolo:** TCP de forma exclusiva para el tráfico de ataque [2, 7].
    *   **Puertos origen:** A menudo puertos altos y fijos durante una ráfaga 
completa (ej. `53189`, `49558`, `63396`) [7-9].
    *   **Puertos destino:** Barrido exhaustivo que abarca desde puertos de 
servicios comunes (80, 443, 22) hasta puertos efímeros altos (>30,000) [11-14].
    *   **Duración:** Invariablemente **0.000 segundos** [2, 15, 16].
    *   **Paquetes:** Exactamente **1 paquete** por flujo en el sentido 
atacante→víctima [2, 15].
    *   **Bytes:** Exactamente **44 bytes** para la petición SYN y **40 bytes**
para las respuestas RST/ACK [2, 15, 17, 18].
    *   **Flags:** Flag **SYN** (`....S.`) dominante desde el origen. 
Respuestas de tipo **RST/ACK** (`.A.R..`) desde el destino ante puertos 
cerrados [2, 7, 17].
    *   **Timestamps:** Agrupación masiva de flujos en segundos específicos, 
indicando ráfagas [6-8].
6.  **Invariantes fuertes:**
    *   **Firma del paquete:** La combinación de **44 bytes + Duración 0.0 + 
Flag SYN** es constante. Es robusto porque define una huella sintética generada
por herramienta, no por un stack TCP de usuario real [2, 5, 15, 19].
    *   **Nodos atacantes:** Las IPs del rango `42.219.150.24x` aparecen de 
forma recurrente en todas las ventanas temporales [6, 8, 10].
7.  **Invariantes secundarios:**
    *   **Periodicidad temporal:** Silencios de aproximadamente **20 segundos**
entre ráfagas sucesivas de una misma pareja IP-IP. Útil para detección pero 
puede variar si el atacante cambia el ritmo [2, 20-22].
    *   **Simultaneidad:** Ejecución paralela de escaneos desde diferentes 
orígenes hacia diferentes destinos en el mismo segundo [6, 8].
8.  **Señales de automatización:**
    *   **Ubicación:** Localizada en el nodo de origen mediante scripts de 
generación de paquetes crudos (*raw sockets*) [4].
    *   **Estructura:** La capacidad de saturar milisegundos exactos con 
cientos de peticiones a puertos destino distintos demuestra el uso de 
herramientas como `nmap` o `zmap` con perfiles agresivos [6, 10].
9.  **Diferencias con background:**
    *   **Separación:** El tráfico normal (HTTP, HTTPS, DNS) presenta 
distribuciones de tamaño y duración altamente variables; scan44 es una "línea 
plana" estadística de baja entropía [15, 23].
    *   **Reducción de Falsos Positivos:** Un solo flujo de 44 bytes y 0s puede
ser un inicio de conexión legítimo; solo la **agregación masiva de puertos 
destino únicos** desde una misma IP confirma el ataque [4, 6].
10. **Posibles confusiones:**
    *   **Tráfico legítimo:** Podría confundirse con escaneos de salud de 
balanceadores de carga si no fuera por la escala de puertos barreados [24-26].
    *   **Otras anomalías:** Se observa ruido de escaneo menor en el puerto 445
(SMB) de fondo, distinguible por su bajo volumen comparado con scan44 [24, 27].
11. **Evidencia suficiente:** El tamaño exacto (44 bytes), la duración nula y 
la identidad de las IPs atacantes están confirmados por múltiples fuentes 
(centered, time\_10s y resúmenes) [2, 6, 7].
12. **Evidencia insuficiente:** No se puede confirmar mediante los datos 
cargados el contenido de los paquetes (opciones TCP) ni si existe una fase de 
exfiltración posterior (el análisis se limita al reconocimiento) [4].
13. **Requisitos para validación posterior:**
    *   **Métricas a medir:** Recuento de puertos destino únicos por IP de 
origen por unidad de tiempo.
    *   **Agregaciones:** Suma de flujos TCP SYN por segundo y por ventana de 
10s.
    *   **Umbrales:** Se recomienda un umbral de >200 flujos/segundo desde un 
origen a puertos distintos para separar el ataque del ruido normal.
    *   **Análisis temporal:** Confirmar si el ratio de ataque crece del 8% al 
45% del tráfico total como se observa en los resúmenes de 60s [15, 28].
14. **Encaje en el modelo de comportamiento sintético:**
    *   Encaja en la categoría de **Escaneo Vertical** [1].
    *   **Ampliación:** El modelo debe ampliarse para incluir la 
**sincronización multi-nodo** (distribuido), donde el ataque es una operación 
orquestada entre varios sensores [6].
15. **Conclusión final:** El ataque **scan44** es una operación de 
reconocimiento coordinada que utiliza ráfagas periódicas de flujos TCP SYN 
sintéticos (44 bytes, duración cero) para mapear servicios en objetivos 
específicos de la red, rompiendo la diversidad normal del tráfico ISP mediante 
un patrón de baja entropía y alta densidad [2, 6, 10, 15].

Conversation: 98eba743-0c94-40fa-8380-8134c0810a52 (turn 1)

---


# anomaly-sshscan

Directorio de resultados:

```text
data\notebooklm_outputs\anomaly-sshscan
```

## Análisis estructural

`anomaly-sshscan`


A partir de las fuentes analizadas sobre el ataque **anomaly-sshscan**, 
presento el siguiente análisis técnico del comportamiento de red observado:

### 1. Resumen ejecutivo del patrón observado
El patrón identificado consiste en una **actividad de escaneo SSH saliente 
extremadamente ligera y persistente**, originada desde un único host interno 
del ISP. A diferencia de un ataque de fuerza bruta volumétrico, este se 
manifiesta como un **"goteo" (trickle) de flujos de un solo paquete** dirigidos
al puerto 22 de diversos servidores externos. El comportamiento es anómalo 
porque las conexiones no llegan a establecerse o se cierran prematuramente con 
flags de Reset (R), lo que sugiere un escaneo de descubrimiento o una 
herramienta automatizada con una configuración específica de sondeo [1-3].

### 2. Topología de comunicación
*   **IPs origen relevantes:** Una única dirección IP interna parece concentrar
toda la actividad etiquetada: **`42.219.156.231`** [1, 2, 4].
*   **IPs destino relevantes:** Múltiples IPs externas dispersas (ej. 
`154.29.70.254`, `129.104.110.251`) [1, 2].
*   **Patrón de flujo:** Claramente **1→Muchos** (desde el interior hacia el 
exterior).
*   **Concentración/Dispersión:** Existe una **concentración absoluta en el 
nodo origen** y una dispersión horizontal en los destinos.

### 3. Actores principales
*   **IP origen dominante:** `42.219.156.231`. Su papel es el de **cliente 
iniciador de la anomalía** (escáner). Por su rango, se interpreta como un host 
dentro de la red del ISP.
*   **IPs destino dominantes:** Varían entre ventanas (ej. `154.29.70.254`). 
Actúan como **servidores SSH externos** que reciben los intentos de conexión 
[4, 5].
*   **Contexto:** El origen parece ser un nodo comprometido o una herramienta 
de auditoría interna operando hacia el exterior. Curiosamente, el destino 
`154.29.70.254` también aparece interactuando con otros hosts internos 
(etiquetados como background), lo que sugiere que podría ser un servidor muy 
solicitado o un destino común de escaneos [4, 6].

### 4. Protocolos y puertos
*   **Protocolo predominante:** **TCP**.
*   **Puertos destino relevantes:** Fijo en el **puerto 22 (SSH)** [1, 2].
*   **Puertos origen relevantes:** Puertos dinámicos altos (ej. 34624, 16397, 
61193, 1575) que cambian con cada flujo [1, 2, 5, 7].
*   **Tipo de escaneo:** **Horizontal**. El atacante barre diferentes 
direcciones IP buscando un servicio específico en un puerto fijo.

### 5. Métricas de flujo
*   **Duración:** Invariablemente **0.000 segundos** [1, 2]. Los flujos no 
tienen persistencia temporal.
*   **Paquetes:** Exactamente **1 paquete por flujo** en los registros de 
ataque [1, 2].
*   **Bytes:** Pequeños y uniformes (típicamente **40-44 bytes**), lo que 
corresponde a paquetes de control TCP sin carga útil [1, 2].
*   **Flags TCP:** Se observa el uso del flag **Reset (`...R..`)** desde el 
origen interno hacia el destino, lo que indica una finalización abrupta o un 
rechazo del intento de conexión tras el primer paquete de respuesta [1, 3, 8].
*   **Entropía:** Señal de **muy baja entropía**. Las métricas son casi 
idénticas en todas las instancias del ataque.

### 6. Comportamiento temporal
*   **Frecuencia:** No se observan ráfagas (bursts) masivas. Es un proceso 
lento.
*   **Timestamp:** Aparece de forma recurrente en diferentes franjas horarias 
(07:35, 10:47, 11:30, 12:23), sugiriendo una **periodicidad de largo plazo** o 
un script que se ejecuta en intervalos [6, 9-11].
*   **Simultaneidad:** Muy baja. Los flujos etiquetados aparecen casi de uno en
uno en los resúmenes de 60 segundos [12, 13].

### 7. Señales de automatización
*   **Elementos generados por herramienta:** La combinación de **un solo 
paquete, duración cero y el uso constante del puerto 22** es incompatible con 
un uso humano del protocolo SSH.
*   **Localización de la automatización:** Se localiza enteramente en el 
**origen interno** (`.231`), que automatiza la apertura (y cierre mediante RST)
de sockets hacia múltiples destinos externos.

### 8. Variaciones entre fuentes
*   **Fuentes centradas:** Permiten ver el "ping-pong" de control (SYN/ACK o 
SYN/RST) entre el actor y sus víctimas [1, 4, 14].
*   **Rows_2000 y Time_10s:** El ataque es **indistinguible visualmente** sin 
la etiqueta, ya que se pierde entre miles de flujos de background (HTTP, DNS, 
etc.) que tienen métricas similares [2, 15, 16].
*   **Resúmenes Time_60s:** Aportan el dato de la **infrecuencia extrema**. En 
una ventana de 100,000 flujos, solo hay 1 o 2 de este ataque (ratio de 0.0000) 
[12, 17]. Al ampliar la ventana, el patrón no cambia, pero su relevancia 
estadística disminuye drásticamente.

### 9. Invariantes robustos
*   La dirección IP origen **`42.219.156.231`** es el rasgo más fuerte.
*   El puerto destino **22**.
*   La métrica de **1 solo paquete** y **0.000s de duración**.

### 10. Rasgos débiles o no constantes
*   Los **puertos origen dinámicos** no siguen una secuencia predecible (no son
incrementales en los snippets).
*   Las **IPs destino** no parecen pertenecer a un rango contiguo, sugiriendo 
una lista de objetivos predefinida o un escaneo aleatorio.

### 11. Interpretación técnica
*   **Tipo de comportamiento:** Representa un **escaneo de reconocimiento 
sigiloso**.
*   **Objetivo:** Identificar hosts que escuchan en SSH sin generar alertas por
volumen o por intentos de login fallidos (ya que el flujo termina antes del 
intercambio de banners).
*   **Etiquetado:** Se denomina "anomaly" probablemente porque el 
comportamiento del cliente SSH es estructuralmente incorrecto (envía RST o solo
un paquete de ACK/RST sin seguir el handshake completo para una sesión útil).

### 12. Limitaciones
*   **Sesgo de selección:** Los snippets están centrados en un solo actor; es 
posible que haya otros escáneres no etiquetados.
*   **Background vs Ataque:** Muchos flujos legítimos (ej. conexiones fallidas 
por red) tienen métricas de 1 paquete y 0 duración. La detección basada solo en
estas métricas generaría muchos falsos positivos.
*   **Validación necesaria:** Se requeriría código para verificar si la IP 
`.231` tiene otros comportamientos (como fuerza bruta posterior) que 
justifiquen su etiquetado como ataque.

### 13. Conclusión
El patrón final de **anomaly-sshscan** es un **escaneo horizontal de baja 
intensidad desde el host interno `42.219.156.231` al puerto 22 externo**. 

*   **Encaje en el modelo:** Encaja parcialmente en el modelo de escaneo 
sintético, pero se aleja de los modelos tradicionales por su **bajísimo volumen
y extrema brevedad de flujo**.
*   **Modificación del modelo:** Este análisis obliga a **ampliar el modelo** 
para incluir ataques "low-and-slow" donde la anomalía no reside en el volumen, 
sino en la **naturaleza estructural del flujo** (finalización anómala mediante 
RST o flujos incompletos) y en la **persistencia de un solo actor** a lo largo 
del tiempo.

---

## Comparación con background

`anomaly-sshscan`


Este análisis técnico y crítico compara el comportamiento de 
**anomaly-sshscan** con el tráfico de fondo (**background**) y el tráfico 
normal del ISP presente en el dataset UGR'16.

### 1. Rasgos diferenciadores del ataque vs background
*   **Finalización Estructural:** El ataque se distingue por el uso sistemático
del flag **Reset (R)** tras un solo paquete [1-3]. Mientras que el background 
tiene flujos con estados de finalización completos (`.AP.SF`), el ataque parece
"abortar" la comunicación de forma deliberada [4, 5].
*   **Especificidad de Servicio:** La anomalía es monolítica hacia el puerto 
**22 (SSH)** [1, 6]. El background es multitemático (80, 443, 53, 445, etc.) 
[7, 8].
*   **Direccionalidad:** Es un patrón **saliente estricto** desde una IP 
interna (`.231`) hacia múltiples destinos externos, sin reciprocidad de datos 
(0 bytes de payload) [5, 9, 10].

### 2. Rasgos comunes (No bastan por sí solos)
*   **Métricas de "Sigilo":** La **duración 0.000s** y el volumen de **1 solo 
paquete** son extremadamente comunes en el background (constituyen entre el 33%
y el 57% del tráfico total según los resúmenes de 60s) [7, 11, 12].
*   **Puertos Origen:** El uso de puertos altos dinámicos es el comportamiento 
estándar de cualquier cliente legítimo en la red [1, 6, 13].

### 3. Métricas con mayor desviación
| Métrica | Desviación del Ataque | Comportamiento en Background |
| :--- | :--- | :--- |
| **IP Origen** | Concentración total en `42.219.156.231` [1, 5]. | Alta 
dispersión (ej. `.211`, `.90`, `.137`) [7, 12]. |
| **Puertos Destino** | **Entropía cero**: Siempre 22 [1, 6]. | Alta diversidad
o tops en 80/443/53 [7, 14]. |
| **Flags** | Predomina el **Reset (`R`)** [2, 5, 15]. | Predominan `ACK` 
(`.A....`) y `Push-Syn-Fin` [7, 12]. |
| **Bytes** | Uniformidad absoluta (**40-44 bytes**) [1, 6, 16]. | Alta 
varianza (media de ~10KB) [7, 8]. |
| **Duración** | **Varianza cero** (0.000s) [1, 2]. | Varianza muy alta (851.0 
- 1286.0) [7, 8]. |

### 4. Cambios en la diversidad
*   **Diversidad de IPs/Puertos:** El ataque reduce drásticamente la 
diversidad. Mientras que una IP normal (como la `.211` del background) contacta
con cientos de IPs y puertos [7], el atacante `.231` muestra una **fijación 
patológica** por un solo servicio externo [1, 16].
*   **Diversidad Temporal:** El ataque es esporádico pero idéntico cada vez que
aparece ("low-and-slow"), a diferencia del background que fluctúa según la 
carga de usuarios.

### 5. Ruptura de la cicloestacionariedad
El ataque **no rompe la cicloestacionariedad volumétrica** de la red ISP debido
a su ratio insignificante (0.0000) [17, 18]. Sin embargo, rompe la **diversidad
estructural**: es un "ruido" constante y anómalo que no sigue los ciclos de 
navegación humana (HTTP/HTTPS) ni las ráfagas típicas de descarga de datos.

### 6. Posibles confusiones
*   **Automatización normal:** Podría confundirse con scripts de mantenimiento 
o keep-alive, pero estos suelen completar handshakes.
*   **SSH Legítimo:** El ataque es fácilmente separable del SSH real, ya que el
tráfico legítimo tiene duraciones largas y muchos paquetes [19].
*   **Ruido de Red:** Es el mayor riesgo. Conexiones fallidas por congestión o 
firewalls externos pueden generar flujos de 1 paquete y RST que imiten al 
ataque.
*   **Otras anomalías:** Podría solaparse con **escaneos de red** genéricos, 
pero la etiqueta específica "sshscan" se justifica por el puerto destino fijo 
[6].

### 7. Señales fiables de separación
La señal más fuerte es la **combinación de baja entropía estructural**: 
`IP_Origen Fija + Puerto_Destino 22 + Tamaño_Paquete Fijo (40B) + Flag RST`. En
el background, aunque existen flujos de 40B, no suelen concentrarse en una sola
IP interna barriendo el puerto 22 hacia el exterior.

### 8. Señales débiles (Aisladas)
*   La **duración 0.000** es inútil por sí sola (38% del tráfico ISP es así) 
[7].
*   El **protocolo TCP** es demasiado genérico (67-71% del tráfico) [7, 12].
*   El **timestamp** no aporta valor predictivo al no ser masivo [7].

### 9. Valor de las escalas de información
*   **Centered_sources:** Aportan la **evidencia estructural** del handshake 
fallido [1, 16].
*   **Rows_2000 / Time_10s:** Permiten ver que el ataque es **invisible por 
volumen**; el atacante `.231` se mezcla con otros hosts internos muy activos 
[9, 10, 15].
*   **Time_60s summaries:** Demuestran que la anomalía es estadísticamente 
**insignificante** [17], lo que obliga a usar detectores basados en firmas o 
estados, no en umbrales de tráfico.

### 10. Limitaciones
*   **Sesgo de Etiquetado:** La etiqueta "anomaly" presupone malicia, pero 
técnicamente podría ser un cliente SSH mal configurado o un escáner de 
auditoría interna [20].
*   **Invisibilidad Estadística:** Al ser tan sutil (1-2 flujos por minuto), 
cualquier modelo basado en medias o varianzas de la red global fallará en 
detectarlo [17, 21].
*   **Falsos Positivos de Red:** Un destino externo que esté caído generará 
flujos de 1 paquete y 0 duración para cualquier host interno que intente 
conectar, imitando el patrón del ataque.

**Conclusión crítica:** Lo que diferencia a `anomaly-sshscan` del tráfico 
normal no es "cuánto" ensucia la red, sino **"cómo" de monótono y 
estructuralmente incompleto** es su comportamiento en comparación con la rica 
diversidad y completitud de las sesiones de usuario reales.

Conversation: 2d07e18b-fdb7-4a34-bd61-535e8999ea36 (turn 1)

---

## Síntesis para validación

`anomaly-sshscan`


Esta es la síntesis técnica final del ataque **anomaly-sshscan**, estructurada 
para servir como especificación en una fase de validación programática.

### 1. Nombre del ataque analizado
**anomaly-sshscan** [1-3].

### 2. Categoría técnica propuesta
**Reconocimiento sigiloso (Low-and-Slow Horizontal Port Probing)** [4, 5].

### 3. Descripción breve del patrón
Actividad de sondeo persistente y de bajísimo volumen originada en un host 
interno, caracterizada por flujos TCP de un solo paquete dirigidos al puerto 22
de múltiples hosts externos, finalizados abruptamente mediante el flag Reset 
(R) [4, 6, 7].

### 4. Topología
*   **Patrón:** 1→Muchos (un único origen interno hacia múltiples destinos 
externos) [1, 4, 8].
*   **Concentración:** Absoluta en la dirección IP origen **`42.219.156.231`** 
[1, 4, 7, 9].
*   **Dispersión:** Alta en las IPs destino, que parecen ser objetivos externos
aleatorios o predefinidos (ej. `154.29.70.254`, `129.104.110.251`) [1, 7, 10].
*   **Roles:** El origen interno actúa como escáner/probeta; los destinos 
externos actúan como servidores SSH pasivos [4, 11].

### 5. Métricas principales observadas
*   **Protocolo:** TCP (estricto) [1, 4, 7].
*   **Puertos origen:** Puertos altos dinámicos y no secuenciales (ej. 61193, 
34624, 16397, 1575) [1, 4, 7, 8].
*   **Puertos destino:** Fijo en **22 (SSH)** [1, 4, 7, 10].
*   **Duración:** Invariablemente **0.000 segundos** [1, 4, 7, 8].
*   **Paquetes:** Exactamente **1 paquete** por registro de flujo [1, 4, 7, 8].
*   **Bytes:** Uniformidad extrema entre **40 y 44 bytes** [1, 4, 7, 8, 10].
*   **Flags:** Predomina el flag **Reset (`...R..`)** enviado desde el origen 
hacia el destino [7, 9, 12-14].
*   **Timestamps:** Apariciones esporádicas pero constantes a lo largo del día 
(ej. 07:35, 10:47, 11:30, 12:23) [1, 4, 7, 8].

### 6. Invariantes fuertes
*   **Tupla Estructural:** La combinación `IP_Origen (.231) + Port_Dest (22) + 
Pkts (1) + Duration (0) + Flag (R)`. Es robusta porque aparece de forma 
idéntica en todas las ventanas temporales analizadas [4, 7, 13, 15].
*   **Host Monolítico:** Solo la IP `42.219.156.231` está asociada a la 
etiqueta de ataque en las muestras, a pesar de que otras IPs realizan SSH 
legítimo o escaneos no etiquetados [1, 4, 7, 16, 17].

### 7. Invariantes secundarios
*   **Tamaño del paquete:** 40-44 bytes (paquete TCP sin carga útil) [1, 4, 7].
*   **Frecuencia:** Menos de 5 flujos por cada 100,000 registros (ratio 0.0000)
[18-22].

### 8. Señales de automatización
*   **Estructura:** La automatización reside en la **monotonía métrica**. La 
repetición exacta de flujos de 1 paquete y 0 duración hacia un puerto 
específico es indicativa de un script de sondeo de puertos (port knocking o 
discovery) [4, 5, 7].
*   **Frecuencia Controlada:** La dispersión temporal sugiere una herramienta 
configurada para evitar detectores volumétricos basados en ráfagas [1, 4, 7].

### 9. Diferencias con background
*   **Estado de la conexión:** Mientras que el background SSH legítimo presenta
flujos con múltiples paquetes y estados completos (`.AP.SF`), el ataque nunca 
llega a la fase de intercambio de datos [23-26].
*   **Flags:** El background usa mayoritariamente `ACK` o combinaciones de 
`Push-Fin`; el ataque usa el `Reset` como firma de finalización anómala [4, 7, 
26].
*   **Entropía de puerto destino:** El tráfico normal es multidestino y 
multipuerto; el ataque muestra entropía cero en el puerto destino (siempre 22) 
[26, 27].

### 10. Posibles confusiones
*   **Ruido de red:** Conexiones SSH fallidas legítimas por saturación o 
firewalls externos pueden generar flujos de 1 paquete y RST que imiten el 
patrón [5, 12].
*   **Sondeos DNS/HTTP:** Flujos de 1 paquete son muy comunes en DNS (UDP) o 
HTTP fallido, pero el puerto 22 es la clave para separarlos [1, 9, 26, 28].

### 11. Evidencia suficiente (Observaciones)
*   El origen es invariablemente `42.219.156.231` [1, 4, 7].
*   El ataque es horizontal (IPs destino dispersas) [1, 4, 7].
*   La duración es nula y el volumen de datos es cero (solo cabeceras) [1, 4, 
7].

### 12. Evidencia insuficiente (Hipótesis)
*   **Intencionalidad:** No se puede confirmar si es un escaneo malicioso o una
herramienta de monitoreo interno mal configurada [12].
*   **Continuidad:** No hay evidencia en las fuentes de que el escaneo sea el 
preludio de un ataque de fuerza bruta masivo en la misma ventana temporal [18, 
22].

### 13. Requisitos para validación posterior
*   **Medición script:** Contar flujos TCP por IP origen dirigidos al puerto 22
externo.
*   **Agregación necesaria:** Ventanas de 60 segundos agrupando por `IP_Origen`
[18, 29].
*   **Umbrales:** 
    *   `Pkts == 1`
    *   `Duration == 0`
    *   `Bytes <= 44`
*   **Análisis temporal:** Identificar si la IP origen mantiene esta actividad 
de forma persistente (ej. en más de 3 ventanas consecutivas de 60s) con una 
tasa de éxito (handshake completo) de 0% [4, 7, 12, 26].

### 14. Encaje en el modelo de comportamiento sintético
*   **Categoría:** Encaja en **Network Scanning** [2].
*   **Modificación:** Requiere una subcategoría de **"Low Intensity Anomaly"** 
donde la desviación no es el volumen (bytes/paquetes por segundo), sino la 
**invarianza estructural y la anomalía de estado (RST)** [5, 12, 30].

### 15. Conclusión final
El **anomaly-sshscan** se define como un **proceso de sondeo horizontal TCP 
sigiloso**, ejecutado por el host interno **`42.219.156.231`**, que emite 
flujos unitarios (1 pkt) de baja entropía hacia el puerto 22 externo, 
caracterizados por una terminación anómala mediante Reset y una invisibilidad 
estadística en términos de volumen de red global.

Conversation: 2d07e18b-fdb7-4a34-bd61-535e8999ea36 (turn 1)

---


# dos

Directorio de resultados:

```text
data\notebooklm_outputs\dos
```

## Análisis estructural

`dos`


Este análisis técnico profundiza en el comportamiento del ataque etiquetado 
como **dos** (Denial of Service) basándose en las múltiples escalas de 
información proporcionadas en las fuentes.

### 1. Resumen ejecutivo del patrón observado
El ataque se manifiesta como una inundación de conexiones de red de **muy corta
duración** y **alta uniformidad estructural** [1, 2]. Se caracteriza por flujos
TCP masivos dirigidos principalmente hacia el puerto 80, utilizando puertos 
origen secuenciales y un conjunto restringido de IPs que actúan de forma 
coordinada [3-5]. La métrica dominante es la **baja entropía** en la duración y
el tamaño de los paquetes, lo que indica un origen sintético o automatizado [2,
6, 7].

### 2. Topología de comunicación
*   **Número de IPs origen relevantes:** El ataque involucra un grupo pequeño 
pero constante de IPs origen, destacando aproximadamente entre 8 y 10 
direcciones dominantes (ej. `42.219.152.20`, `42.219.158.16`, y el rango 
`42.219.150.241` al `247`) [5, 8].
*   **Número de IPs destino relevantes:** Se observa una topología de **muchos 
a muchos** dentro de un segmento específico [5, 8]. Sin embargo, en ventanas de
alta intensidad, el tráfico parece concentrarse en pares específicos de IPs que
intercambian roles [5, 8].
*   **Patrón de concentración:** Existe una **altísima concentración** de 
tráfico en el puerto 80, que absorbe la mayoría de las filas del ataque [5, 8].

### 3. Actores principales
*   **IPs origen dominantes:** `42.219.152.20`, `42.219.158.16`, 
`42.219.150.241`, `42.219.150.242`, `42.219.150.243`, `42.219.150.246`, 
`42.219.150.247` [5, 8].
*   **IPs destino dominantes:** Las mismas IPs mencionadas anteriormente suelen
aparecer como destinos, sugiriendo un escenario de ataque interno o una 
simulación donde las víctimas pertenecen al mismo direccionamiento [5, 8].
*   **Origen:** Dado el prefijo `42.219.x.x`, que es el mismo del tráfico de 
fondo (background), los atacantes parecen ser **internos** al direccionamiento 
del ISP o parte de un modelo sintético diseñado para mezclarse con el tráfico 
legítimo [9-11].

### 4. Protocolos y puertos
*   **Protocolo predominante:** **TCP** es el protocolo absoluto del ataque, 
representando más del 80% del tráfico en ventanas críticas [5, 8].
*   **Puertos destino:** El puerto **80 (HTTP)** es el objetivo principal [5, 
8].
*   **Puertos origen:** Se observa una técnica de **puertos secuenciales** (ej.
2491, 2492, 2493...) [3, 4, 12].
*   **Patrón de barrido:** Es un patrón **híbrido**; es vertical en cuanto a 
que utiliza ráfagas de puertos origen contra un puerto destino fijo, pero es 
distribuido al involucrar múltiples IPs atacantes simultáneamente [3, 5, 13].

### 5. Métricas de flujo
*   **Duración:** Extremadamente baja, frecuentemente **0.000 o 0.004 
segundos** [3, 4, 14, 15].
*   **Paquetes:** Usualmente **1 o 2 paquetes** por flujo [3, 4, 16].
*   **Bytes:** Muy uniformes, con valores repetitivos como **40, 160 o 200 
bytes** [3, 4, 15].
*   **Flags TCP:** Predominan las flags de inicio y reinicio: **SYN** 
(`....S.`), **RESET/SYN** (`...RS.`), y **ACK/SYN** (`.A..S.`) [3-5, 17].
*   **Baja entropía:** La varianza en bytes y duración en los flujos 
etiquetados como "dos" es mínima comparada con el background [2, 6].

### 6. Comportamiento temporal
*   **Ráfagas y simultaneidad:** El ataque opera en ráfagas de **alta densidad 
temporal**. Se observan decenas de flujos iniciados en el **exacto mismo 
milisegundo** [3, 4, 12].
*   **Periodicidad:** En las ventanas de 10s y 60s, se nota que el ataque no es
constante, sino que aparece en bloques densos seguidos de periodos de menor 
actividad o tráfico de fondo [3, 5, 18].
*   **Sincronización:** Existe una sincronización casi perfecta entre las 
diferentes IPs atacantes, lo que refuerza la señal de automatización [3, 4, 
15].

### 7. Señales de automatización
*   **Secuencialidad de puertos:** El incremento de uno en uno en los puertos 
origen es una firma clásica de herramientas de flood (como *hping3*) [3, 4, 12,
13].
*   **Timestamps idénticos:** La capacidad de generar múltiples flujos en el 
mismo instante temporal (`0.000` relativo a la captura) localiza la 
automatización en el **host atacante** [3, 16, 19].
*   **Estructura de paquetes:** La repetición exacta de tamaños de paquete (ej.
siempre 200 bytes) indica que los paquetes no transportan datos variables, sino
que son meras sondas o paquetes de inundación [4, 20, 21].

### 8. Variaciones entre fuentes
*   **Fuentes centradas:** Aíslan el patrón puro, permitiendo ver la secuencia 
de puertos sin distracciones [22, 23].
*   **Ventanas rows_2000:** Muestran cómo el ataque "ahoga" al background 
localmente, ocupando bloques casi continuos de la ventana [3, 14].
*   **Ventanas time_10s:** Permiten ver la **densidad del ataque** (pueden 
aparecer miles de filas de "dos" en menos de un segundo) [3, 4].
*   **Resúmenes time_60s:** Aportan la visión macro: el ataque puede elevar el 
ratio de tráfico TCP al 83% y reducir la duración media de los flujos de la red
debido a la masa de conexiones instantáneas [5, 8].

### 9. Invariantes robustos
*   **Uso del puerto destino 80.**
*   **Duración de flujo inferior a 0.01s.**
*   **Flags de control TCP (SYN, RS, AS).**
*   **IPs del rango 42.219.150.x y 152.x.**
*   **Secuencialidad en puertos origen.**

### 10. Rasgos débiles o no constantes
*   **Aparición de flags RESET (`...R..`):** No siempre aparecen en todas las 
ráfagas, lo que podría depender de si el destino está respondiendo o si el 
ataque es de una sola vía [24-26].
*   **Volumen:** El ratio de ataque varía drásticamente entre ventanas (de 0.04
a 0.46), indicando que el ataque tiene fases de intensidad variable [1, 2, 6].

### 11. Interpretación técnica
*   **Tipo de comportamiento:** Representa un **SYN Flood** o un **Connection 
Flood**.
*   **Objetivo:** Agotar los recursos del sistema destino (tabla de conexiones,
CPU o ancho de banda) mediante la apertura masiva de sesiones TCP que nunca 
llegan a completarse o se cierran inmediatamente [9].
*   **Interpretación de la etiqueta:** No debe verse solo como "malicioso" por 
la etiqueta, sino como un **comportamiento anómalo por su estructura** 
(demasiado perfecto y repetitivo para ser tráfico humano o de aplicaciones 
estándar) [10].

### 12. Limitaciones
*   **Sesgo de direccionamiento:** Al ser todas las IPs del mismo prefijo 
`42.219.x.x`, es difícil distinguir atacantes de víctimas basándose solo en la 
IP si no se conoce la topología lógica del ISP [11].
*   **Riesgo de confusión:** Tráfico legítimo de muy corta duración (ej. 
chequeos de salud de balanceadores o microservicios) podría parecerse al 
ataque, aunque carecería de la secuencialidad de puertos origen a tal escala 
[10].
*   **Validación necesaria:** Se requiere validar mediante código si la 
secuencialidad de puertos es estrictamente lineal a lo largo de toda la 
duración del ataque o si se reinicia [9].

### 13. Conclusión
El patrón final del ataque **dos** en este dataset es una **inundación TCP 
distribuida y altamente automatizada** dirigida al puerto 80, con flujos de 1-2
paquetes y duración cercana a cero [5, 8].

*   **Encaje en el modelo:** Encaja perfectamente en el **modelo de 
comportamiento sintético**, ya que muestra una uniformidad métrica y una 
coordinación temporal imposibles de encontrar en tráfico orgánico [9, 27].
*   **Modificación del modelo:** El análisis sugiere que el modelo no solo debe
buscar "mucho tráfico", sino específicamente **secuencialidad en puertos origen
y colisión de timestamps**, que son los rasgos más discriminantes observados 
[3, 4].

---
**Diferenciación de tipos de información:**
*   *Observaciones apoyadas:* Secuencialidad de puertos, duración cero, flags 
TCP específicas, IPs dominantes.
*   *Interpretaciones técnicas:* Uso de herramientas tipo *hping3*, objetivo de
agotamiento de recursos.
*   *Hipótesis a validar:* Si el ataque es de origen interno real o si las IPs 
atacantes están siendo suplantadas (spoofing) dentro de la red del ISP.

---

## Comparación con background

`dos`


Esta comparativa técnica analiza las diferencias estructurales entre el ataque 
**dos** y el tráfico **background** en el dataset UGR'16, basándose en la 
variabilidad métrica y el contexto de una red ISP.

### 1. Rasgos diferenciadores claros
*   **Duración de flujo:** Mientras el background presenta una distribución 
variada de duraciones (desde milisegundos hasta flujos largos de varios 
segundos), el ataque tiene una duración casi nula (**0.000 o 0.004 segundos**) 
en prácticamente todas sus instancias [1-3].
*   **Uniformidad de carga útil:** El ataque presenta tamaños de paquete 
extremadamente rígidos (ej. siempre **40, 160 o 200 bytes**), lo que genera una
señal de **entropía mínima** frente a la variabilidad del background [3-5].
*   **Secuencialidad de puertos origen:** El ataque utiliza puertos origen que 
incrementan de uno en uno (ej. 2491, 2492, 2493...), un rasgo inexistente en el
tráfico orgánico del background [5, 6].

### 2. Rasgos ambiguos (no bastan por sí solos)
*   **Uso del puerto 80:** Tanto el ataque como gran parte del background 
legítimo se dirigen al puerto 80 (HTTP) [1, 7, 8].
*   **Flag SYN (`....S.`):** Aparece en el ataque pero es también la señal 
estándar de inicio de cualquier conexión TCP legítima en el background [8, 9].
*   **Flujos de 1-2 paquetes:** Aunque el ataque los usa masivamente, el 
background también contiene flujos cortos (ruido de red, intentos fallidos o 
escaneos benignos) [1, 10, 11].

### 3. Métricas con mayor desviación
*   **Timestamps:** El ataque muestra una **colisión masiva de tiempos**, con 
cientos de flujos iniciados exactamente en el mismo milisegundo (ej. 
`08:09:46,0.000`), algo que no ocurre en el background disperso [5, 6, 12].
*   **Puertos origen:** Desviación total hacia la **secuencialidad lineal**, en
contraste con la asignación pseudoaleatoria o efímera del tráfico normal [5, 
13].
*   **Flags:** Predominio de combinaciones de control puro como **SYN/RESET 
(`...RS.`)** o **RESET/ACK (`.A.R..`)** en el ataque, frente a la secuencia 
completa de sesión (`.AP.SF`) del background [4, 8, 9, 14].
*   **Duración:** Desviación hacia el límite inferior (cero absoluto) [3, 15].

### 4. Cambios en la diversidad
*   **Diversidad de IPs:** El ataque reduce la diversidad relativa; aunque 
involucre varias IPs, un grupo muy pequeño de 5-10 direcciones genera casi el 
50% del tráfico en ventanas de alta intensidad [16, 17].
*   **Diversidad de puertos:** La diversidad de puertos destino colapsa hacia 
el puerto 80, mientras que la de puertos origen se vuelve artificialmente 
predecible (secuencial) [5, 16].
*   **Diversidad de protocolos:** El ratio de **TCP sube drásticamente** (hasta
el 83%), desplazando la presencia normal de UDP e ICMP en el mix de la red [8, 
17].
*   **Diversidad temporal:** El tráfico normal es estocástico; el ataque es 
**en ráfagas sincronizadas** [5, 18].

### 5. Ruptura de la cicloestacionariedad
El ataque rompe la naturaleza de una red ISP al introducir una carga masiva que
**no sigue patrones humanos ni de aplicaciones estándar**. La varianza de bytes
y duración se altera significativamente, creando picos de actividad que 
"ahogan" estadísticamente al background en ventanas de 60s, elevando el ratio 
de ataque del 0.04 al 0.46 en periodos cortos [11, 15].

### 6. Posibles confusiones
*   **Escaneo benigno:** Podría confundirse por la brevedad de los flujos, pero
los escaneos suelen ser más lentos o tener una progresión de puertos destino, 
no origen [1, 19].
*   **HTTP/HTTPS legítimo:** Comparten el puerto, pero las sesiones legítimas 
muestran flujos con más paquetes, mayor duración y banderas de empuje (`P`) [7,
20].
*   **Automatización normal:** Chequeos de salud (health checks) pueden ser 
frecuentes, pero no muestran la secuencialidad de puertos origen a escala de 
miles por segundo [5].

### 7. Señales de separación fiables
*   La combinación de **duración cero + puerto 80 + puertos origen 
secuenciales** [5, 16].
*   La **densidad temporal extrema**: miles de filas etiquetadas como "dos" en 
ventanas de tiempo donde el background solo genera decenas de flujos [3, 15].

### 8. Señales débiles aisladas
*   El tamaño de paquete de 40 o 200 bytes por sí solo (común en paquetes de 
control) [1, 4].
*   La IP origen (muchas IPs del ataque pertenecen al direccionamiento normal 
del ISP `42.219.x.x`) [8, 16].

### 9. Evidencia según el tipo de ventana
*   **Centered sources:** Aportan la **firma pura** del ataque (secuencialidad 
y flags) [1, 4].
*   **Rows_2000:** Permiten observar la **intermisión**, cómo el ataque se 
intercala con el background real [2, 9].
*   **Time_10s:** Es la mejor para ver la **densidad y ráfagas** [5, 18].
*   **Time_60s summaries:** Útiles para detectar el **desplazamiento de 
protocolos** y la caída en la duración media de la red [3, 15].

### 10. Limitaciones de la comparación
*   **Sesgo topológico:** Atacantes y víctimas comparten el prefijo 
`42.219.x.x`, lo que sugiere que el ataque es interno o está simulado dentro 
del segmento del ISP [8, 21].
*   **Falta de visibilidad de carga:** Las fuentes CSV no muestran el contenido
de los paquetes, solo metadatos, por lo que la distinción entre un SYN Flood y 
un Connection Flood se basa en la interpretación de flags y duración [4, 9].
*   **Mezcla de etiquetas:** Algunas ventanas muestran tráfico etiquetado como 
`blacklist` que comparte rasgos con el background, lo que añade ruido a la 
definición de "normalidad" [19, 22].

### Conclusión técnica crítica
El tráfico **dos** no es simplemente "mucho tráfico", sino un **tráfico con 
estructura degenerada**. Se diferencia del background por su **baja entropía 
métrica** (duración y tamaño fijos) y su **alta coordinación temporal** 
(ráfagas secuenciales). Mientras el tráfico normal es un conjunto de 
conversaciones diversas y asíncronas, el ataque es una ejecución monótona y 
altamente síncrona de comandos de red.

Conversation: 3498515c-dca1-4140-b276-331e66920635 (turn 1)

---

## Síntesis para validación

`dos`


Esta síntesis técnica define el perfil del ataque **dos** identificado en el 
dataset UGR'16, diseñada para actuar como especificación en una fase de 
validación programática.

### 1. Nombre del ataque analizado
**dos** (Denial of Service). [1], [2].

### 2. Categoría técnica propuesta
**Distributed TCP Flood con colapso de entropía métrica.** Representa un ataque
de agotamiento de recursos mediante inundación de conexiones SYN y ráfagas de 
RESET. [3], [4], [5].

### 3. Descripción breve del patrón
Inundación masiva de flujos TCP dirigida predominantemente al puerto 80, 
caracterizada por duraciones de flujo cercanas a cero, carga útil fija y una 
**progresión lineal secuencial** de los puertos origen. [3], [6], [4], [7].

### 4. Topología
*   **Patrón:** **Muchos a Muchos** dentro de un segmento de red local (prefijo
`42.219.x.x`). [8], [5], [9].
*   **Concentración:** Extrema en el **puerto destino 80**. [8], [10], [11].
*   **Rol de IPs:** Un grupo de IPs dominantes (ej. `42.219.152.20`, 
`42.219.158.16`) intercambian roles de origen y destino, sugiriendo una 
simulación de ataque entre hosts del mismo segmento o un ataque interno. [3], 
[12], [5], [9].

### 5. Métricas principales observadas
*   **Protocolo:** **TCP** (representa hasta el 83% del tráfico en ventanas de 
alta intensidad). [8], [9].
*   **Puertos origen:** Secuenciales (incrementos de +1 o +2 en ráfagas). [3], 
[4], [13], [14].
*   **Puertos destino:** Puerto **80** mayoritariamente. [8], [5].
*   **Duración:** **0.000s o 0.004s** (flujos instantáneos). [3], [15], [4], 
[7].
*   **Paquetes:** **1 o 2 paquetes** por flujo. [3], [16], [15], [4], [17].
*   **Bytes:** Valores rígidos de **40, 160 o 200 bytes**. [3], [16], [4], [7].
*   **Flags:** Combinaciones de control: **SYN** (`....S.`), **RESET/SYN** 
(`...RS.`) y **ACK/SYN** (`.A..S.`). [3], [4], [18], [8].
*   **Timestamps:** Alta simultaneidad; decenas de flujos con el **exacto mismo
milisegundo** de inicio. [3], [6], [4], [14].

### 6. Invariantes fuertes
*   **Persistencia del Puerto 80:** El ataque no varía de puerto destino en 
ninguna de las ventanas analizadas. [8], [5], [11].
*   **Secuencialidad de Puertos Origen:** La progresión lineal de puertos es 
una firma constante en las ráfagas del ataque. [3], [19], [14].
*   **Baja Varianza Métrica:** La duración y el tamaño de los bytes presentan 
una varianza casi nula dentro de la etiqueta "dos". [7], [17].

### 7. Invariantes secundarios
*   **IPs del rango 42.219.150.x:** Aunque son recurrentes, pertenecen al 
direccionamiento normal del ISP, por lo que no son un indicador único fiable 
sin el patrón de puertos. [20], [3], [8].

### 8. Señales de automatización
*   **Lógica de puertos:** El incremento lineal de puertos origen (`7365, 7366,
7367...`) localiza la automatización en el motor de generación de paquetes del 
atacante. [3], [4].
*   **Sincronización entre nodos:** Múltiples IPs origen inician ataques en el 
mismo milisegundo, indicando una herramienta de orquestación o un script 
coordinado. [4], [21], [22], [23].

### 9. Diferencias con background
*   **Entropía:** El background es métricamente diverso (duraciones y tamaños 
variados); el ataque es **monótono**. [2], [7].
*   **Conversación:** El background muestra sesiones TCP completas (flags 
`.AP.SF`); el ataque muestra **sesiones truncadas o de control** (`.A..S.`, 
`...RS.`). [3], [8].
*   **Densidad Temporal:** El ataque genera ráfagas de miles de flujos en 
segundos, superando por órdenes de magnitud la frecuencia de conexión del 
background. [2], [7].

### 10. Posibles confusiones
*   **Tráfico Legítimo HTTP:** Se comparte el puerto 80, pero el tráfico 
legítimo tiene mayor duración y más de 2 paquetes. [24], [8].
*   **Escaneos Benignos:** Pueden usar flujos cortos, pero suelen variar el 
puerto destino, no el origen de forma secuencial. [25].

### 11. Evidencia suficiente
*   El ataque es una inundación TCP automatizada dirigida al puerto 80. [3], 
[4], [8].
*   La secuencialidad de puertos origen es la firma estructural más robusta. 
[3], [4], [14].

### 12. Evidencia insuficiente
*   **Atribución de IPs:** No se puede confirmar si las IPs son atacantes 
reales o víctimas reflejando tráfico sin un análisis de la topología lógica del
ISP. [3], [8].
*   **Persistencia Temporal:** Se observa actividad en ventanas de 60s, pero se
requiere validar si existen ciclos de inactividad programada (periodicidad). 
[7], [17].

### 13. Requisitos para validación posterior
*   **Métrica de linealidad:** Calcular el ratio de puertos origen consecutivos
(Δ port = 1) por IP y ventana temporal.
*   **Agregación por milisegundo:** Contar el número de flujos por IP/destino 
en el mismo timestamp.
*   **Análisis de entropía:** Establecer umbrales de varianza para `duración` y
`bytes`.
*   **Perfil de Flags:** Medir la dominancia de flujos sin flags de datos (`P`)
sobre el total de la ventana.

### 14. Encaje en el modelo de comportamiento sintético
*   Encaja plenamente en el **modelo sintético** debido a su estructura 
degenerada. [24].
*   Se propone una nueva subcategoría: **"Secuencialidad Lógica en Inundación 
de Control"**.

### 15. Conclusión final
El ataque **dos** es una **inundación TCP distribuida y altamente síncrona** 
dirigida al puerto 80, ejecutable mediante herramientas de flood, y 
distinguible del tráfico ISP normal por su **nula variabilidad métrica y su 
progresión lineal de puertos origen**. [3], [4], [8], [5].

---
*   **Observación:** Secuencialidad de puertos, duración cero, puerto 80.
*   **Interpretación:** Uso de herramientas de flood (tipo hping3).
*   **Hipótesis:** El ataque podría estar simulado internamente en la red del 
ISP dado que atacantes y víctimas comparten direccionamiento.

Conversation: 3498515c-dca1-4140-b276-331e66920635 (turn 1)

---


# anomaly-udpscan

Directorio de resultados:

```text
data\notebooklm_outputs\anomaly-udpscan
```

## Análisis estructural

`anomaly-udpscan`


Este análisis técnico extrae el patrón de comportamiento de red del ataque 
**anomaly-udpscan** basándose en las múltiples escalas de información 
proporcionadas.

### 1. Resumen ejecutivo del patrón observado
El ataque consiste en un **escaneo UDP masivo y altamente automatizado**, 
originado por una única IP externa que realiza barridos híbridos (horizontales 
y verticales) a alta velocidad [1-4]. Se caracteriza por flujos de **un solo 
paquete**, duración nula y un tamaño de bytes extremadamente uniforme, lo que 
genera una huella de **baja entropía** fácilmente distinguible del tráfico de 
fondo [1, 4-6].

### 2. Topología de comunicación
*   **Número de IPs origen relevantes:** Una única IP origen domina 
completamente el escenario del ataque: **217.156.59.213** [4, 7, 8].
*   **Número de IPs destino relevantes:** Cientos de IPs destino pertenecientes
principalmente al rango **42.219.x.x** y, en menor medida, **212.112.x.x** [1, 
2, 4, 5].
*   **Tipo de patrón:** El patrón es **1→muchos** (horizontal) combinado con un
**barrido de puertos** interno por cada host (vertical) [1, 9-11].
*   **Concentración/Dispersión:** Existe una **concentración absoluta en el 
origen** y una **dispersión masiva en el destino**, abarcando múltiples 
subredes de la red interna [12-14].

### 3. Actores principales
*   **IP origen dominante:** `217.156.59.213` [4, 8, 15].
*   **IPs destino dominantes:** Aparecen IPs recurrentes como `42.219.156.211`,
`42.219.155.28` y `143.72.8.137` en los resúmenes estadísticos, indicando que 
son objetivos de escaneos más intensos o prolongados [4, 7, 16].
*   **Papel de los actores:** La IP `217.156.59.213` actúa como 
**sonda/escaneador**, mientras que las IPs internas actúan como **objetivos de 
reconocimiento** [4, 6].
*   **Ubicación del origen:** El origen parece ser **externo al ISP**, atacando
desde una red externa hacia los rangos de clientes del ISP [1, 4, 17].

### 4. Protocolos y puertos
*   **Protocolo predominante:** **UDP** de forma exclusiva para las trazas 
etiquetadas como ataque [1, 4, 5].
*   **Puertos origen relevantes:** Utiliza puertos origen fijos que cambian por
ráfagas: **5061, 5062, 5066 y 5068** [1, 3, 4, 15, 18, 19].
*   **Puertos destino relevantes:** Realiza barridos secuenciales en rangos 
específicos, como **5000-5090**, **6000-6060** y **7000-7060** [1, 3, 5, 8, 
18].
*   **Tipo de barrido:** Es un patrón **híbrido**; es horizontal porque salta 
entre IPs y vertical porque recorre secuencias de puertos en cada una [1, 
9-11].

### 5. Métricas de flujo
*   **Duración:** Invariablemente **0.000 segundos** [1, 2, 4, 5].
*   **Paquetes:** Exactamente **1 paquete** por flujo [1, 4, 5].
*   **Bytes:** Extremadamente uniformes, oscilando casi siempre entre **428 y 
436 bytes** [1, 2, 5, 18, 20].
*   **Varianza:** La varianza en las métricas de los flujos de ataque es **casi
nula**, a diferencia del tráfico de fondo (background) que presenta gran 
variabilidad [4, 21, 22].
*   **Flags:** Aparece la flag `.A....`, lo cual en flujos UDP es una anomalía 
de representación o un artefacto del colector NetFlow [1, 2, 4].

### 6. Comportamiento temporal
*   **Ráfagas:** El ataque se organiza en **ráfagas masivas** de flujos 
simultáneos [4, 15].
*   **Timestamps dominantes:** Se observan cientos de flujos compartiendo el 
**mismo segundo** (ej. `04:10:22`, `04:12:48`), lo que indica una tasa de envío
altísima [1, 3, 15, 23].
*   **Simultaneidad:** La herramienta lanza múltiples sondas por milisegundo a 
diferentes puertos o IPs [1, 2, 4].
*   **Periodicidad:** Los resúmenes de 60s muestran que el ataque mantiene una 
**actividad constante durante varios minutos** con cambios bruscos en el puerto
origen [4, 7, 8, 15].

### 7. Señales de automatización
*   **Elementos generados por herramienta:** La **secuencialidad perfecta de 
los puertos destino** y la **identidad métrica de los flujos** (1 pkt, ~433 
bytes, 0 dur) son firmas inequívocas de una herramienta [1, 4, 5, 8].
*   **Localización de la automatización:** La lógica reside enteramente en el 
nodo origen `217.156.59.213` [4, 7].
*   **Servicio concreto:** Los rangos de puertos (5000s, 6000s) y el tamaño de 
paquete sugieren un escaneo orientado a **servicios de VoIP (SIP) o 
señalización**, aunque esto es una interpretación técnica [6, 24].

### 8. Variaciones entre fuentes
*   **Fuentes centradas:** Permiten ver la **micro-estructura** del escaneo: el
orden exacto de los puertos destino [1, 25].
*   **Ventanas rows_2000:** Muestran cómo el ataque "ahoga" al background 
localmente; en estas ventanas, el ataque puede representar más del 90% de las 
filas [10, 26].
*   **Ventanas time_10s:** Permiten ver la **densidad temporal** del ataque 
frente al tráfico normal de red en intervalos cortos [27, 28].
*   **Resúmenes time_60s:** Aportan la visión de la **evolución del ataque**, 
revelando que el puerto origen rota (ej. de 5061 a 5062 y luego a 5066) a 
medida que pasa el tiempo [4, 7, 15].
*   **Ampliación de la ventana:** Al ampliarla, se nota que el patrón no es 
estático, sino que **muta sus puertos origen y rangos destino** mientras 
mantiene sus invariantes métricos [4, 8].

### 9. Invariantes robustos
*   **IP origen única:** `217.156.59.213` [4, 7, 8].
*   **Protocolo:** UDP [1, 4].
*   **Estructura del flujo:** 1 paquete, duración 0, tamaño ~433 bytes [1, 4, 
5].
*   **Naturaleza del escaneo:** Secuencialidad en puertos destino [1, 3, 5].

### 10. Rasgos débiles o no constantes
*   **Puerto origen:** Cambia entre varias ráfagas (5061, 5062, 5066, 5068) [1,
3, 15, 19].
*   **Rango de puertos destino:** Salta entre diferentes bloques de 100 puertos
[1, 18, 29].
*   **Ratio de ataque:** Varía drásticamente entre ventanas (de 0.62 a 0.0006),
lo que indica que el ataque tiene un **inicio y fin definidos** [13, 22].

### 11. Interpretación técnica
*   **Tipo de comportamiento:** Representa un **reconocimiento de red 
agresivo** [6].
*   **Objetivo probable:** Identificar hosts internos con servicios UDP 
abiertos, posiblemente para preparar un ataque posterior de denegación de 
servicio (DoS) o explotación de vulnerabilidades en protocolos de señalización 
[6, 24].
*   **Etiqueta vs. Realidad:** Aunque se etiqueta como "udpscan", es importante
notar que su comportamiento es mucho más **rígido y predecible** que un escaneo
manual, lo que lo sitúa en la categoría de **anomalía estructural** [6, 30].

### 12. Limitaciones
*   **Fragmentación:** Al ser ventanas de tiempo o filas, no tenemos la traza 
completa desde el flujo 1 hasta el final [12, 30].
*   **Sesgo de selección:** Las fuentes centradas están pre-filtradas para 
resaltar el ataque, lo que podría exagerar su visibilidad respecto al ruido 
real [30].
*   **Background ruidoso:** En ventanas completas (ej. `rows_2000`), el tráfico
TCP (puertos 80, 443) oculta parcialmente la cadencia del escaneo si no se 
filtra por protocolo [17, 31].
*   **Validación necesaria:** Sería necesario validar con código si existe una 
**cadencia temporal exacta** (periodicidad) entre los paquetes o si el envío es
a "máxima velocidad" según el hardware [30].

### 13. Conclusión
El patrón final es un **escaneo UDP determinista** ejecutado por 
`217.156.59.213` mediante flujos atómicos (1 pkt, ~433B, 0s) que barren puertos
destino secuencialmente [1, 4, 5].
*   **Encaje en el modelo sintético:** Encaja perfectamente, ya que el modelo 
sintético predice comportamientos de **baja entropía y alta repetición** [4, 
6].
*   **Modificación del modelo:** El análisis sugiere ampliar el modelo para 
incluir la **rotación de puertos origen** como un rasgo de las herramientas de 
escaneo modernas para evitar bloqueos simples basados en el socket completo [4,
8, 15].

---

## Comparación con background

`anomaly-udpscan`


Este análisis técnico compara la estructura del ataque **anomaly-udpscan** con 
el tráfico de fondo (background) de una red ISP real, evaluando su desviación 
respecto a la normalidad estadística y estructural.

### 1. Rasgos diferenciadores claros del ataque
*   **Determinismo métrico:** El ataque presenta una entropía nula en sus 
métricas fundamentales: flujos invariablemente de **1 paquete**, **duración de 
0.000s** y un tamaño de **~433 bytes** [1-3]. El background, por el contrario, 
muestra una alta varianza en todas estas dimensiones [4, 5].
*   **Estructura secuencial:** La progresión perfectamente aritmética de los 
puertos destino (ej. 6031, 6032, 6033...) es una firma de automatización 
agresiva que no existe en el background [1, 6].
*   **Concentración absoluta del origen:** Mientras que el tráfico normal se 
distribuye entre miles de IPs, el ataque está monopolizado por una única IP 
origen (`217.156.59.213`) que genera ráfagas de decenas de miles de flujos [4, 
7, 8].

### 2. Rasgos compartidos con tráfico normal
*   **Protocolo UDP:** El uso de UDP es masivo en el background para servicios 
como DNS o streaming, por lo que el protocolo por sí solo es un indicador 
irrelevante [4, 5].
*   **Flujos de un paquete y duración cero:** Aparecen frecuentemente en el 
background debido a intentos de conexión fallidos, ruidos de red o paquetes 
espurios (ej. escaneos residuales benignos) [9, 10].
*   **Puertos comunes:** El ataque usa puertos como el 5061 o el 5066 como 
origen, que podrían solaparse con servicios legítimos de señalización VoIP [1, 
11].

### 3. Desviación de métricas (Ataque vs. Background)
*   **IPs origen:** Concentración extrema (1 IP) vs. alta dispersión (miles en 
background) [4, 7].
*   **IPs destino:** Dispersión masiva en el ataque (barrido horizontal) vs. 
concentración en servidores populares (Google, CDNs) en el background [3, 5, 
7].
*   **Puertos origen:** Fijos o rotando en bloques específicos (5061, 5062, 
5066, 5068) vs. puertos efímeros aleatorios en el background [1, 6, 7, 11, 12].
*   **Puertos destino:** Secuencialidad perfecta vs. selección basada en 
servicios (80, 443, 53) [1, 2, 4, 5].
*   **Duración/Paquetes/Bytes:** El ataque elimina la varianza. El background 
tiene una distribución de "cola larga", mientras que el ataque es un punto 
discreto en el espacio métrico [1, 4, 5].
*   **Timestamps:** Simultaneidad masiva. Cientos de flujos del ataque 
comparten el mismo segundo, rompiendo la cadencia interactiva del tráfico 
humano [1, 4].

### 4. Cambios en la diversidad
*   **Diversidad de IPs:** El ataque **reduce la diversidad en el origen** pero
la **dispara en el destino**, buscando "tocar" el máximo número de hosts 
internos [4, 7].
*   **Diversidad de protocolos:** El ataque **colapsa la diversidad** hacia UDP
[4].
*   **Diversidad de tamaños:** Desaparece por completo; el ataque es 
**isométrico** [1, 2].
*   **Diversidad temporal:** El ataque es **altamente denso**, comprimiendo 
miles de eventos en ventanas de tiempo donde el background es mucho más ralo 
[1, 4, 13].

### 5. Ruptura de la cicloestacionariedad
El ataque rompe la naturaleza estocástica de la red. Una red ISP normal sigue 
patrones de diversidad y varianza predecibles (cicloestacionariedad). El ataque
introduce una **cuña de baja entropía** que altera los promedios de la ventana:
baja la duración media de los flujos e incrementa artificialmente el volumen de
flujos de un solo paquete, "ahogando" las estadísticas de tráfico legítimo [4, 
7, 14].

### 6. Análisis de posibles confusiones
*   **DNS:** Se separa fácilmente; aunque ambos son UDP, el DNS no suele 
presentar barridos secuenciales de puertos y sus tamaños de paquete varían 
según la consulta [4, 15].
*   **HTTP/HTTPS:** No hay confusión posible; son TCP y su estructura de flujo 
(múltiples paquetes, duraciones largas) es opuesta al ataque [5, 16, 17].
*   **Escaneo benigno:** Se diferencia por la **intensidad**. Un escaneo normal
de red suele ser más lento para evitar detección; este es un barrido industrial
a alta velocidad [1, 4, 13].
*   **Otras anomalías:** Podría confundirse con un ataque DoS UDP si no se 
analizara la secuencialidad de puertos destino, que confirma que el objetivo es
**reconocimiento** y no solo saturación.

### 7. Señales fiables de separación
La señal más robusta es la **combinación de invariantes**:
`SrcIP única + Protocolo UDP + 1 pkt + 0s dur + Tamaño fijo + DstPorts 
secuenciales`. La presencia de 4 de estos 6 rasgos simultáneamente ya es una 
señal de alerta crítica [1, 3, 4, 6].

### 8. Señales débiles en aislamiento
*   **La IP origen:** Puede cambiar o ser spoofed [4, 14].
*   **El puerto origen:** Rota durante el ataque (5061 -> 5062...) [1, 6].
*   **El volumen de bytes:** Por sí solo, 433 bytes es un tamaño común en 
muchos protocolos [1].

### 9. Valor de las ventanas de evidencia
*   **Centered_sources:** Aportan la **micro-evidencia** estructural (la 
secuencia de puertos) [1, 18].
*   **Rows_2000:** Permiten ver la **densidad local** y cómo el ataque desplaza
al background en una ráfaga [13, 18].
*   **Time_60s summaries:** Son fundamentales para la **detección 
estadística**; revelan cómo el ataque altera los promedios globales de la red 
(ej. ratio de duración cero sube al 75% cuando lo normal es mucho menor) [18, 
19].

### 10. Limitaciones del análisis
*   **Sesgo de visibilidad:** Si el ataque tiene un ratio muy bajo (como en la 
ventana 05 con 0.0006), se vuelve **invisible para los resúmenes 
estadísticos**, requiriendo inspección de flujos individuales [5, 20].
*   **Sincronización:** Al trabajar con ventanas pre-cortadas, se pierde la 
visión del ciclo de vida completo del ataque (cuánto dura en total y cómo 
termina).
*   **Falsos positivos potenciales:** Un servidor VoIP interno mal configurado 
intentando retransmitir masivamente podría generar una firma similar, aunque la
secuencialidad de puertos destino sigue siendo el rasgo que inclina la balanza 
hacia un escaneo intencionado [1, 21].

Conversation: 08c46aa9-a23d-44b5-a164-9b045b2c8763 (turn 1)

---

## Síntesis para validación

`anomaly-udpscan`


Esta es la síntesis técnica final del ataque **anomaly-udpscan**, estructurada 
como especificación técnica para una posterior fase de validación y detección.

### 1. Nombre del ataque analizado
**anomaly-udpscan** [1-3].

### 2. Categoría técnica propuesta
**Reconocimiento Activo Determinista (Escaneo Híbrido UDP de Baja Entropía).**

### 3. Descripción breve del patrón
El ataque consiste en el envío masivo de sondas UDP de un solo paquete desde 
una única fuente externa hacia múltiples destinos y puertos internos [4, 5]. Se
distingue por una **isometría métrica perfecta** (mismos paquetes, mismos 
bytes, misma duración) y una **secuencialidad aritmética** en los puertos 
destino, lo que indica un proceso altamente automatizado y orquestado [4, 6-9].

### 4. Topología
*   **Patrón:** **1→Muchos** (Escaneo Horizontal) combinado con **1→Muchos 
puertos** (Escaneo Vertical) por cada host objetivo [4, 6].
*   **Concentración/Dispersión:** Concentración total en la IP origen y 
dispersión masiva en el espacio de direcciones y puertos destino [10, 11].
*   **Roles:**
    *   **IP Origen:** Sonda única externa (`217.156.59.213`) [4, 10, 11].
    *   **IPs Destino:** Hosts pasivos del ISP (principalmente rangos 
`42.219.x.x` y `212.112.x.x`) actuando como superficie de exposición [4, 12, 
13].

### 5. Métricas principales observadas
*   **Protocolo:** UDP de forma exclusiva [4, 10].
*   **Puertos Origen:** Fijos por ráfagas temporales: **5061, 5062, 5066, 
5068** [4, 7-11, 14].
*   **Puertos Destino:** Barridos secuenciales (incremento +1) en bloques: 
**5000-5090, 6000-6060, 7000-7060** [4, 7, 15, 16].
*   **Duración:** Invariablemente **0.000 segundos** [4, 6, 8].
*   **Paquetes:** Exactamente **1 paquete** por flujo [4, 10, 11].
*   **Bytes:** Uniformidad extrema entre **428 y 436 bytes** (con ~433 como 
valor central) [6, 8, 16-19].
*   **Flags:** Presencia anómala de la flag `.A....` (ACK) en el registro 
NetFlow para flujos UDP [4, 12, 13].
*   **Timestamps:** Alta densidad temporal; cientos de flujos por segundo [4, 
6, 7].

### 6. Invariantes fuertes (Robustos)
*   **Identidad del Origen:** La IP `217.156.59.213` aparece en todas las 
ventanas de ataque significativas [10, 11, 14, 20].
*   **Estructura Atómica:** El flujo siempre es `1 pkt / 0s / ~433 bytes`. Esta
terna es la huella digital más robusta porque rompe la variabilidad natural del
tráfico de red [4, 6, 8].
*   **Secuencialidad de Puertos:** Los puertos destino nunca son aleatorios; 
siguen una progresión aritmética `n+1` detectable por host objetivo [15, 
21-24].

### 7. Invariantes secundarios
*   **Puertos Origen Específicos:** El uso de puertos en el rango 5061-5068 es 
constante, pero el atacante rota entre ellos en diferentes ráfagas [10, 11, 
14].
*   **Tamaño de ventana destino:** El escaneo suele cubrir bloques de 
aproximadamente 10 a 30 puertos por cada dirección IP antes de saltar a la 
siguiente [4, 21, 25].

### 8. Señales de automatización
*   **Localización:** En la IP origen `217.156.59.213`.
*   **Estructura:** La **simultaneidad de flujos** (mismo segundo para 
diferentes IPs/puertos) y la **identidad métrica** total entre miles de flujos 
[4, 6, 7]. La falta de deriva en el tamaño de los paquetes sugiere una 
herramienta que envía un payload pre-construido de forma industrial.

### 9. Diferencias con background
*   **Varianza:** El background tiene alta varianza en bytes y duración; el 
ataque tiene varianza cero o cercana a cero [10, 26].
*   **Relación IPs/Puertos:** En el background, pocos puertos destino suelen 
recibir la mayoría del tráfico (80, 443, 53); en el ataque, la distribución de 
puertos destino es uniforme y extensa [10, 14].

### 10. Posibles confusiones
*   **SIP/VoIP Legítimo:** El uso de puertos 5061/UDP y tamaños de ~430 bytes 
podría parecer señalización SIP, pero el SIP real presenta flujos con múltiples
paquetes y duraciones mayores a cero debido al handshake [Interpretación 
técnica].
*   **Escaneos Benignos:** Otros escaneos de red, pero la intensidad (miles de 
flujos por minuto) y la secuencialidad perfecta lo clasifican como anomalía 
estructural frente al ruido de fondo [Interpretación técnica].

### 11. Evidencia suficiente (Soportada)
*   La existencia de una **IP atacante única** externa [10].
*   La **secuencialidad de puertos** destino en cada host objetivo [4, 6, 8].
*   La **estabilidad de las métricas** de flujo (1 pkt, 0s) en todas las 
ventanas [4, 10, 11].

### 12. Evidencia insuficiente (Hipótesis)
*   **Objetivo final:** Se asume reconocimiento para servicios VoIP por los 
puertos, pero no se puede confirmar sin inspección de payload (no disponible en
NetFlow).
*   **Capacidad de Spoofing:** No hay evidencia de que la IP origen sea 
falsificada, aunque es una posibilidad técnica en UDP.

### 13. Requisitos para validación posterior (Scripting)
*   **Métricas a medir:** `std_dev(bytes)`, `std_dev(duration)`, `count(unique 
DstPort) / count(flows)`.
*   **Agregaciones necesarias:** Por `SrcIP` en ventanas de tiempo de 10s y 
60s.
*   **Umbrales requeridos:**
    *   Ratio de flujos con `duration == 0` > 0.70.
    *   Ratio de flujos con `packets == 1` > 0.80.
    *   Varianza de `bytes` < 5.
*   **Análisis Temporal:** Detectar ráfagas donde `flows_per_second` desde una 
única IP supere un umbral de "comportamiento no humano" (ej. > 100 flujos/s).

### 14. Encaje en el modelo de comportamiento sintético
*   Encaja en la categoría de **Anomalías de Baja Entropía** (comportamientos 
altamente predecibles y repetitivos).
*   **Modificación:** Sugiere añadir el rasgo de **"Rotación de Socket de 
Origen"**, donde la herramienta cambia el puerto origen (5061→5062...) para 
evadir bloqueos por tupla completa.

### 15. Conclusión final
El **anomaly-udpscan** es un **escaneo UDP isométrico y determinista** 
caracterizado por una IP origen única enviando flujos atómicos (1 pkt, ~433B, 
0s) que barren puertos destino de forma secuencial, rompiendo drásticamente la 
diversidad estadística natural de la red ISP.

Conversation: 08c46aa9-a23d-44b5-a164-9b045b2c8763 (turn 1)

---


# nerisbotnet

Directorio de resultados:

```text
data\notebooklm_outputs\nerisbotnet
```

## Análisis estructural

`nerisbotnet`


El análisis de las fuentes proporcionadas sobre el ataque **nerisbotnet** 
permite extraer un perfil de comportamiento de red altamente estructurado y 
automatizado, característico de una botnet coordinada operando dentro de una 
infraestructura de ISP.

### 1. Resumen ejecutivo del patrón observado
El ataque se manifiesta como un **esfuerzo coordinado de un clúster de IPs 
internas** que ejecutan simultáneamente múltiples vectores: **envío masivo de 
correo (SMTP)**, comunicación con servidores de **IRC** y un volumen 
extremadamente alto de tráfico **UDP (DNS/propietario)** [1-4]. La 
característica definitoria es la **sincronización casi perfecta** entre decenas
de nodos origen que realizan las mismas acciones en el mismo segundo exacto [1,
5, 6].

### 2. Topología de comunicación
*   **IPs origen relevantes:** Se identifica un bloque compacto de 
aproximadamente **20 direcciones IP** (rango 42.219.152.x a 42.219.158.x) 
actuando como el clúster agresor [1, 5, 7].
*   **IPs destino relevantes:** El destino varía según el servicio; para SMTP 
hay una **gran dispersión hacia IPs externas**, mientras que para UDP e IRC se 
observa concentración en destinos específicos como 143.72.8.137 o 89.46.59.46 
[2, 4, 8, 9].
*   **Patrón de mapeo:** Es predominantemente **muchos→1** (varios bots hacia 
un C2 o servidor DNS) y **muchos→muchos** (la red de bots atacando a diversos 
servidores de correo) [1, 4, 6, 8].
*   **Concentración/Dispersión:** Existe una **altísima concentración en el 
origen** (el clúster de bots) y una dispersión controlada en el destino según 
la fase del ataque [5, 10, 11].

### 3. Actores principales
*   **IPs origen dominantes:** El grupo formado por 42.219.152.[4, 12-15], 
42.219.154.[7, 16-19], 42.219.156.[20-24] y 42.219.158.[4, 5, 12, 25, 26] [1, 
5, 7, 18, 19].
*   **IPs destino dominantes:** Destaca **143.72.8.137** como un receptor 
masivo de UDP y **212.117.174.7** o **209.85.225.27** para conexiones TCP [4, 
6, 17, 27].
*   **Papel probable:** Las IPs del rango 42.219.x.x son **nodos infectados 
(bots)**; las IPs destino fijas parecen ser **centros de mando (C2)** o 
repetidores [2, 4, 28, 29].
*   **Ubicación respecto al ISP:** El origen parece ser **interno**, dado que 
el rango de IPs es consistente con una subred específica bajo monitorización de
red local [25, 30, 31].

### 4. Protocolos y puertos
*   **Protocolo predominante:** El tráfico se reparte entre **TCP** (fases de 
C2 y spam) y **UDP** (posible sincronización o resolución masiva) [30-32].
*   **Puertos origen:** Se observan puertos efímeros en TCP (ej. 4354, 2847, 
4849) y un puerto fijo **2077** recurrente en UDP [1, 17, 18, 33, 34].
*   **Puertos destino:** Dominan el **25 (SMTP)** para spam, el **6667 (IRC)** 
para control, y el **53 (DNS)** para UDP [1, 2, 4, 8].
*   **Patrón de puertos:** Se observa **puerto destino fijo** para servicios 
específicos y un uso de puertos origen que, aunque efímeros, suelen ser 
idénticos entre todos los bots en un mismo instante [5, 6, 10].
*   **Tipo de patrón:** Es **híbrido y distribuido**; combina barrido 
horizontal hacia servidores de correo con comunicaciones verticales hacia C2 
[1, 2, 4, 27].

### 5. Métricas de flujo
*   **Duración:** Los flujos de ataque suelen tener una duración uniforme, 
frecuentemente de **9.013 o 9.014 segundos** en intentos de conexión TCP [1, 8,
35].
*   **Paquetes:** Muy estables; **6 paquetes** para intentos SMTP y **1 o 2 
paquetes** para ráfagas UDP [1, 3, 4, 8].
*   **Bytes:** Baja variabilidad; **288 bytes** por flujo SMTP es un invariante
fortísimo [1, 8, 27, 35].
*   **Flags TCP:** Predomina **`....S.` (SYN)** en los intentos de conexión 
masivos, lo que sugiere una fase de propagación o conexión fallida sistemática 
[1, 8, 27].
*   **Baja entropía:** La repetición exacta de tamaños (70, 86, 288 bytes) y 
duraciones indica un comportamiento **altamente predecible y no humano** [1, 4,
36, 37].

### 6. Comportamiento temporal
*   **Ráfagas:** El ataque opera mediante **ráfagas masivas simultáneas**; no 
es un goteo constante, sino explosiones de actividad [1, 4, 5].
*   **Timestamps dominantes:** Las fuentes muestran picos de actividad donde 
cientos de flujos comparten el mismo segundo (ej. `09:15:09`, `09:20:02`, 
`09:24:46`) [1, 14, 20].
*   **Simultaneidad:** Es el rasgo más distintivo; todos los bots inician y 
terminan sus ráfagas al unísono [5, 6, 8, 10].
*   **Periodicidad:** Se observa una recurrencia temporal (ventanas cada pocos 
minutos), sugiriendo un **ciclo de "keep-alive" o reintentos** programados [30,
38, 39].

### 7. Señales de automatización
*   **Elementos generados:** La **identidad absoluta de los parámetros de 
flujo** (duración, bytes, puertos) entre 20 nodos distintos es imposible sin 
una herramienta de orquestación [5, 6, 8].
*   **Localización:** La automatización reside en un agente (bot) instalado en 
los nodos origen que responde a un **reloj maestro** o comando centralizado [2,
7, 29].
*   **Servicio concreto:** Se localiza en el motor de **envío de spam (puerto 
25)** y en la capa de **comunicación C2 (UDP/6667)** [1, 2, 4].

### 8. Variaciones entre fuentes
*   **Fuentes centradas:** Aíslan el "corazón" del ataque, permitiendo ver el 
clúster de IPs bots sin ruido [1, 27, 33].
*   **Rows_2000:** Permiten observar cómo el ataque SMTP o UDP se intercala con
el tráfico legítimo (background) del ISP [5, 22].
*   **Time_10s:** Capturan la **simultaneidad extrema**; muestran cómo en menos
de un segundo se disparan cientos de flujos del ataque [6, 7, 10].
*   **Resúmenes time_60s:** Aportan la visión macro, confirmando que en 
periodos de un minuto el volumen de flujos `nerisbotnet` puede llegar a ser un 
ratio significativo del tráfico total (ej. 14% en la ventana 02) [36, 40].
*   **Cambio al ampliar:** Al ampliar la ventana, el patrón nerisbotnet destaca
sobre el ruido por su **comportamiento "en bloque"** frente a la naturaleza 
aleatoria del background [25, 30].

### 9. Invariantes robustos (Evidencia fuerte)
*   Uso de las **mismas 20 IPs origen** de forma repetida [5, 7, 10].
*   Flujos SMTP TCP con **duración de ~9s y tamaño de 288 bytes** [1, 8, 27, 
35].
*   Ráfagas UDP masivas con puerto origen **2077** [34, 41, 42].
*   **Simultaneidad absoluta** de timestamps entre bots [5, 6, 10].

### 10. Rasgos débiles o no constantes
*   **Direcciones IP destino:** Los bots cambian de objetivo frecuentemente, lo
que dificulta la detección basada solo en listas de IPs destino [1, 8, 27].
*   **Flags TCP:** Aunque SYN es común, aparecen flujos con `.AP.SF` o 
`.APRS.`, indicando que algunas conexiones sí se completan [43-45].
*   **Puertos origen TCP:** Son efímeros y cambian entre ráfagas, aunque se 
mantienen constantes *dentro* de una ráfaga para todos los bots [6, 10, 18].

### 11. Interpretación técnica
*   **Tipo de comportamiento:** Representa una **botnet de spam y control 
(C2)** con capacidades de sincronización masiva [2, 5, 29].
*   **Objetivo:** El envío masivo de correo no deseado y la manutención de una 
red de bots persistente mediante protocolos de chat o UDP [1, 2, 4].
*   **Más allá de la etiqueta:** No es solo un ataque de red, es una 
**infraestructura distribuida** que utiliza el ancho de banda del ISP para 
fines maliciosos, imitando servicios comunes como DNS o SMTP para evadir 
filtros simples [4, 25].

### 12. Limitaciones
*   **Sesgo de selección:** Las ventanas están pre-etiquetadas, lo que podría 
exagerar la visibilidad de ciertos patrones que en el tráfico real estarían más
diluidos [25, 28].
*   **Background vs Ataque:** Algunos flujos de background en puertos 25 u 80 
podrían parecerse al ataque si no se analiza la **simultaneidad multiclúster** 
[5, 25].
*   **Validación necesaria:** Se requiere código para confirmar si la 
**entropía de los intervalos entre ráfagas** es constante o sigue una 
distribución específica de comando y control.

### 13. Conclusión
*   **Patrón final:** El ataque `nerisbotnet` es una **orquestación síncrona 
multivector** (TCP/25, TCP/6667, UDP/53) ejecutada por un grupo estable de bots
internos hacia una red dispersa de destinos [2, 4, 5, 8].
*   **Modelo de comportamiento:** Encaja perfectamente en un **modelo de 
comportamiento sintético de "simultaneidad de ráfagas" y "uniformidad de 
métricas de flujo"** [29, 30, 37].
*   **Modificación del modelo:** Se sugiere ampliar el modelo actual para 
incluir la **correlación entre diferentes protocolos** (ej. una ráfaga UDP 
suele preceder o acompañar a una ráfaga TCP/25), lo que daría una señal de 
detección mucho más potente que el análisis de protocolos aislados [4, 6, 8].

---
**Observaciones:** Basadas en los datos de los archivos CSV y resúmenes 
estadísticos.
**Interpretaciones técnicas:** Deducciones sobre el papel de las IPs y el 
propósito de los puertos basados en estándares de red.
**Hipótesis:** Sugerencias sobre la naturaleza interna/externa y la lógica de 
control que deben ser validadas con herramientas analíticas adicionales.

---

## Comparación con background

`nerisbotnet`


La comparación técnica entre el tráfico de **nerisbotnet** y el **background** 
(tráfico legítimo de un ISP) revela una colisión entre dos naturalezas 
estadísticas opuestas: la estocasticidad diversa del comportamiento humano 
frente a la rigidez determinista de un sistema orquestado.

### 1. Rasgos diferenciadores claros
*   **Sincronización Multiclúster:** Mientras el background se distribuye 
temporalmente de forma asíncrona, el ataque presenta **timestamps idénticos** 
en múltiples nodos origen (ej. decenas de IPs iniciando flujos en el mismo 
segundo exacto), una señal de orquestación centralizada inexistente en el 
tráfico humano [1-4].
*   **Determinismo de Métricas:** El ataque produce flujos con **invariantes 
exactos** (288 bytes, 9.013 segundos de duración, 6 paquetes para SMTP), 
mientras que el background muestra una varianza masiva en bytes y duraciones 
debido a la diversidad de contenidos y sesiones [1, 5-7].
*   **Estructura de Ráfaga UDP:** El uso masivo de UDP con puerto origen fijo 
**2077** hacia múltiples destinos en ráfagas de microsegundos es un rasgo 
ausente en el background convencional [8-10].

### 2. Rasgos ambiguos (Insuficientes por sí solos)
*   **Uso de Puertos Estándar:** El tráfico en puertos **25 (SMTP), 53 
(UDP/DNS) y 80 (HTTP)** abunda en el background [11-13]. Un flujo SMTP de 288 
bytes podría ser un correo legítimo pequeño si no se considera la simultaneidad
con otros 20 nodos [6, 14].
*   **Flags TCP SYN:** El uso de flujos SYN (`....S.`) es extremadamente común 
tanto en el ataque como en el background (errores de conexión, escaneos 
benignos, servicios caídos) [11, 15, 16].
*   **IPs Internas:** El hecho de que el tráfico provenga de IPs del ISP no es 
malicioso *per se*, ya que es donde residen los clientes legítimos [11].

### 3. Métricas con mayor desviación
*   **Bytes y Paquetes:** La desviación es máxima hacia la **uniformidad**. 
Mientras el background tiene una varianza de bytes del orden de $10^{11}$ o 
$10^{12}$ [7, 17], el ataque se concentra en valores fijos como 288 o 70 bytes 
[5, 18].
*   **Duración:** Los bots presentan duraciones de **9.013s o 9.014s** de forma
repetitiva para intentos fallidos, reflejando el *timeout* específico de su 
stack de red, a diferencia de los tiempos variables de sesión del background 
[1, 19, 20].
*   **Timestamps:** El ataque rompe la distribución de llegadas típica de una 
red; cientos de flujos ocurren en el mismo segundo exacto en ventanas de 10s 
[21-23].
*   **Puertos Origen:** En UDP, el uso del puerto **2077** por parte de 
múltiples IPs internas es una desviación crítica respecto al uso de puertos 
efímeros aleatorios en el tráfico normal [8, 10, 24].

### 4. Cambios en la diversidad
*   **Diversidad de IPs:** El ataque **reduce la entropía local**; un clúster 
pequeño de IPs (rango 42.219.152.x-158.x) genera un volumen desproporcionado de
flujos comparado con la diversidad de miles de IPs origen en el background [7, 
25].
*   **Diversidad de Protocolos:** El ataque inyecta una mezcla rígida (TCP/25, 
TCP/6667, UDP/53) que altera los ratios normales de protocolo de la red en 
ventanas cortas [17, 25].
*   **Diversidad de Tamaños:** El ataque colapsa la diversidad de tamaños de 
paquetes hacia un **conjunto discreto de firmas** (ej. 70, 86, 128, 192, 288 
bytes) [5, 8, 26, 27].

### 5. Ruptura de la cicloestacionariedad y diversidad ISP
El tráfico ISP normal es diverso y sigue ciclos estacionales (día/noche). El 
ataque nerisbotnet introduce **"picos de identidad"** que rompen esta 
diversidad. Al observar las ventanas `time_60s`, se ve que el ataque puede 
representar desde un 0.01% hasta un **14.4% del tráfico total** en un minuto, 
inyectando una masa de datos idénticos que "aplana" la variabilidad natural de 
la red [7, 25].

### 6. Riesgo de confusión
*   **DNS:** Las ráfagas UDP del ataque al puerto 53 podrían confundirse con 
tráfico DNS legítimo si solo se mira el puerto destino, pero el puerto origen 
**2077** y la uniformidad de paquetes (1-2 paquetes por flujo) lo delatan [8, 
28].
*   **SSH (Puerto 22):** Se observa que nerisbotnet también intenta conexiones 
al puerto 22, lo que podría confundirse con escaneos de fuerza bruta benignos o
ruidosos, a menos que se detecte la **simultaneidad multivector** [29, 30].
*   **Automatización normal:** Servicios como actualizaciones de sistema o 
*keep-alives* de aplicaciones son automáticos, pero suelen tener una dispersión
temporal mayor y no actúan de forma coordinada entre 20 hosts distintos del ISP
[31, 32].

### 7. Señales de separación fiables
*   **Simultaneidad Maestra:** La coincidencia de parámetros (timestamp, 
duración, bytes) a través de un **clúster de IPs origen** [1, 33, 34].
*   **Correlación Cruzada de Protocolos:** Un mismo grupo de IPs realizando 
SMTP masivo y ráfagas UDP sospechosas simultáneamente [19, 35].
*   **Baja Entropía en Métricas de Flujo:** La repetición exacta de valores de 
bytes y duración en flujos TCP/25 [5, 6].

### 8. Señales débiles en aislamiento
*   **Lista de IPs destino:** Los bots cambian de objetivo constantemente, por 
lo que una IP destino no es evidencia fuerte de ataque [36-38].
*   **Protocolo IRC (6667):** Aunque es sospechoso, por sí solo podría ser uso 
legítimo de chat, pero en este contexto está ligado exclusivamente al clúster 
agresor [23, 27].

### 9. Valor de evidencia por tipo de fuente
*   **Centered_sources:** Aportan la **"huella dactilar"** pura del ataque sin 
ruido, permitiendo definir los invariantes (288 bytes, etc.) [1, 39].
*   **Time_10s:** Son las mejores para capturar la **simultaneidad**, mostrando
cómo se agrupan los flujos en fracciones de segundo [21, 29, 40].
*   **Rows_2000:** Útiles para ver la **intercalación**; cómo el ataque SMTP 
"ensucia" el flujo normal de navegación web o correo legítimo [6, 41].
*   **Time_60s summaries:** Aportan el **contexto de impacto**, permitiendo ver
si el ataque domina las estadísticas de la red o es un ruido de fondo menor 
[25, 42].

### 10. Limitaciones de la comparación
*   **Pre-etiquetado:** Las fuentes ya vienen marcadas como `nerisbotnet`, lo 
que facilita la identificación de patrones; en un entorno real, la señal de 
sincronización es la que debe descubrir el clúster, no al revés [43, 44].
*   **Fragmentación:** Algunas ventanas solo muestran intentos (SYN), lo que 
impide ver la fase completa de la conversación SMTP en todos los casos [1, 39].
*   **Escalabilidad:** Identificar la sincronización entre miles de flujos de 
background requiere un procesamiento de correlación temporal que no se aprecia 
en el análisis estático de archivos [44, 45].

Conversation: 437a199f-cbb2-4163-8993-cb17a5a63e2a (turn 1)

---

## Síntesis para validación

`nerisbotnet`


Esta síntesis técnica del ataque **nerisbotnet** se estructura como una 
especificación formal para su posterior validación programática.

### 1. Nombre del ataque analizado
**nerisbotnet** (Dataset UGR’16) [1, 2].

### 2. Categoría técnica propuesta
**Botnet multi-vector orquestada** con comportamiento determinista síncrono 
(Spam SMTP + C2/IRC + UDP Sprinting) [3-5].

### 3. Descripción breve del patrón
El ataque consiste en la actividad coordinada de un clúster de nodos infectados
(bots) que ejecutan ráfagas masivas y síncronas de flujos de red [3, 6, 7]. El 
patrón se caracteriza por una entropía nula en las métricas de flujo (paquetes 
y bytes idénticos) y una sincronización temporal absoluta entre decenas de 
direcciones IP origen [3, 8, 9].

### 4. Topología
*   **Patrones de mapeo:**
    *   **Muchos-a-Muchos:** En SMTP (Puerto 25), el clúster de bots ataca 
múltiples servidores externos simultáneamente [10-12].
    *   **Muchos-a-Uno:** En C2 (Puerto 6667) y UDP, el clúster se comunica con
destinos específicos (posibles centros de mando o repetidores) [5, 13, 14].
*   **Concentración/Dispersión:** Altísima concentración en el origen (clúster 
de IPs del ISP) y dispersión controlada en los destinos SMTP [3, 10, 15].
*   **Rol de IPs:**
    *   **Origen:** Bots internos comprometidos (rango identificado: 
42.219.152.x - 42.219.158.x) [3, 13, 15, 16].
    *   **Destino:** Objetivos de spam, servidores de chat IRC para comando y 
control, o servidores DNS utilizados como vector de comunicación [5, 6, 10, 
17].

### 5. Métricas principales observadas
*   **Protocolos:** TCP y UDP [3, 4].
*   **Puertos origen:** TCP efímeros (variables por ráfaga pero idénticos entre
bots en un instante dado); UDP frecuentemente fijado en **2077** [3, 4, 9, 18].
*   **Puertos destino:** **25** (SMTP), **6667** (IRC), **53** (DNS/UDP) y 
ocasionalmente **80** (HTTP) y **22** (SSH) [3, 5, 19-22].
*   **Duración:** 
    *   SMTP: ~**9.013s** para intentos de conexión [3, 15, 23].
    *   IRC: ~**3.004s** [5, 17, 24].
    *   UDP: Predominantemente **0.000s** (flujos de un solo paquete) [6, 7, 
25].
*   **Paquetes:** SMTP = **6**; IRC = **4**; UDP = **1, 2 o 4** [3, 5, 13, 14, 
18, 26].
*   **Bytes:** SMTP = **288**; IRC = **192**; UDP = **70, 86, 112, 114, 116, 
128, 170** [3, 5, 6, 13, 18, 27, 28].
*   **Flags:** TCP SYN (`....S.`) dominante en SMTP e IRC; UDP sin flags 
relevantes (`......`) [3, 5, 29].
*   **Timestamps:** Sincronización masiva al segundo exacto (ej. cientos de 
flujos a las `09:15:09` o `09:20:02`) [3, 6, 7, 30].

### 6. Invariantes fuertes
*   **Determinismo Métrico SMTP:** El valor de **288 bytes y 6 paquetes** en el
puerto 25 aparece de forma constante en todas las ventanas analizadas [3, 8, 
11, 15, 31].
*   **Firma UDP 2077:** El uso del puerto origen **2077** en ráfagas UDP 
masivas es un rasgo persistente y altamente anómalo [4, 18, 29, 32].
*   **Coherencia del Clúster:** La participación repetida del mismo bloque de 
aproximadamente **20 IPs origen** en diferentes vectores de ataque [4, 9, 13, 
18].
*   **Sincronía Temporal:** La capacidad de múltiples IPs de iniciar flujos en 
el mismo segundo ($T_0$) [6, 7, 33].

### 7. Invariantes secundarios
*   Intentos de conexión IRC (6667) con duraciones de ~3s y tamaños de 192 
bytes [5, 17, 24].
*   Ráfagas HTTP (80) coordinadas de 4 paquetes y 1945 bytes [21, 34, 35].
*   Uso de IPs destino recurrentes para UDP como 143.72.8.137 [6, 19, 20].

### 8. Señales de automatización
*   **Simultaneidad Maestra:** La ejecución de comandos al unísono por parte de
20 nodos sugiere un reloj maestro o un comando C2 global [6, 7, 33].
*   **Métricas "Hardcoded":** La repetición exacta de bytes (ej. 288) y 
duraciones (ej. 9.013s) indica que los flujos son generados por un software con
parámetros fijos, no por comportamiento humano variable [3, 11, 23].

### 9. Diferencias con background
*   **Entropía de Métricas:** El background muestra una varianza masiva en 
bytes y duraciones; el ataque presenta **varianza cero** en estos campos dentro
de una ráfaga [36-40].
*   **Correlación Temporal:** El tráfico ISP normal es estocástico; el ataque 
introduce picos de identidad donde miles de flujos comparten parámetros en 
ventanas de 1s [27, 33, 41].
*   **Uso de Puertos:** El puerto 2077 (UDP) no aparece de forma significativa 
en el background ISP, mientras que en el ataque es dominante [4, 18, 41, 42].

### 10. Posibles confusiones
*   **Tráfico Legítimo:** El puerto 25 es común en ISPs; un flujo SMTP de 288 
bytes aislado podría ser legítimo. La clave es la **agregación por clúster**.
*   **Consultas DNS:** Las ráfagas UDP al puerto 53 imitan DNS, pero su puerto 
origen fijo y uniformidad las distinguen [4, 6].
*   **Automatización Benigna:** Actualizaciones de software o *keep-alives* son
automáticos, pero carecen de la sincronización multiclúster agresiva observada 
aquí.

### 11. Evidencia suficiente (Observaciones)
*   Se confirma un clúster de IPs atacantes (42.219.152.x-158.x) [3, 13, 15, 
16].
*   Se confirma la simultaneidad de timestamps entre bots [6, 7, 33].
*   Se confirman las firmas métricas (288 bytes en SMTP, 192 bytes en IRC) [3, 
5].

### 12. Evidencia insuficiente (Hipótesis/Interpretaciones)
*   **Objetivo UDP:** Se interpreta como sincronización o exfiltración, pero la
naturaleza exacta de los datos UDP no es visible [Interpretación técnica].
*   **Origen Externo:** Se hipotetiza que las IPs destino SMTP son servidores 
reales siendo atacados, pero no se dispone de logs de esos servidores 
[Hipótesis].

### 13. Requisitos para validación posterior
*   **Métricas a medir:** Varianza de `bytes` y `paquetes` por grupos de 
`IP_src` y `Port_dst` en ventanas de 1s.
*   **Agregaciones:** Contar número de `IP_src` distintas compartiendo 
`Timestamp`, `Bytes` y `Duration`.
*   **Umbrales:** Definir un umbral de "clúster mínimo" (ej. >5 IPs realizando 
la misma acción en 1s).
*   **Análisis temporal:** Detectar la periodicidad de las ráfagas (intervalos 
entre explosiones de actividad).

### 14. Encaje en el modelo de comportamiento sintético
*   Encaja en la categoría de **"Ráfagas síncronas deterministas"**.
*   Amplía el modelo al demostrar **comportamiento multivectorial 
correlacionado** (un bot realiza UDP y TCP síncronos en la misma ventana 
temporal) [20, 21, 43].

### 15. Conclusión final
**Definición técnica:** El ataque `nerisbotnet` es una orquestación síncrona 
ejecutada por un clúster de bots internos que inyecta ráfagas de flujos con 
firmas métricas deterministas (SMTP: 6pq/288B; IRC: 4pq/192B; UDP-Src2077) para
maximizar el impacto de spam y control manteniendo una huella de red altamente 
predecible [3-7].

Conversation: 437a199f-cbb2-4163-8993-cb17a5a63e2a (turn 1)

---


# anomaly-spam

Directorio de resultados:

```text
data\notebooklm_outputs\anomaly-spam
```

## Análisis estructural

`anomaly-spam`


Este análisis técnico se basa en las trazas y estadísticas de red 
proporcionadas en las fuentes para el ataque **anomaly-spam** dentro del 
dataset UGR'16.

### 1. Resumen ejecutivo del patrón observado
El ataque **anomaly-spam** se manifiesta como una campaña de envío de correo 
electrónico (o intentos de envío) altamente **automatizada y de bajo volumen** 
[1, 2]. A diferencia de los ataques de denegación de servicio, este patrón no 
busca saturar el ancho de banda, sino establecer conexiones TCP completas hacia
el servicio SMTP (puerto 25) de múltiples víctimas de forma secuencial o 
ligeramente solapada [1, 3, 4]. La característica técnica más distintiva es la 
**extrema uniformidad** en las métricas de los flujos (paquetes y bytes), lo 
que indica el uso de herramientas de scripting o bots [1, 5, 6].

### 2. Topología de comunicación
*   **Número de IPs origen relevantes:** Se identifica un grupo reducido de IPs
externas, principalmente pertenecientes a la subred **253.136.x.x** (ej. 
`253.136.161.200`, `253.136.160.168`) [1, 3, 4, 7, 8].
*   **Número de IPs destino relevantes:** El ataque se dirige a múltiples IPs 
dentro de la red del ISP (red **42.219.156.x**) [1, 4-6, 9].
*   **Patrón de comunicación:** Se observa un patrón **muchos $\rightarrow$ 
muchos** de forma coordinada, donde un pequeño grupo de atacantes externos 
barre un rango de direcciones internas [1, 5, 10, 11].
*   **Concentración/Dispersión:** Existe una alta concentración en el bloque de
red de origen y una dispersión controlada (barrido horizontal) en el destino 
[6, 12-14].

### 3. Actores principales
*   **IPs origen dominantes:** `253.136.161.200` y `253.136.160.168` [1, 3, 4, 
11].
*   **IPs destino dominantes:** Varias IPs internas como `42.219.156.223`, 
`42.219.156.212`, `42.219.156.213` y `42.219.156.214` [1, 5, 6, 15].
*   **Papel probable:** Los orígenes actúan como **nodos emisores de spam** 
(probablemente bots). Los destinos son servidores de correo o terminales de 
clientes del ISP con el puerto 25 expuesto [2, 16].
*   **Ubicación:** El origen es claramente **externo** al ISP, mientras que el 
objetivo es la infraestructura interna de los clientes [17-20].

### 4. Protocolos y puertos
*   **Protocolo predominante:** **TCP** de forma exclusiva para las etiquetas 
de ataque [1, 3, 5, 14].
*   **Puertos origen relevantes:** Puertos altos dinámicos (efímeros) que 
varían en cada flujo (ej. `52210`, `58624`, `34262`, `59492`, `45400`) [1, 3, 
6, 7, 14].
*   **Puertos destino relevantes:** Casi invariablemente el puerto **25 
(SMTP)** [1, 4, 5, 14, 21].
*   **Tipo de barrido:** Es un **barrido horizontal** (un mismo servicio 
atacado en múltiples IPs de destino) [1, 4, 5]. No se observa barrido vertical 
(múltiples puertos en una sola IP).

### 5. Métricas de flujo
*   **Duración:** Flujos de corta duración, generalmente entre **1.3 y 2.2 
segundos** [1, 3, 4, 14, 21].
*   **Paquetes:** Gran uniformidad, típicamente **8, 10 o 11 paquetes** por 
flujo [1, 3-5, 7, 14].
*   **Bytes:** Volumen bajo y constante. Valores recurrentes observados: **763,
893, 3136 o 3143 bytes** [1, 3-5, 9, 21].
*   **Varianza:** La varianza en los flujos etiquetados como `anomaly-spam` es 
extremadamente baja en comparación con el `background` [22-24].
*   **Flags TCP:** Predominan flujos con el set de flags **.AP.SF** (conexión 
establecida, datos transferidos y cierre ordenado) o **.APRS.** (conexión 
reseteada), lo que sugiere que algunos intentos tienen éxito y otros son 
rechazados por el destino [1, 5, 14, 20, 21].
*   **Señales de baja entropía:** La repetición exacta de combinaciones 
"paquetes/bytes" es la firma estructural del ataque [1, 4, 5].

### 6. Comportamiento temporal
*   **Ráfagas:** El ataque no es masivo en un instante dado, sino que inyecta 
flujos de forma constante [17, 19, 25].
*   **Periodicidad:** Se observa una cadencia donde pueden aparecer varios 
flujos en el mismo segundo o con pocos segundos de diferencia (ej. ráfagas a 
las `19:42:22`, `19:42:30`, `19:42:36` y `19:42:38`) [1, 3, 7, 9].
*   **Simultaneidad:** Se observan flujos paralelos desde la misma IP de origen
hacia diferentes destinos en la misma marca temporal [4, 5, 8, 26].

### 7. Señales de automatización
*   **Elementos generados por herramienta:** El número de paquetes y el tamaño 
exacto de los bytes transferidos sugieren un **payload fijo** típico de una 
herramienta de mailing masivo [2, 4].
*   **Localización de la automatización:** Se localiza en el **origen 
externo**. La herramienta parece iterar sobre una lista de IPs objetivo 
enviando el mismo mensaje o comando SMTP [1, 10, 11, 27].

### 8. Variaciones entre fuentes
*   **Fuentes centradas:** Aíslan el patrón y permiten confirmar la firma de 10
paquetes / 893 bytes como un invariante [1, 3].
*   **rows_2000 y time_10s:** Revelan que el ataque es "quirúrgico" y se mezcla
con una gran cantidad de tráfico legítimo (HTTP, HTTPS, DNS, ICMP), lo que 
dificulta su detección sin un análisis de flujo [4-6, 12].
*   **Resúmenes time_60s:** Aportan el dato crítico del **ratio de ataque**, 
que es extremadamente bajo (0.0001 a 0.0005) [22-24, 28, 29]. Esto confirma que
el ataque es sigiloso.
*   **Ampliación de ventana:** Al ampliar la ventana temporal, el patrón no 
cambia estructuralmente, pero se hace más evidente la dispersión de las IPs 
destino dentro del rango del ISP [30-32].

### 9. Invariantes robustos (Evidencia fuerte)
1.  Puerto destino **25/TCP** [1, 4, 14].
2.  IPs de origen concentradas en subredes específicas externas (ej. 
`253.136.x.x`) [1, 3, 4].
3.  Volumen de paquetes muy bajo y constante (**8-13 paquetes**) [1, 3-5].
4.  Cierre de conexión con **PUSH/FIN** o **RESET** tras transferir una 
cantidad mínima de datos [14, 20].

### 10. Rasgos débiles o no constantes
*   El puerto de origen cambia en cada conexión (comportamiento estándar de 
sockets TCP) [1, 3].
*   El tamaño exacto en bytes varía ligeramente entre ráfagas (posiblemente 
diferentes "mensajes" de spam), aunque se mantiene uniforme dentro de cada 
ráfaga [1, 5].
*   La duración del flujo puede verse afectada por la latencia de la red o la 
respuesta del servidor víctima [17, 25, 33].

### 11. Interpretación técnica
Este ataque representa una **campaña de spam botnet** o un proceso de 
**harvesting/validación de usuarios** (vía comandos VRFY o similares en SMTP). 
El objetivo no es degradar el servicio, sino utilizar la infraestructura del 
ISP para propagar contenido o recolectar datos [2]. No debe interpretarse 
simplemente por la etiqueta "spam", sino como una anomalía estructural 
caracterizada por la **mecanización del flujo** (baja entropía métrica) [2].

### 12. Limitaciones
*   **Sesgo de selección:** Las ventanas analizadas son cortas; el ataque 
podría tener fases de mayor intensidad no capturadas [16, 34].
*   **Riesgo de confusión:** Servidores de correo legítimos muy activos podrían
presentar comportamientos similares (muchos destinos, puerto 25), aunque su 
entropía en bytes/paquetes debería ser mayor debido a la diversidad de correos 
enviados [2].
*   **Validación necesaria:** Se requeriría código para verificar si existe una
**periodicidad exacta** (inter-arrival time) entre los intentos de conexión de 
un mismo bot.

### 13. Conclusión
El patrón final de **anomaly-spam** es un barrido horizontal coordinado hacia 
el puerto 25/TCP, ejecutado por actores externos, con flujos de volumen mínimo 
y métricas casi idénticas entre sí [1, 2, 4, 5].
*   **Encaje en el modelo sintético:** Encaja perfectamente, ya que el 
comportamiento muestra una **baja entropía** y una **cadencia mecánica** [2].
*   **Modificación del modelo:** El modelo debería enfatizar no solo el puerto 
25, sino la **relación constante entre paquetes y bytes** como el principal 
indicador de anomalía frente al tráfico de correo humano o de servidores 
legítimos.

---

## Comparación con background

`anomaly-spam`


Este análisis técnico compara el comportamiento del ataque **anomaly-spam** con
el tráfico de fondo (**background**) y el tráfico normal definido 
metodológicamente, basándose en las trazas reales del dataset UGR'16.

### 1. Rasgos diferenciales frente al Background
La diferencia fundamental radica en la **entropía de las métricas de flujo**. 
Mientras que el background presenta una altísima varianza en paquetes y bytes 
debido a la diversidad de servicios (HTTP, DNS, streaming), el ataque exhibe 
una **uniformidad mecánica** [1-3]. El ataque se caracteriza por un barrido 
horizontal coordinado hacia el puerto 25/TCP, algo que en el background solo 
ocurre de forma legítima desde servidores de correo conocidos, los cuales 
suelen tener una distribución de tamaños de mensaje mucho más errática [4-6].

### 2. Rasgos compartidos con el tráfico normal
Ciertos elementos del ataque son indistinguibles del tráfico legítimo si se 
analizan de forma aislada:
*   **Protocolo y Flags:** El uso de TCP con flags `.AP.SF` (finalización 
normal) o `.APRS.` (reset) es estándar en cualquier comunicación de red [7-9].
*   **Puertos Origen:** Son puertos efímeros aleatorios, comportamiento 
idéntico al de cualquier cliente legítimo [7, 10, 11].
*   **Duración:** Los flujos duran entre 1.3 y 2.2 segundos, un rango común 
para transacciones breves de otros protocolos como HTTP o consultas DNS sobre 
TCP [7, 12, 13].

### 3. Métricas con mayor desviación
*   **IPs Origen/Destino:** El ataque muestra una **concentración extrema en el
bloque origen** (`253.136.x.x`) frente a una **dispersión intencionada en el 
destino** (múltiples IPs del ISP en el rango `42.219.156.x`) [7, 14, 15].
*   **Puertos Destino:** Desviación total hacia el **puerto 25** de forma 
exclusiva para los flujos etiquetados [4, 6, 16].
*   **Paquetes y Bytes:** Es la desviación más fiable. El ataque se "clava" en 
valores fijos como **10 paquetes / 893 bytes** o **8 paquetes / 763 bytes**, 
mientras que el background en el mismo puerto 25 muestra flujos de, por 
ejemplo, 5 paquetes / 318 bytes o 18 paquetes / 6016 bytes [8, 11, 12, 17].
*   **Timestamps:** Presentan ráfagas de simultaneidad donde la misma IP de 
origen conecta a diferentes destinos en el mismo segundo o con diferencias de 
milisegundos [5, 7, 8].

### 4. Cambios en la diversidad
El ataque reduce drásticamente la diversidad en dimensiones clave de la red:
*   **Diversidad de Protocolos/Puertos:** Cae a cero; el ataque es monolítico 
(TCP/25) [7, 10].
*   **Diversidad de Tamaños:** Desaparece; la varianza de bytes en los flujos 
de ataque es nula o mínima, indicando un **payload sintético** [6, 8, 11].
*   **Diversidad Temporal:** Se observa una cadencia repetitiva que sugiere un 
bucle de ejecución (scripting) [5, 6].

### 5. Impacto en la red ISP
A nivel macro, el ataque **no rompe la cicloestacionariedad** ni la diversidad 
del ISP debido a su bajísimo volumen (ratio de ataque de 0.0001 a 0.0005) [1, 
3]. Es un ataque "quirúrgico" que se diluye en las métricas agregadas de la 
red, lo que lo hace invisible para detectores basados puramente en volumen de 
ancho de banda [1, 18].

### 6. Riesgos de confusión
El patrón podría confundirse técnicamente con:
*   **Automatización normal:** Alertas de sistemas, monitorización de estado 
(keep-alive) o scripts de backup que usen SMTP [4, 5].
*   **Escaneo benigno:** Procesos de inventario de red que verifican si el 
puerto 25 está abierto, aunque estos suelen generar flujos más cortos (solo 
SYN/ACK) [14, 15].
*   **No se confunde con:** DNS (UDP/53), HTTP/HTTPS (80/443) o SSH (22), ya 
que el puerto destino 25 es un invariante fuerte del ataque [19-21].

### 7. Señales de separación fiables
La separación más robusta se logra mediante la **correlación de la tupla 
(Puerto 25 + Recurrencia de Tamaño + Dispersión de IP Destino)**. Un servidor 
de correo real envía correos de distintos tamaños a distintos destinos; un bot 
de spam inyecta el mismo mensaje (mismo tamaño en bytes y paquetes) a una lista
de IPs [6, 8, 11].

### 8. Señales débiles aisladas
Son insuficientes por sí solas:
*   **IP externa:** El ISP recibe millones de conexiones externas legítimas [1,
22].
*   **Flujo corto:** El background está lleno de flujos de menos de 2 segundos 
[12, 23].
*   **Uso del puerto 25:** Es un servicio legítimo necesario para el correo 
[12, 17].

### 9. Valor de las ventanas de información
*   **Centered\_sources:** Permiten definir la "firma" métrica (ej. 10 pkts / 
893 bytes) [8, 11].
*   **Rows\_2000 y Time\_10s:** Demuestran que el ataque ocurre de forma 
intercalada con tráfico masivo de otros protocolos, confirmando su naturaleza 
sigilosa [5, 7, 12].
*   **Time\_60s Summaries:** Aportan la perspectiva de la **rareza 
estadística** del evento dentro del tráfico global [1, 3].

### 10. Limitaciones de la comparación
*   **Volumen:** El ataque es tan tenue que cualquier servidor de correo 
legítimo muy activo (como uno interno del ISP) podría generar más ruido que el 
propio ataque, dificultando la distinción si no se analiza el bloque de red 
origen [1, 2].
*   **Sesgo temporal:** Solo se dispone de una ventana temporal específica; no 
se puede confirmar si el bot cambia de payload (y por tanto de tamaño de flujo)
cada ciertas horas [24, 25].
*   **Falta de Payload:** Al trabajar con Netflow (trazas de flujo), no vemos 
el contenido del spam, solo su **huella estructural**, lo que obliga a depender
de la regularidad estadística como proxy de la anomalía [26, 27].

Conversation: 5c5f1b91-0d5a-4b00-a04e-7e5fcb04353c (turn 1)

---

## Síntesis para validación

`anomaly-spam`


Esta es la síntesis técnica final del ataque **anomaly-spam** basada en el 
análisis de las trazas del dataset UGR'16, estructurada como especificación 
para una futura fase de validación programática.

### 1. Nombre del ataque analizado
**anomaly-spam**

### 2. Categoría técnica propuesta
**Campaña de spam botnet con baja entropía estructural (Barrido horizontal 
SMTP).**

### 3. Descripción breve del patrón
Ejecución coordinada y sigilosa de flujos TCP hacia el puerto 25 de múltiples 
objetivos, caracterizada por una extrema uniformidad en las métricas de volumen
(paquetes y bytes), lo que indica el envío de un payload fijo mediante 
herramientas automatizadas [1-4].

### 4. Topología
*   **Patrón:** **Muchos $\rightarrow$ Muchos** coordinado. Un grupo reducido 
de IPs externas barriendo rangos de IPs internas [1, 3, 5, 6].
*   **Concentración o dispersión:** Alta concentración en el bloque de red 
origen externo (subredes como `253.136.160.0/23`) y alta dispersión en las IPs 
destino internas (rango `42.219.156.x`) [1, 5, 7-9].
*   **Rol de IPs:** Las IPs origen actúan como **nodos emisores (bots)** que 
iteran sobre una lista de víctimas; las IPs destino actúan como **servidores o 
clientes SMTP** expuestos del ISP [1, 3, 10].

### 5. Métricas principales observadas
*   **Protocolo:** **TCP** de forma exclusiva para el ataque [1, 2, 7].
*   **Puertos origen:** Puertos efímeros aleatorios altos (ej. `52210`, 
`37325`, `59734`, `45400`) [1, 3, 11-13].
*   **Puerto destino:** **25 (SMTP)** de forma invariable [1, 3, 5, 14].
*   **Duración:** Flujos cortos, típicamente entre **1.3 y 2.2 segundos** [1, 
3, 10, 14].
*   **Paquetes:** Gran uniformidad con valores predominantes de **8, 9, 10 u 11
paquetes** por flujo [1-3, 10, 14, 15].
*   **Bytes:** Valores de volumen bajos y recurrentes: **763, 815, 841, 893 
bytes** son los más frecuentes; algunos flujos específicos alcanzan los **3136 
o 3143 bytes** [1-3, 14-16].
*   **Flags:** Predominio de flujos finalizados correctamente (**`.AP.SF`**) o 
reseteados tras el envío de datos (**`.APRS.`**) [1, 3, 7, 17, 18].
*   **Timestamps:** Aparición de **ráfagas de simultaneidad** donde una misma 
IP de origen conecta a diferentes destinos en el mismo segundo o con 
diferencias de milisegundos [3, 8, 19, 20].

### 6. Invariantes fuertes (Observaciones consistentes)
*   **Puerto destino 25/TCP:** Es el rasgo más estable en todas las fuentes 
analizadas [1-3, 5].
*   **Relación rígida Paquetes/Bytes:** La repetición exacta de la tupla (ej. 
10 pkts / 893 bytes) a través de múltiples flujos hacia distintos destinos. Es 
robusto porque delata la naturaleza mecánica del payload [2-4, 15, 21].
*   **Origen externo:** Las IPs atacantes siempre provienen de fuera del rango 
del ISP analizado [1, 5, 7, 9].

### 7. Invariantes secundarios
*   **Duración breve:** Útil para filtrar flujos largos de transferencia de 
archivos, pero no basta por sí sola al solaparse con tráfico legítimo corto [1,
10, 22].
*   **Flags TCP:** Indican actividad de envío de datos (`PUSH/ACK`), pero son 
comunes a cualquier sesión TCP SMTP normal [7, 17, 18].

### 8. Señales de automatización
*   **Localización:** Se localiza en el **nodo emisor (origen)**.
*   **Estructura:** La **mecanización métrica** (varianza casi nula en bytes en
una ráfaga hacia múltiples destinos) y la **cadencia temporal** sugieren un 
bucle de ejecución de un script o bot [3, 8, 20, 23].

### 9. Diferencias con background
*   **Entropía de volumen:** El tráfico legítimo de correo presenta una alta 
varianza en bytes debido a la diversidad de los mensajes humanos; el ataque es 
**monolítico** [1, 3, 24, 25].
*   **Proporción de tráfico:** El ataque tiene un **ratio bajísimo** (0.0001 - 
0.0005), lo que lo diferencia de ataques volumétricos masivos y lo hace 
invisible a métricas de ancho de banda [24, 26, 27].

### 10. Posibles confusiones
*   **Automatización legítima:** Scripts de monitorización (keep-alive) o 
alertas de sistemas que usen SMTP. Para distinguirlos, se debe observar el 
**número de IPs destino** (el ataque es un barrido horizontal amplio) [3, 6].
*   **Escaneos de red:** Herramientas de inventario que buscan el puerto 25 
abierto. Se distinguen porque el ataque transfiere datos reales (`PUSH`), 
mientras que el escaneo suele ser solo `SYN` o `FIN` [1, 2, 10].

### 11. Evidencia suficiente (Afirmaciones apoyadas)
*   El ataque es un barrido horizontal dirigido exclusivamente al servicio SMTP
(puerto 25) [1, 3, 5].
*   Los flujos de ataque presentan una firma de volumen (paquetes/bytes) 
extremadamente constante [1, 3, 15, 21].
*   La actividad se origina en bloques de red externos específicos [1, 5, 9].

### 12. Evidencia insuficiente (Hipótesis a validar)
*   No se puede confirmar si el payload del spam cambia cada cierto tiempo (ej.
diferentes campañas en diferentes horas) [1, 3, 7].
*   No se ha determinado si existe una **periodicidad matemática exacta** en el
tiempo de llegada entre flujos de un mismo bot [3, 8].

### 13. Requisitos para validación posterior (Especificación técnica)
*   **Métricas a medir:** Varianza de `bytes` y `paquetes` por IP origen en 
flujos dirigidos al puerto 25.
*   **Agregaciones necesarias:** Contar el número de `IPs destino` distintas 
contactadas por cada `IP origen` en ventanas de tiempo cortas (10s - 60s).
*   **Umbrales requeridos:** Definir un umbral de "Similitud Métrica" (ej. 
flujos SMTP con $> 95\%$ de coincidencia en tamaño de bytes).
*   **Análisis temporal:** Calcular el *Inter-Arrival Time* (IAT) para detectar
ráfagas de envío secuencial de baja latencia [3, 8, 20].

### 14. Encaje en el modelo de comportamiento sintético
*   **Categoría:** Encaja en **Ataques de Baja Entropía** y **Barridos 
Horizontales de Servicio**.
*   **Modificación del modelo:** El modelo debe priorizar la **correlación fija
entre bytes y paquetes** por encima de la IP de origen, ya que esta última 
podría variar (botnet), pero la firma estructural del payload tiende a 
mantenerse [3, 28].

### 15. Conclusión final
El ataque **anomaly-spam** es una campaña coordinada de botnet que ejecuta 
barridos horizontales sobre el puerto 25/TCP, caracterizada por inyectar flujos
mecánicos con firmas métricas invariantes (bajo volumen de paquetes y bytes 
idénticos) para propagar contenido de forma sigilosa dentro de la red del ISP.

Conversation: 5c5f1b91-0d5a-4b00-a04e-7e5fcb04353c (turn 1)

---


# Conclusión general

La fase multifuente con NotebookLM permitió obtener una caracterización más amplia de cada ataque. Los resultados consolidados en este documento servirán como entrada para la siguiente fase del trabajo: transformar las hipótesis estructurales en reglas medibles mediante Python.

Documento generado automáticamente el 2026-06-03 19:44:35.

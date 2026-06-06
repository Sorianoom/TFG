# Metodología de uso de LLMs

## 1. Objetivo

El objetivo de esta metodología es estudiar cómo pueden utilizarse los modelos de lenguaje grandes (LLMs) como apoyo al análisis de tráfico de red en el dataset UGR'16.

En este trabajo, los LLMs no se utilizan como clasificadores automáticos ni como sustitutos directos de un sistema IDS. Su función principal es servir como herramienta de apoyo para:

- interpretar ventanas de tráfico NetFlow
- comparar tráfico normal y anómalo
- identificar patrones de comportamiento
- generar hipótesis técnicas
- explicar diferencias entre tipos de ataque
- ayudar a formalizar reglas de detección basadas en comportamiento

El enfoque seguido combina análisis asistido por LLM con validación programática mediante scripts Python.

---

## 2. Papel del LLM en el trabajo

El LLM se utiliza como una herramienta de análisis e interpretación.

Su papel dentro del proyecto se puede dividir en cuatro funciones principales:

### 2.1 Análisis descriptivo

El LLM ayuda a describir el comportamiento de una ventana de tráfico, identificando elementos como:

- IPs origen y destino relevantes
- puertos predominantes
- protocolos utilizados
- duración de los flujos
- volumen de paquetes y bytes
- concentración o dispersión del tráfico
- posibles patrones repetitivos

### 2.2 Comparación entre tráfico normal y anómalo

El LLM compara perfiles normales de calibración con ventanas de ataque para detectar desviaciones respecto al comportamiento esperado.

Esto permite identificar diferencias en:

- diversidad de IPs
- diversidad de puertos
- duración de los flujos
- distribución de bytes
- frecuencia temporal
- estructura de comunicación

### 2.3 Generación de hipótesis

A partir de las observaciones realizadas, el LLM propone hipótesis técnicas sobre el comportamiento del ataque.

Por ejemplo:

- un ataque DoS puede caracterizarse por concentración hacia un único destino
- un UDP Scan puede caracterizarse por barrido secuencial de puertos destino
- una botnet puede caracterizarse por múltiples nodos sincronizados hacia un servidor C2

Estas hipótesis no se aceptan directamente como conclusiones finales, sino que se validan posteriormente mediante código.

### 2.4 Apoyo a la formalización

El LLM ayuda a transformar observaciones empíricas en un modelo técnico estructurado.

En este trabajo, esta fase permitió construir un modelo de comportamiento sintético basado en:

- densidad temporal
- baja entropía
- secuencialidad de puertos
- concentración o dispersión de IPs
- sincronización distribuida
- localización de la automatización

---

## 3. Fuentes proporcionadas al LLM

Para realizar el análisis, se proporcionaron al LLM distintas fuentes de información.

### 3.1 Perfiles normales de calibración

Se extrajeron perfiles normales a partir del conjunto de calibración del dataset UGR'16.

Estos perfiles representan tráfico legítimo de fondo y permiten establecer una línea base de comportamiento normal.

Los perfiles utilizados fueron:

- perfil laboral
- perfil nocturno
- perfil de transición

Estos archivos permiten al LLM identificar características normales del tráfico del ISP, como la presencia habitual de servicios DNS, HTTP, HTTPS o correo electrónico, así como diferencias entre horarios.

### 3.2 Ventanas de ataque

Se extrajeron ventanas temporales del conjunto de test alrededor de eventos de ataque.

Las ventanas incluyen tráfico anterior, tráfico del ataque y tráfico posterior, con el objetivo de analizar el ataque dentro de su contexto.

Los ataques analizados fueron:

- DoS
- UDP Scan
- NerisBotnet

Esta estrategia evita analizar flujos aislados y permite estudiar patrones estructurales dentro de una ventana temporal.

### 3.3 Resultados intermedios

También se proporcionaron al LLM documentos generados durante el análisis, como:

- análisis de tráfico normal
- análisis de DoS
- análisis de UDP Scan
- análisis de NerisBotnet
- modelo de comportamiento sintético
- resultados del detector heurístico

Estos documentos permiten que el LLM trabaje con contexto acumulado y ayude a consolidar conclusiones.

---

## 4. Flujo metodológico

La metodología seguida se divide en varias fases.

---

### 4.1 Extracción de ventanas temporales

En primer lugar, se identifican eventos de ataque dentro del dataset.

A partir de cada evento, se extraen ventanas temporales que incluyen tráfico anterior y posterior. Esto permite observar el comportamiento del ataque dentro de su contexto.

La unidad de análisis no es una traza aislada, sino una ventana de flujos NetFlow.

Este enfoque permite estudiar:

- aparición del ataque
- tráfico de fondo que lo rodea
- mezcla entre tráfico normal y malicioso
- continuidad temporal
- repetición de patrones
- consistencia de etiquetas

---

### 4.2 Análisis asistido por LLM

Una vez extraídas las ventanas, se proporcionan al LLM junto con prompts específicos.

Los prompts están diseñados para evitar respuestas genéricas y orientar al modelo hacia el análisis técnico.

Se solicita al LLM que identifique:

- patrones comunes entre ventanas
- diferencias con tráfico normal
- métricas alteradas
- posibles reglas de detección
- explicación técnica del ataque
- limitaciones del análisis

El LLM actúa como una herramienta de razonamiento y explicación.

---

### 4.3 Formalización de patrones

Las respuestas del LLM se revisan críticamente y se transforman en hipótesis técnicas.

Ejemplos de hipótesis formalizadas:

- El DoS se manifiesta como una concentración de múltiples flujos de baja duración hacia un único destino.
- El UDP Scan se manifiesta como una dispersión hacia múltiples destinos con barrido secuencial de puertos.
- NerisBotnet se manifiesta como una coordinación distribuida entre múltiples nodos hacia un canal C2.

Estas hipótesis permiten construir un modelo de comportamiento sintético.

---

### 4.4 Validación programática

Las hipótesis generadas por el LLM se validan mediante scripts Python.

El detector heurístico implementado analiza las ventanas temporales y calcula métricas como:

- número de flujos
- IPs origen únicas
- IPs destino únicas
- puertos origen y destino únicos
- duración media
- bytes medios
- varianza de bytes
- secuencialidad de puertos
- sincronización temporal
- concentración o dispersión

La validación permite comprobar si las hipótesis del LLM son medibles en los datos.

---

### 4.5 Documentación de resultados

Finalmente, los resultados se documentan en archivos Markdown para conservar la trazabilidad del proceso.

Se documentan:

- prompts utilizados
- respuestas relevantes del LLM
- hipótesis generadas
- evidencias observadas
- resultados del detector
- limitaciones
- conclusiones

Esta documentación sirve como base para la redacción de la memoria final del TFG.

---

## 5. Tipos de uso del LLM

Durante el proyecto se han utilizado los LLMs de distintas formas.

### 5.1 Uso exploratorio

Se utiliza el LLM para comprender patrones desconocidos o poco claros dentro de una ventana.

Ejemplo:

```text
Analiza estas tres ventanas DoS e identifica patrones comunes.
```

### 5.2 Uso comparativo

Se utiliza el LLM para comparar tráfico normal y tráfico de ataque.

Ejemplo:

```text
Compara los perfiles normales con las ventanas UDP Scan.
```

### 5.3 Uso explicativo

Se utiliza el LLM para redactar explicaciones técnicas de un patrón observado.

Ejemplo:

```text
Explica por qué este comportamiento puede considerarse un ataque DoS.
```

### 5.4 Uso de formalización

Se utiliza el LLM para transformar observaciones en un modelo estructurado.

Ejemplo:

```text
Formaliza un modelo de detección basado en comportamiento para DoS y UDP Scan.
```

### 5.5 Uso crítico

Se utiliza el LLM para revisar sus propias respuestas y detectar posibles sobreinterpretaciones.

Ejemplo:

```text
Revisa críticamente esta conclusión e indica qué partes requieren validación con código.
```

---

## 6. Ventajas observadas

El uso de LLMs aporta varias ventajas al análisis:

- facilita la interpretación de ventanas de tráfico
- permite generar hipótesis rápidamente
- ayuda a comparar comportamientos complejos
- transforma datos técnicos en explicaciones comprensibles
- facilita la documentación del razonamiento
- ayuda a estructurar modelos de comportamiento
- permite explorar distintas interpretaciones de un mismo patrón

En particular, el LLM resultó útil para diferenciar conceptualmente entre:

- DoS como automatización en el origen
- UDP Scan como automatización en el espacio de destino
- NerisBotnet como automatización distribuida en red

---

## 7. Limitaciones observadas

El uso de LLMs también presenta limitaciones importantes:

- no puede procesar directamente datasets completos de gran tamaño
- depende de la calidad de las ventanas proporcionadas
- puede sobreinterpretar patrones si no se valida
- puede asumir causalidad donde solo existe correlación
- puede generar explicaciones plausibles pero no demostradas
- requiere prompts específicos y bien formulados
- no sustituye a la validación programática

Por este motivo, todas las conclusiones relevantes deben contrastarse con evidencia empírica.

---

## 8. Relación entre LLM y código

El LLM y el código cumplen funciones diferentes dentro del proyecto.

| Elemento | Función |
|---|---|
| LLM | Interpretar, comparar, explicar y generar hipótesis |
| Python | Medir, validar y comprobar hipótesis sobre datos |
| Documentación | Registrar metodología, resultados y conclusiones |

El LLM no se considera un detector final. El detector heurístico implementado se utiliza como mecanismo de validación de las hipótesis generadas.

---

## 9. Ejemplo de flujo completo

Un ejemplo de flujo seguido durante el trabajo es el siguiente:

1. Se extraen tres ventanas DoS.
2. Se proporcionan al LLM junto con perfiles normales.
3. El LLM identifica concentración hacia un destino, duración cero y puertos origen secuenciales.
4. Se formaliza la hipótesis de que el DoS presenta automatización en el origen.
5. Se implementa una regla en Python para medir secuencialidad, duración y concentración.
6. El detector valida las tres ventanas DoS.
7. La hipótesis queda documentada como validada.

Este mismo flujo se aplicó a UDP Scan y parcialmente a NerisBotnet.

---

## 10. Conclusión metodológica

La metodología seguida demuestra que los LLMs pueden ser útiles como herramientas de apoyo al análisis de tráfico de red, especialmente en tareas de interpretación y explicación.

Sin embargo, su utilidad depende de una validación posterior. El LLM permite generar hipótesis y formalizar patrones, pero el código es necesario para comprobar si dichos patrones existen realmente en los datos.

El enfoque adoptado en este trabajo combina las capacidades explicativas de los LLMs con la verificación empírica mediante scripts programáticos, manteniendo un equilibrio entre interpretabilidad y rigor técnico.
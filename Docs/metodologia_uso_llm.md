# Metodología de uso de LLMs

## 1. Objetivo

El objetivo de esta metodología es estudiar el uso de modelos de lenguaje grandes (LLMs) como apoyo al análisis explicativo de tráfico de red en el dataset UGR'16.

En este trabajo, los LLMs no se utilizan como clasificadores automáticos ni como sustitutos de un sistema IDS tradicional. Su función principal es actuar como herramienta de análisis, comparación, interpretación y generación de hipótesis sobre ventanas temporales de tráfico NetFlow.

El enfoque seguido consiste en proporcionar al LLM muestras representativas del tráfico normal y anómalo, solicitar explicaciones técnicas sobre los patrones observados y posteriormente validar dichas hipótesis mediante análisis programático.

---

## 2. Papel del LLM dentro del trabajo

El LLM se utiliza como una herramienta de apoyo en las siguientes tareas:

1. Analizar perfiles de tráfico normal.
2. Comparar tráfico normal con ventanas de ataque.
3. Identificar patrones estructurales en ataques concretos.
4. Proponer reglas de detección basadas en comportamiento.
5. Generar explicaciones técnicas interpretables.
6. Ayudar a formalizar un modelo de comportamiento sintético.

El LLM no toma decisiones finales sin validación. Las conclusiones generadas se contrastan posteriormente mediante scripts de análisis sobre las ventanas temporales extraídas.

---

## 3. Fuentes proporcionadas al LLM

Para realizar el análisis se proporcionan distintas fuentes al LLM:

### 3.1 Perfiles normales de calibración

Extraídos del conjunto de calibración de UGR'16, correspondiente a tráfico legítimo de fondo.

Se utilizaron perfiles representativos de:

- tráfico laboral
- tráfico nocturno
- tráfico de transición

Estos perfiles permiten al LLM disponer de una referencia de comportamiento normal del ISP.

### 3.2 Ventanas de ataque

Se proporcionaron ventanas temporales extraídas del conjunto de test, incluyendo tráfico anterior y posterior al evento de ataque.

Los ataques estudiados fueron:

- DoS
- UDP Scan
- NerisBotnet

Estas ventanas permiten analizar el comportamiento del ataque dentro de su contexto temporal.

### 3.3 Documentos técnicos intermedios

Durante el análisis se generaron documentos técnicos para consolidar los hallazgos:

- modelo de comportamiento sintético
- validación del detector heurístico
- análisis comparativos entre tipos de ataque

Estos documentos se utilizan como fuentes de contexto para que el LLM pueda trabajar de forma acumulativa.

---

## 4. Flujo metodológico

El proceso seguido se divide en varias fases.

### Fase 1: Extracción de muestras

A partir del dataset original se extraen ventanas temporales representativas. En lugar de analizar trazas aisladas, se trabaja con bloques de tráfico que incluyen contexto antes, durante y después del evento.

Esto permite observar:

- cambios temporales
- transición entre tráfico normal y ataque
- mezcla entre background y tráfico malicioso
- persistencia o repetición de patrones

### Fase 2: Análisis con LLM

Las muestras se proporcionan al LLM junto con prompts específicos. El objetivo es obtener una interpretación técnica del comportamiento observado.

El LLM analiza:

- IPs origen y destino
- puertos origen y destino
- protocolo
- duración
- paquetes
- bytes
- dispersión
- concentración
- secuencialidad
- sincronización temporal

### Fase 3: Formalización de hipótesis

A partir de las respuestas del LLM se extraen hipótesis técnicas.

Ejemplos:

- un ataque DoS se caracteriza por concentración hacia un único destino
- un UDP Scan se caracteriza por barrido secuencial de puertos destino
- una botnet se caracteriza por coordinación distribuida entre nodos

### Fase 4: Validación programática

Las hipótesis generadas por el LLM se validan mediante scripts Python sobre las ventanas temporales extraídas.

El objetivo de esta fase es comprobar si los patrones descritos por el LLM son medibles en los datos reales.

### Fase 5: Documentación del modelo

Finalmente, las hipótesis validadas se integran en un modelo de comportamiento sintético basado en invariantes estructurales.

---

## 5. Ventajas del uso de LLMs

El uso de LLMs aporta varias ventajas en este contexto:

- facilita la interpretación de grandes volúmenes de información
- ayuda a encontrar relaciones entre métricas de red
- permite comparar tráfico normal y anómalo de forma estructurada
- genera explicaciones técnicas legibles
- ayuda a transformar observaciones empíricas en reglas de comportamiento
- permite documentar el razonamiento de forma clara

---

## 6. Limitaciones del uso de LLMs

El uso de LLMs también presenta limitaciones importantes:

- no pueden procesar directamente datasets completos de decenas de GB
- dependen de la calidad y representatividad de las muestras proporcionadas
- pueden sobreinterpretar patrones si no se validan
- no sustituyen al análisis programático
- requieren prompts precisos
- no deben considerarse detectores automáticos por sí mismos

Por este motivo, el LLM se utiliza como herramienta de apoyo, no como sistema de detección final.

---

## 7. Papel de la validación

Toda hipótesis generada por el LLM debe contrastarse con los datos.

En este trabajo se implementó un detector heurístico para comprobar si los patrones identificados por el LLM podían medirse automáticamente sobre ventanas NetFlow.

La validación permitió confirmar patrones como:

- secuencialidad de puertos origen en DoS
- secuencialidad de puertos destino en UDP Scan
- coordinación distribuida hacia C2 en NerisBotnet

---

## 8. Conclusión metodológica

La metodología seguida combina análisis asistido por LLM y validación programática.

El LLM permite generar hipótesis, explicar patrones y formalizar modelos. El código permite verificar dichas hipótesis sobre datos reales.

Este enfoque permite aprovechar las capacidades explicativas de los LLMs sin renunciar al rigor técnico necesario en el análisis de tráfico de red.
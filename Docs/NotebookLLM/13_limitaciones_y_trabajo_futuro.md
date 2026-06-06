# Limitaciones y trabajo futuro

## 1. Objetivo

Este documento recoge las principales limitaciones identificadas durante el desarrollo del trabajo y plantea posibles líneas de mejora o ampliación.

El objetivo no es presentar el sistema desarrollado como una solución final de detección de intrusiones, sino delimitar claramente su alcance y dejar establecidas futuras líneas de evolución.

---

## 2. Alcance actual del trabajo

El trabajo desarrollado hasta el momento se centra en:

- análisis de tráfico NetFlow del dataset UGR'16
- uso de LLMs como herramienta de apoyo al análisis
- extracción de ventanas temporales de ataques
- comparación con perfiles normales de calibración
- generación de hipótesis mediante LLM
- validación de hipótesis mediante scripts Python
- formalización de un modelo de comportamiento sintético

Los ataques analizados son:

- DoS
- UDP Scan
- NerisBotnet

El sistema actual no pretende sustituir a un IDS real, sino demostrar una metodología de análisis basada en LLMs y validación empírica.

---

## 3. Limitaciones relacionadas con los datos

### 3.1 Uso de ventanas previamente extraídas

El análisis se ha realizado sobre ventanas temporales seleccionadas previamente.

Esto permite estudiar los patrones con detalle, pero limita la generalización directa al dataset completo.

Actualmente, el detector no recorre automáticamente todo el fichero original buscando anomalías.

---

### 3.2 Representatividad de las ventanas

Las ventanas analizadas son representativas de ciertos patrones, pero no cubren necesariamente toda la variabilidad posible de cada ataque.

Por ejemplo:

- DoS y UDP Scan presentan patrones muy claros.
- NerisBotnet requiere más contexto y puede aparecer de forma más dispersa.
- Algunas ventanas contienen pocos flujos etiquetados como ataque.

Por tanto, los resultados deben interpretarse como una validación inicial sobre muestras seleccionadas.

---

### 3.3 Mezcla de background y ataque

Las ventanas extraídas contienen tráfico de fondo mezclado con tráfico malicioso.

Esto refleja un escenario realista, pero complica el análisis porque la etiqueta dominante de una ventana puede ser `background`, aunque dentro existan subestructuras maliciosas.

Por este motivo, el análisis se realiza buscando patrones internos dentro de la ventana, no únicamente la etiqueta mayoritaria.

---

### 3.4 Etiqueta blacklist

El dataset contiene flujos etiquetados como `blacklist`.

En este trabajo no se utiliza `blacklist` como criterio de detección, ya que el objetivo es analizar comportamiento y no depender de listas negras.

Sin embargo, esta etiqueta puede aparecer mezclada en algunas ventanas y debe interpretarse con cautela.

---

## 4. Limitaciones relacionadas con los LLMs

### 4.1 Capacidad limitada para procesar grandes ficheros

Los LLMs no pueden procesar directamente ficheros masivos completos como los del dataset UGR'16.

Por ello es necesario trabajar con:

- ventanas temporales
- muestras representativas
- resúmenes
- documentos intermedios
- resultados agregados

Esto obliga a diseñar cuidadosamente qué información se proporciona al modelo.

---

### 4.2 Dependencia del prompt

La calidad de las respuestas depende en gran medida de cómo se formula el prompt.

Prompts demasiado genéricos pueden producir respuestas vagas, incompletas o con sobreinterpretaciones.

Los prompts más útiles fueron aquellos que:

- indicaban claramente el tipo de tráfico
- pedían patrones estructurales
- evitaban descripciones línea por línea
- solicitaban comparación con tráfico normal
- pedían reglas verificables
- exigían diferenciar observación e interpretación

---

### 4.3 Riesgo de sobreinterpretación

Un LLM puede generar explicaciones técnicamente plausibles aunque no estén completamente respaldadas por los datos proporcionados.

Por este motivo, las respuestas del LLM deben considerarse hipótesis, no conclusiones finales.

Toda afirmación relevante debe validarse posteriormente mediante código o evidencia empírica.

---

### 4.4 Ausencia de ejecución directa sobre los datos

El LLM puede analizar muestras y resultados, pero no sustituye al procesamiento programático.

No calcula de forma fiable sobre todo el dataset si no se le proporcionan resultados agregados.

Por tanto, el papel del LLM es interpretativo y explicativo, mientras que la validación debe recaer en scripts.

---

## 5. Limitaciones del detector heurístico

### 5.1 No es un IDS completo

El detector desarrollado no pretende ser un sistema de detección de intrusiones completo.

Es una herramienta auxiliar para validar si las hipótesis generadas por el LLM son medibles en los datos.

---

### 5.2 Umbrales empíricos

Los umbrales utilizados en el detector se han ajustado a partir de observaciones sobre las ventanas analizadas.

Ejemplos:

- tamaño mínimo de grupo
- ratio de duración cercana a cero
- ratio de pocos paquetes
- varianza máxima de bytes
- número mínimo de IPs origen o destino
- criterio de secuencialidad de puertos

Estos umbrales podrían necesitar ajuste al aplicarse sobre otros periodos o redes.

---

### 5.3 Detección parcial de botnets

La detección de NerisBotnet es más compleja que la de DoS o UDP Scan.

El detector solo clasifica correctamente la ventana donde existe una evidencia clara de coordinación distribuida hacia un servidor C2.

Las ventanas con pocos flujos etiquetados como `nerisbotnet` no se clasifican para evitar falsos positivos.

Esto muestra que las botnets requieren análisis temporal y contextual más amplio.

---

### 5.4 No se analiza aún periodicidad a largo plazo

El modelo actual trabaja sobre ventanas concretas.

Todavía no se analiza de forma completa:

- beaconing periódico
- repeticiones cada cierto intervalo
- relaciones entre tráfico anterior y posterior
- conexiones recurrentes a un mismo destino
- evolución de una IP a lo largo de minutos u horas

Este análisis sería especialmente útil para botnets.

---

## 6. Limitaciones metodológicas

### 6.1 Validación sobre pocas familias de ataque

El trabajo analiza tres tipos principales de comportamiento:

- DoS
- UDP Scan
- NerisBotnet

Aunque representan familias distintas, no cubren todos los ataques del dataset.

Quedan pendientes otros tipos como:

- scan11
- scan44
- anomaly-spam
- anomaly-sshscan

---

### 6.2 No se realiza Machine Learning

Este trabajo no entrena un modelo de Machine Learning propio.

El enfoque se centra en el uso de LLMs como herramientas de análisis y explicación, apoyadas por validación programática.

Esto es una decisión de alcance del proyecto.

---

### 6.3 No se evalúa rendimiento en tiempo real

El detector no está diseñado ni evaluado para ejecución en tiempo real.

El análisis se realiza offline sobre ventanas extraídas.

---

## 7. Trabajo futuro

### 7.1 Aplicar el detector al fichero completo

Una línea futura natural es aplicar el detector heurístico sobre el fichero completo del dataset.

Esto permitiría pasar de:

```text
ventanas seleccionadas manualmente
```

a:

```text
detección automática sobre tráfico completo
```

Para ello sería necesario implementar un sistema de ventanas deslizantes por tiempo o por número de flujos.

---

### 7.2 Extraer ventanas temporales por tiempo real

Actualmente se han utilizado ventanas basadas en número de filas.

En el futuro podría trabajarse con ventanas temporales reales:

- 1 segundo
- 10 segundos
- 1 minuto
- 5 minutos

Esto permitiría estudiar mejor patrones de periodicidad y relaciones entre eventos.

---

### 7.3 Analizar más tipos de ataques

Sería útil ampliar el análisis a otros ataques presentes en UGR'16:

- scan11
- scan44
- anomaly-spam
- anomaly-sshscan

Esto permitiría comprobar si el modelo de comportamiento sintético puede extenderse a más familias.

---

### 7.4 Mejorar el análisis de botnets

Para NerisBotnet sería conveniente estudiar:

- periodicidad de conexiones C2
- beaconing
- repetición de contactos hacia el mismo destino
- correlación entre múltiples nodos
- evolución temporal en ventanas más amplias
- relación entre probing y coordinación

Esto permitiría construir una detección más robusta de comportamientos distribuidos.

---

### 7.5 Crear un pipeline automático de análisis con LLM

Otra línea futura sería automatizar parte del flujo de trabajo:

1. Extraer ventana sospechosa.
2. Calcular métricas agregadas.
3. Generar resumen estructurado.
4. Proporcionar el resumen al LLM.
5. Obtener explicación técnica.
6. Validar hipótesis con código.

Esto permitiría integrar LLMs como capa explicativa dentro de un sistema de análisis.

---

### 7.6 Comparar distintos LLMs

También sería interesante comparar respuestas entre distintos modelos:

- NotebookLM
- Gemini
- ChatGPT
- otros modelos especializados

Se podría evaluar:

- calidad de las hipótesis
- precisión técnica
- riesgo de sobreinterpretación
- utilidad para generar documentación
- capacidad de comparación entre ataques

---

## 8. Conclusión

El trabajo actual demuestra que los LLMs pueden ser útiles como herramientas de análisis, interpretación y generación de hipótesis en ciberseguridad.

Sin embargo, su uso debe estar acompañado de validación programática.

El enfoque más sólido no consiste en delegar la detección en el LLM, sino en utilizarlo para explicar patrones y formular hipótesis, que posteriormente se contrastan con datos reales.

Las principales líneas futuras pasan por escalar el análisis al dataset completo, trabajar con ventanas temporales más amplias, estudiar más ataques y mejorar la detección de comportamientos distribuidos como botnets.
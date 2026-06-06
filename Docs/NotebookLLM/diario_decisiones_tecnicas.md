# Diario de decisiones técnicas

## 1. Objetivo

Este documento recoge las principales decisiones técnicas tomadas durante el desarrollo del TFG.

Su finalidad es mantener trazabilidad sobre cómo ha evolucionado el proyecto, por qué se han elegido determinadas estrategias y qué criterios se han descartado.

Este diario no sustituye a la memoria final, pero sirve como apoyo para justificar decisiones metodológicas, especialmente en un trabajo donde se combinan análisis asistido por LLMs, extracción de ventanas reales y validación programática.

---

## 2. Decisión inicial: no trabajar únicamente con etiquetas

### Decisión

No basar el análisis únicamente en la etiqueta de cada flujo.

### Motivo

En el dataset UGR'16, una ventana temporal puede contener tráfico de fondo mezclado con tráfico malicioso. Si se analiza solo la etiqueta dominante de una ventana, se pueden perder patrones relevantes.

Por ejemplo, algunas ventanas DoS tienen como etiqueta dominante `background`, pero contienen subgrupos claros de ataque.

Además, etiquetas como `blacklist` pueden aparecer mezcladas con ataques o tráfico de fondo, por lo que no deben utilizarse como criterio principal de detección.

### Consecuencia

El análisis se centra en patrones estructurales dentro de la ventana:

* concentración de flujos
* secuencialidad de puertos
* baja varianza
* sincronización temporal
* dispersión de destinos
* coordinación distribuida
* relación entre IPs origen, IPs destino y puertos
* duración y número de paquetes por flujo

---

## 3. Decisión: analizar ventanas temporales y no filas aisladas

### Decisión

Extraer ventanas alrededor de eventos de ataque, en lugar de analizar únicamente filas individuales.

### Motivo

Una única fila NetFlow no permite comprender el comportamiento de un ataque. El valor real aparece al observar el contexto:

* qué ocurre antes del ataque
* qué ocurre durante el ataque
* qué ocurre después
* si hay mezcla con background
* si hay repetición temporal
* si existen flujos relacionados
* si el patrón es puntual o persistente

### Consecuencia

El análisis se realiza sobre ventanas de tráfico, no sobre registros aislados.

Inicialmente se extrajeron ventanas para:

* DoS
* UDP Scan
* NerisBotnet

Posteriormente, el enfoque se amplió a:

* scan11
* scan44
* anomaly-sshscan
* anomaly-spam

---

## 4. Decisión: utilizar perfiles normales de calibración

### Decisión

Extraer perfiles normales del conjunto de calibración.

### Motivo

Para interpretar correctamente un ataque es necesario tener una línea base de normalidad.

El tráfico normal de una red ISP no es constante, sino cicloestacionario. Esto significa que cambia según:

* horario laboral
* horario nocturno
* transición entre franjas horarias
* actividad humana
* servicios automáticos
* carga de la red

### Consecuencia

Se extrajeron perfiles normales representativos:

```text
normal_laboral.csv
normal_nocturno.csv
normal_transicion.csv
```

Estos perfiles se utilizan como referencia para comparar los ataques y evitar interpretar como malicioso cualquier comportamiento de baja duración, ráfaga puntual o uso de puertos comunes.

---

## 5. Decisión: usar LLMs como apoyo, no como detector final

### Decisión

Utilizar LLMs como herramienta de análisis, explicación y generación de hipótesis, pero no como clasificador final.

### Motivo

Los LLMs pueden interpretar patrones, comparar comportamientos y redactar explicaciones útiles. Sin embargo, también pueden:

* sobreinterpretar datos
* generar conclusiones plausibles pero no demostradas
* confundir ruido de fondo con patrón relevante
* generalizar a partir de pocas muestras
* expresar con seguridad hipótesis que deben validarse

### Consecuencia

Toda hipótesis generada por el LLM debe validarse posteriormente mediante código o análisis estructural.

El flujo metodológico adoptado es:

```text
Ventanas de tráfico → Prompt → Respuesta LLM → Hipótesis técnica → Validación programática
```

El LLM no decide la clasificación final. Su papel es ayudar a formular explicaciones e hipótesis interpretables.

---

## 6. Decisión: documentar prompts

### Decisión

Crear un banco de prompts utilizados durante el análisis.

### Motivo

El uso de LLMs debe ser reproducible y trazable. No basta con decir que se ha utilizado un LLM; es necesario documentar:

* qué se preguntó
* en qué fase del trabajo
* con qué objetivo
* qué tipo de respuesta se esperaba
* cómo se utilizó la respuesta obtenida

### Consecuencia

Se creó el archivo:

```text
docs/05_prompts_llm.md
```

Este documento permite justificar el uso de NotebookLM y otros LLMs como parte de la metodología.

---

## 7. Decisión: no usar blacklist como criterio de detección

### Decisión

No utilizar la etiqueta `blacklist` como base del modelo.

### Motivo

El objetivo del trabajo es analizar comportamiento de red, no depender de listas negras.

Una lista negra puede aportar contexto, pero no explica por sí misma el patrón técnico del ataque.

Además, la etiqueta `blacklist` aparece mezclada con diferentes ventanas y no representa necesariamente el comportamiento estructural que se quiere modelar.

### Consecuencia

El detector heurístico ignora `blacklist` como criterio principal de clasificación.

El modelo se basa en métricas estructurales:

* concentración
* dispersión
* secuencialidad
* baja varianza
* sincronización temporal
* topología de comunicación
* duración
* paquetes
* bytes

---

## 8. Decisión: construir un detector heurístico

### Decisión

Implementar un detector heurístico en Python.

### Motivo

Era necesario comprobar si las hipótesis generadas por el LLM eran medibles en las trazas reales.

El detector no se plantea como IDS final ni como modelo de Machine Learning, sino como herramienta de validación programática.

### Consecuencia

Se implementó:

```text
scripts/02_attack_analysis/detect_synthetic_behavior.py
```

y se generó:

```text
data/attack_analysis/behavior_detection_results.csv
```

Este detector permitió validar inicialmente los patrones de:

* DoS
* UDP Scan
* NerisBotnet, con matices
* tráfico normal, sin falsos positivos en las ventanas utilizadas

---

## 9. Decisión: clasificar por comportamiento, no por IP concreta

### Decisión

No construir reglas basadas únicamente en IPs o puertos específicos.

### Motivo

Aunque algunas IPs aparecen claramente en las ventanas, un modelo basado solo en valores concretos sería frágil.

Por ejemplo, aparecen IPs como:

```text
42.219.150.246
42.219.158.16
217.156.59.213
220.194.21.2
42.219.156.231
```

Estas IPs son evidencias útiles dentro de las ventanas analizadas, pero no deben ser el núcleo general del modelo.

### Consecuencia

Las reglas se formulan mediante invariantes estructurales:

* mismo origen hacia mismo destino
* múltiples destinos desde un origen
* múltiples puertos por destino
* puerto destino fijo
* secuencialidad de puertos
* baja duración
* baja varianza de bytes
* sincronización temporal
* coordinación distribuida

---

## 10. Decisión: diferenciar ataques por localización de automatización

### Decisión

Formalizar los ataques según dónde aparece la automatización.

### Motivo

Los ataques analizados no solo se diferencian por protocolo o etiqueta, sino por la localización de la estructura automatizada.

### Modelo resultante

| Ataque          | Categoría                   | Localización de la automatización  |
| --------------- | --------------------------- | ---------------------------------- |
| DoS             | Inundación                  | Origen                             |
| UDP Scan        | Reconocimiento UDP          | Espacio de destino/red             |
| scan11          | Single-Source Vertical Scan | Servicios del host objetivo        |
| scan44          | Distributed Vertical Scan   | Red coordinada + servicios destino |
| anomaly-sshscan | SSH Horizontal Scan         | Selección de IPs destino           |
| NerisBotnet     | Botnet/C2                   | Red distribuida/C2                 |

### Consecuencia

Esta idea se convirtió en el eje del modelo de comportamiento sintético.

El modelo no se centra solo en decir “esto es DoS” o “esto es scan”, sino en explicar dónde aparece la automatización y qué estructura rompe la normalidad del tráfico ISP.

---

## 11. Decisión: tratar NerisBotnet de forma distinta

### Decisión

No aplicar a NerisBotnet las mismas reglas que a DoS o UDP Scan.

### Motivo

NerisBotnet no siempre presenta un patrón local claro en una ventana pequeña. Su comportamiento puede estar distribuido entre múltiples nodos y requerir más contexto temporal.

Las primeras ventanas podían contener pocos flujos etiquetados como `nerisbotnet`, mientras que otras ventanas sí mostraban evidencia clara de coordinación C2.

### Consecuencia

El detector solo clasifica NerisBotnet cuando existe evidencia suficiente de:

* múltiples IPs origen
* mismo destino
* mismo puerto C2
* mismo timestamp o intervalo muy reducido
* baja varianza de bytes
* métricas homogéneas entre nodos

Esto evita forzar la clasificación cuando no hay evidencia distribuida suficiente.

---

## 12. Decisión: evitar falsos positivos en tráfico normal

### Decisión

Priorizar reglas conservadoras para evitar clasificar tráfico normal como ataque.

### Motivo

En redes ISP reales puede haber:

* tráfico UDP legítimo
* ráfagas DNS
* flujos de corta duración
* puertos repetidos
* tráfico automatizado legítimo
* ruido de fondo
* actividad puntual de alta densidad

Por tanto, una única métrica aislada no basta para detectar un ataque.

### Consecuencia

El detector exige combinación de condiciones.

Ejemplo:

```text
UDP + duración cero
```

no basta para clasificar UDP Scan.

Debe existir además:

```text
src_ip fijo + src_port fijo + múltiples dst_ip + dst_port secuencial + baja varianza
```

Este enfoque reduce falsos positivos sobre tráfico normal.

---

## 13. Decisión: ampliar el análisis a nuevas familias de ataque

### Decisión

Después de analizar DoS, UDP Scan y NerisBotnet, se decidió ampliar el análisis a nuevas etiquetas:

* scan11
* scan44
* anomaly-sshscan
* anomaly-spam

### Motivo

El modelo inicial era útil, pero estaba centrado en tres familias. Para hacerlo más sólido, era necesario comprobar si podía generalizarse a otras formas de reconocimiento y anomalía.

### Consecuencia

Se integraron nuevas categorías conceptuales:

```text
scan11 → Single-Source Vertical Scan
scan44 → Distributed Vertical Scan
anomaly-sshscan → SSH Horizontal Scan
anomaly-spam → caso exploratorio de baja evidencia
```

Estas categorías todavía requieren validación programática completa, pero ya están formalizadas mediante análisis asistido por LLM.

---

## 14. Decisión: crear un extractor único de ventanas

### Decisión

Crear un único script para extraer todas las ventanas necesarias de todos los ataques.

### Motivo

Inicialmente se habían utilizado scripts o ejecuciones específicas para extraer ventanas de algunos ataques. Sin embargo, al ampliar el trabajo a más etiquetas y distintos tamaños de ventana, era mejor unificar el proceso.

El objetivo era evitar:

* duplicación de scripts
* errores de rutas
* configuraciones inconsistentes
* diferencias entre ataques
* dificultad para reproducir la extracción

### Consecuencia

Se creó el script:

```text
scripts/02_attack_analysis/extract_attack_windows_unified.py
```

Este script permite modificar fácilmente:

* ataques a procesar
* número de ventanas
* tamaño por filas
* segundos antes/después
* límite máximo de filas
* estructura de salida

---

## 15. Decisión: extraer tres tipos de ventanas por ataque

### Decisión

Extraer tres tipos de ventanas para cada ataque:

```text
rows_2000
time_10s
time_60s
```

### Motivo

Cada tipo de ventana aporta una perspectiva distinta:

| Tipo de ventana | Objetivo                                     |
| --------------- | -------------------------------------------- |
| `rows_2000`     | Analizar contexto local por número de trazas |
| `time_10s`      | Analizar contexto temporal corto             |
| `time_60s`      | Analizar contexto temporal amplio            |

Esto permite observar si el patrón se mantiene igual cuando cambia la escala de análisis.

### Consecuencia

La estructura de salida adoptada es:

```text
data/attack_analysis/<ataque>/
├── rows_2000/
├── time_10s/
└── time_60s/
```

---

## 16. Decisión: limitar las ventanas temporales a 100.000 filas

### Decisión

Aplicar un límite máximo de filas por ventana temporal:

```text
MAX_ROWS_PER_WINDOW = 100000
```

### Motivo

En un entorno ISP, una ventana de 60 segundos puede contener muchísimos flujos. Sin límite, algunas ventanas podrían ser demasiado grandes para:

* revisarlas manualmente
* cargarlas en NotebookLM
* procesarlas de forma cómoda
* usarlas en una web demostrativa

### Consecuencia

Cuando una ventana supera el límite, se trunca y se marca en el resumen como:

```text
created_truncated
```

Esto no se considera un error, sino una decisión de control de tamaño.

Las ventanas truncadas se usan como contexto amplio limitado.

---

## 17. Resultado del extractor único

### Decisión/resultado

El extractor único se ejecutó sobre el fichero limpio de agosto y generó ventanas para todos los ataques configurados.

### Resultado obtenido

El script localizó las siguientes ocurrencias:

| Ataque          | Ocurrencias encontradas |
| --------------- | ----------------------: |
| dos             |                 391.599 |
| anomaly-udpscan |                 989.872 |
| nerisbotnet     |                 151.525 |
| scan11          |                  36.144 |
| scan44          |                 190.584 |
| anomaly-sshscan |                       8 |
| anomaly-spam    |                      47 |

El plan de extracción generó:

```text
171 ventanas planificadas
127 ventanas creadas completas
44 ventanas truncadas por límite de filas
0 ventanas vacías
```

### Consecuencia

El extractor se considera funcional.

Se generaron resúmenes por ataque y un resumen global:

```text
data/attack_analysis/window_extraction_summary.csv
```

Este resumen permite controlar:

* número de filas por ventana
* número de flujos de ataque
* número de flujos background
* otras etiquetas presentes
* estado de creación
* si la ventana fue truncada

---

## 18. Interpretación de los resultados de extracción

### Decisión

Utilizar el resumen del extractor como evidencia metodológica para decidir qué ataques tienen alta o baja evidencia.

### Observaciones

Los ataques DoS, UDP Scan, scan11, scan44 y NerisBotnet presentan muchas ocurrencias y ventanas con suficiente volumen de ataque.

En cambio:

```text
anomaly-sshscan → 8 ocurrencias
anomaly-spam → 47 ocurrencias
```

Por tanto, estos dos casos deben tratarse con más cautela.

### Consecuencia

`anomaly-sshscan` y `anomaly-spam` se mantienen como casos de baja evidencia relativa frente a otros ataques.

La diferencia es:

* `anomaly-sshscan` se integra conceptualmente como SSH Horizontal Scan, pero requiere cautela por su bajo número de flujos.
* `anomaly-spam` se trata como caso exploratorio, no como validación fuerte del modelo.

---

## 19. Decisión: crear un cuaderno NotebookLM por ataque

### Decisión

Crear un cuaderno independiente de NotebookLM para cada ataque.

### Motivo

Un único cuaderno con todos los ataques puede mezclar patrones y provocar respuestas menos precisas.

Separar por ataque permite:

* acumular contexto específico
* evitar confusiones entre patrones
* hacer prompts más especializados
* generar explicaciones más consistentes
* construir un “experto” por familia de ataque

### Cuadernos previstos

```text
UGR16 - DoS
UGR16 - UDP Scan
UGR16 - NerisBotnet
UGR16 - scan11
UGR16 - scan44
UGR16 - anomaly-sshscan
UGR16 - anomaly-spam
```

### Consecuencia

Cada cuaderno recibirá sus propias ventanas reales y un resumen del modelo actual.

---

## 20. Decisión: usar NotebookLM para generar simulaciones sintéticas ilustrativas

### Decisión

Generar pequeños datasets sintéticos ilustrativos mediante LLM.

### Motivo

El objetivo es crear ejemplos visuales y didácticos de cada patrón de ataque.

Estas simulaciones pueden servir para:

* mostrar claramente la estructura del ataque
* alimentar una web demostrativa
* explicar visualmente la topología
* mostrar ejemplos sencillos en la defensa
* ilustrar cómo se vería un patrón idealizado

### Aclaración metodológica

Estas simulaciones no se utilizarán para:

* entrenar modelos
* validar el detector
* ajustar umbrales
* sustituir datos reales
* afirmar resultados empíricos

### Consecuencia

Las simulaciones se tratarán como:

```text
datasets sintéticos ilustrativos
simulaciones explicativas
ejemplos artificiales representativos
```

La validación seguirá realizándose únicamente sobre ventanas reales de UGR'16.

---

## 21. Decisión: separar datos reales y datos sintéticos generados por LLM

### Decisión

Guardar las simulaciones generadas por LLM en una carpeta independiente.

### Motivo

Es importante evitar cualquier mezcla entre datos reales y ejemplos artificiales.

### Consecuencia

La estructura prevista es:

```text
data/synthetic_llm_examples/
├── dos/
├── anomaly-udpscan/
├── nerisbotnet/
├── scan11/
├── scan44/
└── anomaly-sshscan/
```

Dentro de cada carpeta se generarán dos tipos de archivo:

```text
<attack>_attack_only.csv
<attack>_context_window.csv
```

Donde:

* `attack_only` representa un patrón puro del ataque
* `context_window` incluye algunas trazas normales antes y después del ataque

También se creará un README explicando que estos archivos son solo ilustrativos.

---

## 22. Decisión: no basar el TFG en una API de NotebookLM

### Decisión

No hacer depender el TFG de una integración automática con NotebookLM.

### Motivo

Aunque existen formas de automatizar o conectar servicios externos, basar el núcleo del TFG en una API no oficial o inestable puede introducir riesgos:

* dependencia externa
* problemas de credenciales
* cambios en el servicio
* dificultad para reproducir
* complejidad innecesaria

### Consecuencia

La integración automática con NotebookLM se considera opcional o experimental.

Para la web, la primera versión mostrará:

* prompts utilizados
* respuestas ya generadas
* simulaciones ya guardadas
* resultados del detector

Una posible integración automática se deja como ampliación futura.

---

## 23. Decisión: usar Trello para organizar el trabajo

### Decisión

Organizar el trabajo pendiente mediante Trello.

### Motivo

El proyecto ya tiene varias líneas abiertas:

* extracción de ventanas
* análisis con NotebookLM
* simulaciones sintéticas
* detector actualizado
* documentación
* web demostrativa

Trello permite separar tareas y evitar perder el foco.

### Estructura adoptada

Listas:

```text
Backlog
Por hacer
En progreso
Revisión
Hecho
```

### Consecuencia

Las tareas se ordenan por prioridad.

El criterio adoptado es trabajar en una tarea principal cada vez, evitando empezar la web antes de cerrar el extractor, los cuadernos y la validación.

---

## 24. Decisión: dejar la web como demostrador final

### Decisión

Crear una web interactiva, pero no como núcleo inicial del TFG.

### Motivo

La web puede aportar mucho valor visual, pero también puede consumir demasiado tiempo si se aborda antes de cerrar la parte metodológica.

### Consecuencia

La web se plantea como demostrador final para mostrar:

* ataques analizados
* topología de cada ataque
* reglas del detector
* resultados sobre ventanas reales
* simulaciones sintéticas ilustrativas
* prompts usados

La web no sustituye a la memoria ni a la validación programática.

---

## 25. Decisión: no hacer Machine Learning propio

### Decisión

No entrenar un modelo de Machine Learning propio.

### Motivo

El foco del trabajo es el uso de LLMs como herramientas de análisis, explicación y generación de hipótesis.

El detector heurístico se utiliza únicamente para validación, no como modelo entrenado.

### Consecuencia

La aportación principal del trabajo no es un clasificador ML, sino una metodología de análisis explicable asistida por LLMs.

---

## 26. Estado actual del trabajo

Hasta este punto se ha realizado:

* estudio inicial del dataset UGR'16
* extracción de perfiles normales
* extracción inicial de ventanas de ataque
* análisis de tráfico normal
* análisis DoS
* análisis UDP Scan
* análisis NerisBotnet
* análisis scan11
* análisis scan44
* análisis anomaly-sshscan
* formalización del modelo de comportamiento sintético
* validación inicial mediante detector heurístico
* documentación metodológica
* banco de prompts
* borrador de memoria
* índice de documentación
* extractor único de ventanas
* generación de ventanas por filas y por tiempo
* resumen global de extracción

---

## 27. Próximas decisiones y tareas

Quedan abiertas las siguientes tareas:

* crear cuadernos NotebookLM por ataque
* subir las nuevas ventanas a cada cuaderno
* ejecutar prompts multiventana
* generar simulaciones sintéticas ilustrativas
* documentar el uso de simulaciones
* adaptar el detector a:

  * Single-Source Vertical Scan
  * Distributed Vertical Scan
  * SSH Horizontal Scan
* ejecutar el detector actualizado
* revisar falsos positivos en tráfico normal
* actualizar validaciones y memoria
* desarrollar una web demostrativa

---

## 28. Conclusión

Las decisiones tomadas orientan el trabajo hacia un enfoque explicable y metodológicamente controlado.

El proyecto no busca sustituir un IDS ni entrenar un modelo de clasificación, sino estudiar cómo los LLMs pueden ayudar a analizar tráfico de red, formular hipótesis y generar explicaciones técnicas, siempre con validación posterior sobre datos reales.

La incorporación del extractor único, los cuadernos especializados por ataque y las simulaciones sintéticas ilustrativas refuerzan la metodología, ya que permiten trabajar con más contexto real, mantener trazabilidad y generar recursos visuales sin confundirlos con evidencia empírica.

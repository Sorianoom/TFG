# Banco de prompts utilizados con LLMs

## 1. Objetivo

Este documento recoge los prompts utilizados durante el análisis del dataset UGR'16 mediante modelos de lenguaje grandes (LLMs), principalmente NotebookLM.

El objetivo es documentar cómo se ha interactuado con el LLM durante el trabajo, qué tipo de preguntas se han planteado y cómo se han orientado los prompts para obtener análisis técnicos útiles.

Los prompts se organizan por fase del proyecto:

- análisis de tráfico normal
- análisis de ataques individuales
- comparación entre ataques
- formalización de modelos
- validación de hipótesis
- redacción académica

---

## 2. Prompt para analizar tráfico normal

### Objetivo

Identificar la línea base de comportamiento normal del ISP a partir de perfiles de calibración.

### Prompt

```text
Analiza estos perfiles normales de calibración del dataset UGR'16.

Quiero que identifiques:

1. Comportamiento general de cada perfil.
2. Diferencias entre horario laboral, nocturno y transición.
3. Puertos, protocolos y métricas predominantes.
4. Rasgos que puedan considerarse normales en esta red.
5. Señales que podrían indicar desviación respecto a la normalidad.

No busques ataques. Céntrate en describir el comportamiento normal del tráfico de fondo.
```

### Uso dentro del trabajo

Este prompt se utilizó para que el LLM construyera una referencia de normalidad basada en los perfiles extraídos del conjunto de calibración.

---

## 3. Prompt para comparar DoS con tráfico normal

### Objetivo

Comparar ventanas DoS con perfiles normales y extraer patrones técnicos diferenciales.

### Prompt

```text
Compara los perfiles normales con las ventanas DoS.

Quiero que identifiques:

1. Patrones comunes en las ventanas DoS.
2. Diferencias respecto al tráfico normal.
3. Métricas más alteradas:
   - IP origen
   - IP destino
   - puerto origen
   - puerto destino
   - protocolo
   - paquetes
   - bytes
   - duración
4. Señales que permitan explicar por qué se trata de un ataque DoS.
5. Posibles reglas de detección basadas en comportamiento.

No te limites a describir etiquetas. Explica el comportamiento técnico del ataque.
```

### Uso dentro del trabajo

Este prompt permitió identificar que el DoS presentaba concentración hacia un único destino, uso de TCP, puerto destino fijo, duración cercana a cero y secuencialidad en puertos de origen.

---

## 4. Prompt para formalizar el modelo DoS

### Objetivo

Transformar el análisis del ataque DoS en un modelo de comportamiento generalizable.

### Prompt

```text
A partir del análisis de las ventanas DoS, formaliza un modelo de detección basado en comportamiento.

Debe incluir:

1. Patrón observado.
2. Métricas alteradas.
3. Diferencias con tráfico normal.
4. Explicación técnica del ataque.
5. Reglas de detección.
6. Conclusión técnica.

Evita depender de IPs concretas. Céntrate en patrones generalizables.
```

### Uso dentro del trabajo

Este prompt permitió pasar de una descripción del ataque a una formalización basada en invariantes estructurales.

---

## 5. Prompt para analizar UDP Scan

### Objetivo

Extraer el patrón estructural del ataque `anomaly-udpscan`.

### Prompt

```text
Analiza exclusivamente las ventanas anomaly-udpscan.

Identifica patrones comunes entre ellas:

1. IP origen e IPs destino.
2. Puerto origen y puertos destino.
3. Protocolo utilizado.
4. Duración, paquetes y bytes.
5. Existencia de barrido de puertos.
6. Existencia de dispersión de IPs.
7. Nivel de variabilidad o entropía.
8. Diferencias con tráfico UDP normal como DNS.

No describas línea por línea. Extrae el patrón estructural global del ataque.
```

### Uso dentro del trabajo

Este prompt permitió identificar el puerto origen fijo, la dispersión hacia múltiples destinos y el barrido secuencial de puertos destino.

---

## 6. Prompt para comparar UDP Scan con tráfico normal

### Objetivo

Determinar por qué el UDP Scan no debe confundirse con tráfico UDP legítimo, como DNS.

### Prompt

```text
Compara el patrón anomaly-udpscan con los perfiles normales de calibración.

Quiero que identifiques:

1. Qué diferencias hay entre el escaneo UDP y el tráfico normal.
2. Qué métricas se desvían más respecto a la normalidad.
3. Cómo cambia la diversidad de IPs, puertos, duración, paquetes y bytes.
4. Por qué este patrón no puede considerarse tráfico UDP normal, como DNS.
5. Qué reglas de detección se pueden proponer.

Céntrate en comportamiento, no en etiquetas.
```

### Uso dentro del trabajo

Este prompt fue útil para diferenciar el UDP Scan del tráfico DNS normal, destacando la secuencialidad de puertos y la baja varianza en bytes.

---

## 7. Prompt para comparar DoS y UDP Scan

### Objetivo

Comparar dos ataques sintéticos con estructuras diferentes.

### Prompt

```text
Compara el modelo DoS con el modelo anomaly-udpscan.

Quiero que expliques:

1. Diferencias de objetivo.
2. Diferencias de concentración/dispersión.
3. Diferencias en puertos.
4. Diferencias en métricas de flujo.
5. Reglas de detección específicas para cada ataque.
6. Cómo se pueden integrar ambos en un mismo modelo de detección basado en comportamiento.

La comparación debe centrarse en dónde aparece la estructura de automatización.
```

### Uso dentro del trabajo

Este prompt permitió formular la idea de que en DoS la automatización se localiza en el origen, mientras que en UDP Scan se localiza en la exploración del destino.

---

## 8. Prompt para analizar NerisBotnet

### Objetivo

Analizar NerisBotnet como comportamiento distribuido y no como ataque sintético simple.

### Prompt

```text
Analiza exclusivamente las tres ventanas etiquetadas como nerisbotnet.

Identifica patrones comunes en comportamiento de red, sin asumir que se trata de un ataque homogéneo como DoS o Scan.

El análisis debe centrarse en:

1. Identificación de roles:
   - IPs de origen y destino
   - Determinar si el patrón es 1→1, 1→muchos o muchos→1

2. Estructura de comunicación:
   - Puertos utilizados
   - Persistencia de puertos específicos
   - Protocolo predominante

3. Métricas de flujo:
   - Duración
   - Número de paquetes
   - Tamaño en bytes
   - Nivel de entropía

4. Comportamiento temporal:
   - Frecuencia de aparición
   - Periodicidad o ráfagas

5. Tipo de actividad:
   - Beaconing
   - Propagación
   - Coordinación distribuida

6. Diferencias con:
   - tráfico normal
   - DoS
   - UDP Scan

7. Conclusión técnica:
   - definir el patrón de comportamiento del botnet
   - explicar dónde reside la automatización

No describas cada línea individual. Extrae el patrón estructural global del ataque.
```

### Uso dentro del trabajo

Este prompt permitió identificar NerisBotnet como un comportamiento de coordinación distribuida, donde múltiples nodos pueden actuar de forma sincronizada hacia un destino común C2.

---

## 9. Prompt para generar el modelo unificado

### Objetivo

Integrar DoS, UDP Scan y NerisBotnet en un único modelo de comportamiento sintético.

### Prompt

```text
Genera un nuevo archivo llamado modelo_comportamiento_sintetico.md.

Debe integrar en un único modelo los tres comportamientos analizados en UGR'16:

- Ataque DoS
- UDP Scan
- NerisBotnet

Estructura obligatoria:

1. Introducción.
2. Pipeline jerárquico de detección.
3. Modelo DoS.
4. Modelo UDP Scan.
5. Modelo NerisBotnet.
6. Tabla comparativa clara entre los tres modelos.
7. Conclusión técnica.

No incluyas datos crudos ni ejemplos CSV.
Redacta de forma técnica y estructurada, orientado a un modelo de detección implementable.
```

### Uso dentro del trabajo

Este prompt permitió construir el modelo integrado de comportamiento sintético, basado en la localización de la automatización.

---

## 10. Prompt para validar hipótesis

### Objetivo

Contrastar las hipótesis generadas por el LLM con los resultados del detector heurístico.

### Prompt

```text
A partir de los resultados del detector heurístico, compara las hipótesis generadas por el LLM con la evidencia obtenida en los datos.

Quiero una tabla que incluya:

1. Hipótesis planteada.
2. Evidencia observada.
3. Si queda validada o no.
4. Comentario técnico.

Diferencia claramente entre hipótesis confirmadas, parcialmente confirmadas y no confirmadas.
```

### Uso dentro del trabajo

Este prompt se utilizó para convertir los resultados del detector en evidencia de validación de hipótesis.

---

## 11. Prompt para generar una explicación técnica a partir de resultados

### Objetivo

Transformar los resultados del detector en una explicación técnica clara.

### Prompt

```text
A partir de los resultados obtenidos por el detector heurístico, redacta una explicación técnica clara.

Debe incluir:

1. Qué ataques han sido detectados correctamente.
2. Qué métricas han permitido detectarlos.
3. Qué ventanas no han sido clasificadas y por qué.
4. Qué diferencias hay entre detección de DoS, UDP Scan y NerisBotnet.
5. Qué limitaciones tiene el detector actual.
6. Qué conclusiones se pueden extraer sobre el uso de LLMs en este análisis.

No presentes el detector como un IDS completo. Preséntalo como una validación programática de hipótesis generadas mediante LLM.
```

### Uso dentro del trabajo

Este prompt permitió redactar conclusiones técnicas sin exagerar el alcance del detector.

---

## 12. Prompt para revisar críticamente una respuesta del LLM

### Objetivo

Reducir el riesgo de aceptar conclusiones no demostradas.

### Prompt

```text
Revisa críticamente la respuesta anterior.

Quiero que identifiques:

1. Afirmaciones técnicamente sólidas.
2. Afirmaciones dudosas o no demostradas.
3. Posibles sobreinterpretaciones.
4. Qué partes deberían validarse con código.
5. Qué partes pueden utilizarse en la memoria del TFG.
6. Qué partes deberían reformularse para ser más rigurosas.

No des por válida ninguna conclusión que no esté apoyada por los datos proporcionados.
```

### Uso dentro del trabajo

Este prompt se utiliza para filtrar respuestas demasiado generales o afirmaciones que requieren validación empírica.

---

## 13. Prompt para transformar análisis en redacción académica

### Objetivo

Convertir análisis técnico en texto apto para la memoria del TFG.

### Prompt

```text
Convierte el análisis técnico anterior en una sección académica para memoria de TFG.

Requisitos:

1. Mantén un tono formal y técnico.
2. No incluyas datos crudos extensos.
3. Explica el razonamiento de forma progresiva.
4. Diferencia claramente observación, interpretación y conclusión.
5. Evita afirmar causalidad si solo hay correlación.
6. Indica limitaciones cuando sea necesario.

La sección debe poder integrarse directamente en una memoria académica.
```

### Uso dentro del trabajo

Este prompt permite convertir los resultados del análisis en secciones redactadas de forma académica.

---

## 14. Prompt para generar conclusiones parciales

### Objetivo

Obtener conclusiones controladas y no exageradas a partir de una fase del trabajo.

### Prompt

```text
Genera conclusiones parciales a partir del análisis realizado.

Deben responder a:

1. Qué se ha observado.
2. Qué se ha confirmado con datos.
3. Qué papel ha tenido el LLM.
4. Qué se ha validado mediante código.
5. Qué limitaciones quedan abiertas.
6. Qué implicaciones tiene para la detección basada en comportamiento.

No exageres el alcance de los resultados.
```

### Uso dentro del trabajo

Este prompt permite cerrar fases del trabajo de forma rigurosa.

---

## 15. Prompt para analizar resultados del detector

### Objetivo

Interpretar el CSV generado por el detector heurístico.

### Prompt

```text
Analiza los resultados del archivo behavior_detection_results.csv.

Quiero que identifiques:

1. Qué ventanas han sido clasificadas correctamente.
2. Qué ventanas no han sido clasificadas.
3. Si existen falsos positivos sobre tráfico normal.
4. Qué métricas justifican cada clasificación.
5. Qué limitaciones se observan.
6. Qué conclusiones se pueden extraer sobre el modelo de comportamiento.

No evalúes solo la etiqueta dominante. Ten en cuenta que una ventana puede contener background mezclado con ataque.
```

### Uso dentro del trabajo

Este prompt se utiliza para interpretar los resultados experimentales generados por el script Python.

---
## 16. Prompt general para analizar un nuevo ataque

### Objetivo

Disponer de un prompt reutilizable para analizar cualquier nueva etiqueta de ataque del dataset UGR'16.

Este prompt se utiliza cuando se extraen nuevas ventanas temporales y todavía no se conoce el patrón estructural del ataque.

### Prompt

```text
Analiza exclusivamente estas tres ventanas etiquetadas como [NOMBRE_DEL_ATAQUE].

No describas línea por línea. Extrae el patrón estructural global del ataque.

Quiero que identifiques:

1. IPs origen e IPs destino relevantes.
2. Si el patrón es 1→1, 1→muchos, muchos→1 o muchos→muchos.
3. Protocolos predominantes.
4. Puertos origen y destino más relevantes.
5. Si existe barrido de puertos o barrido de IPs.
6. Si el escaneo parece horizontal, vertical o híbrido.
7. Duración, paquetes y bytes.
8. Nivel de variabilidad o entropía.
9. Comportamiento temporal: ráfagas, periodicidad o sincronización.
10. Señales que indiquen automatización.
11. Posibles reglas de detección basadas en comportamiento.
12. Dónde parece localizarse la automatización: origen, destino, host objetivo, puertos destino o red distribuida.

Céntrate en comportamiento, no en etiquetas.
No asumas que el patrón es igual a ataques anteriores: dedúcelo a partir de las trazas.
```

### Uso dentro del trabajo

Este prompt sirve como plantilla base para analizar nuevas familias de ataque, como `scan11`, `scan44`, `anomaly-sshscan` o `anomaly-spam`.

---

## 17. Prompt para analizar scan11

### Objetivo

Extraer el patrón estructural del ataque `scan11` y comprobar si representa una variante de escaneo distinta a DoS, UDP Scan o NerisBotnet.

### Prompt

```text
Analiza exclusivamente las tres ventanas etiquetadas como scan11.

No describas línea por línea. Extrae el patrón estructural global del ataque.

Quiero que identifiques:

1. IPs origen e IPs destino relevantes.
2. Si el patrón es 1→1, 1→muchos, muchos→1 o muchos→muchos.
3. Protocolos predominantes.
4. Puertos origen y destino más relevantes.
5. Si existe barrido de puertos o barrido de IPs.
6. Si el escaneo parece horizontal, vertical o híbrido.
7. Duración, paquetes y bytes.
8. Nivel de variabilidad o entropía.
9. Comportamiento temporal: ráfagas, periodicidad o sincronización.
10. Señales que indiquen automatización.
11. Posibles reglas de detección basadas en comportamiento.
12. Dónde parece localizarse la automatización: origen, destino o red distribuida.

Céntrate en comportamiento, no en etiquetas.
No asumas que es igual a UDP Scan: dedúcelo a partir de las trazas.
```

### Uso dentro del trabajo

Este prompt permitió identificar `scan11` como un escaneo TCP vertical de fuente única, con topología `1 origen → 1 destino → muchos puertos`.

---

## 18. Prompt para integrar scan11 en el modelo sintético

### Objetivo

Comparar el patrón `scan11` con el modelo de comportamiento sintético previamente definido y determinar si encaja en alguna categoría existente o requiere una nueva subcategoría.

### Prompt

```text
A partir del patrón observado en scan11, compáralo con el siguiente modelo de comportamiento sintético que estoy utilizando en mi TFG:

- DoS: automatización localizada en el origen. Patrón 1→1, muchos flujos TCP de baja duración hacia un único destino, puerto destino fijo y puertos origen secuenciales.
- UDP Scan: automatización localizada en el espacio de destino. Patrón 1→muchos, protocolo UDP, origen fijo, puerto origen fijo, múltiples destinos y puertos destino secuenciales.
- NerisBotnet: automatización distribuida en red. Patrón muchos→1 o híbrido, múltiples nodos sincronizados, destino C2 común y comportamiento coordinado.

Ahora compara scan11 con este modelo.

Quiero que respondas:

1. Si scan11 encaja en alguna categoría existente.
2. Si scan11 debe considerarse una variante de escaneo distinta al UDP Scan.
3. Dónde se localiza la automatización en scan11: origen, destino, host objetivo, puertos destino o red distribuida.
4. Qué diferencias tiene scan11 respecto a DoS.
5. Qué diferencias tiene scan11 respecto a UDP Scan.
6. Qué diferencias tiene scan11 respecto a NerisBotnet.
7. Si el modelo de comportamiento sintético debe ampliarse para incluir scan11.
8. Qué nombre técnico tendría esta nueva categoría.
9. Qué reglas de detección deberían añadirse al modelo.

Justifica la respuesta usando IPs, puertos, protocolo, duración, paquetes, bytes, dispersión, concentración, secuencialidad y sincronización temporal.

No fuerces el encaje si el patrón no coincide claramente.
```

### Uso dentro del trabajo

Este prompt permitió concluir que `scan11` debe tratarse como `TCP Vertical Scan` o `Escaneo TCP vertical`, ya que su automatización se localiza en el barrido de puertos de un único host objetivo.

---

## 19. Prompt para analizar scan44 e integrarlo con scan11

### Objetivo

Analizar el ataque `scan44` y determinar si representa una variante de `scan11` o una nueva forma de escaneo distribuido.

### Prompt

```text
Analiza exclusivamente las tres ventanas etiquetadas como scan44.

No describas línea por línea. Extrae el patrón estructural global del ataque.

Quiero que identifiques:

1. IPs origen e IPs destino relevantes.
2. Si el patrón es 1→1, 1→muchos, muchos→1 o muchos→muchos.
3. Protocolos predominantes.
4. Puertos origen y destino más relevantes.
5. Si existe barrido de puertos o barrido de IPs.
6. Si el escaneo parece horizontal, vertical o híbrido.
7. Duración, paquetes y bytes.
8. Nivel de variabilidad o entropía.
9. Comportamiento temporal: ráfagas, periodicidad o sincronización.
10. Señales que indiquen automatización.
11. Posibles reglas de detección basadas en comportamiento.
12. Dónde parece localizarse la automatización: origen, destino, host objetivo, puertos destino o red distribuida.

Céntrate en comportamiento, no en etiquetas.
No asumas que scan44 es igual a scan11: dedúcelo a partir de las trazas.
```

### Prompt de integración

```text
A partir del patrón observado en scan44, compáralo con scan11 y con el modelo de comportamiento sintético que estoy utilizando en mi TFG:

- DoS: automatización localizada en el origen. Patrón 1→1, muchos flujos TCP de baja duración hacia un único destino, puerto destino fijo y puertos origen secuenciales.
- UDP Scan: automatización localizada en el espacio de destino/red. Patrón 1→muchos, protocolo UDP, origen fijo, puerto origen fijo, múltiples destinos y puertos destino secuenciales.
- scan11: escaneo TCP vertical. Patrón 1→1, protocolo TCP, un origen contra un único host objetivo, muchos puertos destino, duración 0.000s, 1 paquete y tamaño muy bajo.
- NerisBotnet: automatización distribuida en red. Patrón muchos→1 o híbrido, múltiples nodos sincronizados, destino C2 común y comportamiento coordinado.

Quiero que respondas:

1. Si scan44 encaja con scan11 como otro TCP Vertical Scan.
2. Si scan44 representa otra variante de escaneo.
3. Dónde se localiza la automatización en scan44.
4. Qué diferencias tiene scan44 respecto a scan11.
5. Qué diferencias tiene scan44 respecto a UDP Scan.
6. Qué diferencias tiene scan44 respecto a NerisBotnet.
7. Si el modelo debe ampliarse o simplemente agrupar scan11 y scan44 bajo una misma familia.
8. Qué nombre técnico tendría la categoría final.
9. Qué reglas de detección deberían añadirse o modificarse.

Justifica la respuesta usando IPs, puertos, protocolo, duración, paquetes, bytes, dispersión, concentración, secuencialidad y sincronización temporal.

No fuerces el encaje si el patrón no coincide claramente.
```

### Uso dentro del trabajo

Este prompt permitió identificar `scan44` como una variante distribuida del escaneo TCP vertical.

El modelo se amplió con una familia de reconocimiento de servicios TCP:

```text
TCP Vertical Scan
├── scan11 → Single-Source Vertical Scan
└── scan44 → Distributed Vertical Scan
```

## 20. Observaciones generales sobre el diseño de prompts

Durante el trabajo se observó que los prompts más útiles son aquellos que:

- especifican claramente el tipo de tráfico o ataque que se quiere analizar
- piden patrones estructurales, no descripciones línea por línea
- solicitan comparación con tráfico normal
- obligan a justificar las conclusiones
- separan análisis, formalización y validación
- piden revisar críticamente las respuestas generadas
- evitan depender únicamente de etiquetas del dataset
- recuerdan al LLM que no debe asumir causalidad sin evidencia
- exigen diferenciar observación, interpretación y conclusión

Los prompts demasiado genéricos producen respuestas menos precisas y con mayor riesgo de sobreinterpretación.

---

## 21. Conclusión

El banco de prompts documenta la forma en que se ha utilizado el LLM durante el proyecto.

Esta documentación permite:

- reproducir el proceso de análisis
- justificar el uso de LLMs como herramienta metodológica
- mostrar cómo se generaron las hipótesis
- conectar las respuestas del LLM con la validación programática
- mantener trazabilidad entre datos, prompts, respuestas y conclusiones
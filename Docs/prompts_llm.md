# Banco de prompts utilizados con LLMs

## 1. Objetivo

Este documento recoge los prompts utilizados durante el análisis del dataset UGR'16 mediante modelos de lenguaje grandes (LLMs).

El objetivo es documentar la metodología de interacción con el LLM y asegurar que el análisis sea reproducible, estructurado y orientado a la extracción de patrones técnicos.

---

## 2. Prompt para analizar tráfico normal

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

---

## 3. Prompt para comparar DoS con tráfico normal

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

---

## 4. Prompt para formalizar el modelo DoS

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

---

## 5. Prompt para analizar UDP Scan

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

---

## 6. Prompt para comparar UDP Scan con tráfico normal

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

---

## 7. Prompt para comparar DoS y UDP Scan

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

---

## 8. Prompt para analizar NerisBotnet

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

---

## 9. Prompt para generar el modelo unificado

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

---

## 10. Prompt para validar hipótesis

```text
A partir de los resultados del detector heurístico, compara las hipótesis generadas por el LLM con la evidencia obtenida en los datos.

Quiero una tabla que incluya:

1. Hipótesis planteada.
2. Evidencia observada.
3. Si queda validada o no.
4. Comentario técnico.

Diferencia claramente entre hipótesis confirmadas, parcialmente confirmadas y no confirmadas.
```

---

## 11. Prompt para generar una explicación técnica a partir de resultados

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

---

## 12. Prompt para revisar una respuesta del LLM

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

---

## 13. Prompt para transformar análisis en redacción académica

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

---

## 14. Prompt para generar conclusiones parciales

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

---

## 15. Observaciones sobre el uso de prompts

Durante el trabajo se comprobó que los prompts más útiles son aquellos que:

- especifican claramente el tipo de ataque
- piden patrones estructurales, no descripciones línea a línea
- solicitan comparación con tráfico normal
- obligan a justificar las conclusiones
- separan análisis, formalización y validación
- piden revisar críticamente las respuestas generadas
- evitan depender únicamente de etiquetas del dataset

Los prompts genéricos producen respuestas menos precisas y con mayor riesgo de sobreinterpretación.
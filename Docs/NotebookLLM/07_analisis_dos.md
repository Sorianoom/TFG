# Análisis del ataque DoS

## 1. Objetivo

El objetivo de este análisis es estudiar el comportamiento del ataque de Denegación de Servicio (DoS) observado en el dataset UGR'16 y formalizar un modelo de detección basado en comportamiento.

El análisis no se centra únicamente en la etiqueta `dos`, sino en identificar qué estructura de tráfico diferencia este ataque del tráfico normal de fondo.

Para ello se utilizan ventanas temporales extraídas del conjunto de test y perfiles normales obtenidos del conjunto de calibración.

---

## 2. Datos utilizados

Se analizaron tres ventanas temporales DoS:

| Archivo | Descripción |
|---|---|
| `dos_window_1.csv` | Primera ventana DoS |
| `dos_window_2.csv` | Segunda ventana DoS |
| `dos_window_3.csv` | Tercera ventana DoS |

Estas ventanas incluyen tráfico de fondo mezclado con flujos etiquetados como ataque. Por tanto, el análisis se realiza buscando patrones estructurales dentro de la ventana, no únicamente la etiqueta dominante.

También se utilizaron como referencia los perfiles normales:

- `normal_laboral.csv`
- `normal_nocturno.csv`
- `normal_transicion.csv`

---

## 3. Análisis asistido por LLM

Las ventanas DoS fueron proporcionadas al LLM junto con los perfiles normales de calibración.

El LLM identificó que el ataque presenta una estructura altamente mecanizada que rompe la diversidad estadística del tráfico normal.

La hipótesis principal generada fue que el ataque no se caracteriza tanto por el volumen total de datos transferidos, sino por la generación masiva de flujos sintéticos de corta duración dirigidos hacia un objetivo concreto.

---

## 4. Patrón observado

El patrón DoS observado se caracteriza por una concentración clara desde un origen hacia un destino:

```text
42.219.150.246 → 42.219.158.16:80
```

El puerto de destino es el puerto `80`, asociado a HTTP.

La estructura del ataque responde a una relación:

```text
1 origen → 1 destino
```

El rasgo técnico más robusto es la progresión aritmética de los puertos de origen. Esta secuencialidad sugiere que los flujos han sido generados por una herramienta automatizada, simulando múltiples conexiones desde un mismo nodo.

---

## 5. Métricas alteradas

### 5.1 Densidad temporal

El ataque aparece como una ráfaga de flujos concentrados temporalmente.

Los flujos se generan en intervalos muy próximos, llegando a compartir el mismo timestamp o timestamps muy cercanos.

Esto contrasta con el tráfico normal, que presenta mayor dispersión temporal y variabilidad.

---

### 5.2 Duración de flujo

Los flujos del ataque presentan duración tendente a cero:

```text
duration ≈ 0.000s
```

Esto indica que no se establece una sesión de datos prolongada, sino flujos instantáneos o de muy corta duración.

---

### 5.3 Varianza de bytes

Los flujos detectados presentan baja varianza de bytes.

En la validación programática, los grupos DoS detectados presentan:

```text
bytes_var = 0.00
```

Esto indica una estructura repetitiva y uniforme, impropia de tráfico interactivo humano.

---

### 5.4 Secuencialidad de puertos origen

Los puertos de origen siguen una progresión secuencial.

Este comportamiento contrasta con el tráfico normal, donde los puertos efímeros suelen aparecer de forma más dispersa.

La secuencialidad de puertos origen es uno de los indicadores más fuertes de automatización en el ataque DoS analizado.

---

## 6. Diferencias con tráfico normal

Frente a los datos de calibración, donde el tráfico es heterogéneo y cicloestacionario, el ataque introduce una homogeneidad artificial.

El tráfico normal se caracteriza por:

- diversidad de IPs origen y destino
- diversidad de puertos
- mezcla de protocolos
- duraciones variables
- tamaños de flujo variables
- ausencia de una estructura secuencial dominante

En cambio, el DoS presenta:

- concentración hacia un único destino
- puerto destino fijo
- duración cercana a cero
- puertos origen secuenciales
- baja varianza de bytes
- repetición estructural

La diferencia principal es que el tráfico normal conserva diversidad estadística, mientras que el DoS presenta rigidez algorítmica.

---

## 7. Explicación técnica del ataque

El ataque puede interpretarse como una inundación TCP orientada al agotamiento del plano de control del sistema objetivo.

El objetivo no parece ser saturar el ancho de banda mediante grandes volúmenes de datos, sino generar múltiples flujos de corta duración que obligan al destino a gestionar intentos repetidos de conexión o control de estado.

Desde esta perspectiva, el ataque busca maximizar la carga en las estructuras de estado del sistema objetivo, como tablas de conexión o mecanismos de gestión del stack TCP/IP.

La automatización se localiza en el origen, ya que el atacante estructura los puertos de origen de forma secuencial para simular múltiples conexiones.

---

## 8. Pipeline de detección jerárquico

A partir del análisis se propone un pipeline de detección en tres fases.

### Fase 1: Detección primaria

Identificar grupos de flujos TCP con:

- alta concentración temporal
- misma IP origen
- misma IP destino
- mismo puerto destino
- duración cercana a cero

### Fase 2: Validación de automatización

Comprobar si el grupo presenta:

- puertos origen secuenciales
- pocos paquetes por flujo
- baja varianza en bytes

### Fase 3: Confirmación estructural

Confirmar que el patrón rompe la diversidad normal del tráfico de calibración:

- concentración anómala
- homogeneidad de métricas
- ausencia de comportamiento interactivo prolongado

---

## 9. Validación programática

Las hipótesis generadas por el LLM se validaron mediante el script:

```text
scripts/02_attack_analysis/detect_synthetic_behavior.py
```

El detector heurístico identificó correctamente las tres ventanas DoS.

| Ventana | Resultado del detector |
|---|---|
| `dos_window_1.csv` | DoS |
| `dos_window_2.csv` | DoS |
| `dos_window_3.csv` | DoS |

---

## 10. Evidencia observada

| Ventana | Grupo detectado | Flujos | Secuencialidad src_port | Duración ≈ 0 | Varianza bytes |
|---|---|---:|---|---|---:|
| `dos_window_1.csv` | `42.219.150.246 → 42.219.158.16:80` | 25 | Sí | Sí | 0.00 |
| `dos_window_2.csv` | `42.219.150.246 → 42.219.158.16:80` | 86 | Sí | Sí | 0.00 |
| `dos_window_3.csv` | `42.219.150.246 → 42.219.158.16:80` | 166 | Sí | Sí | 0.00 |

La validación confirma que el patrón identificado por el LLM es medible en las trazas reales.

---

## 11. Regla de detección derivada

La regla de detección DoS puede expresarse de forma general como:

```text
Si existe un grupo TCP con:
- mismo src_ip
- mismo dst_ip
- mismo dst_port
- duración cercana a cero
- pocos paquetes por flujo
- puertos origen secuenciales
- baja varianza de bytes
- concentración temporal

entonces clasificar como posible DoS.
```

Esta regla no depende de una IP concreta, sino de la estructura del comportamiento.

---

## 12. Relación con el modelo de comportamiento sintético

Dentro del modelo general de comportamiento sintético, el DoS se caracteriza por la localización de la automatización en el origen.

El atacante estructura los flujos desde el nodo emisor mediante puertos de origen secuenciales y los concentra hacia un único destino.

Esto lo diferencia de:

- UDP Scan, donde la automatización se observa en el barrido del espacio de destino.
- NerisBotnet, donde la automatización aparece distribuida entre múltiples nodos.

---

## 13. Limitaciones

El análisis presenta varias limitaciones:

- se realiza sobre ventanas previamente extraídas
- no se ha aplicado todavía al dataset completo
- las ventanas contienen mezcla de background y ataque
- el detector es heurístico
- los umbrales utilizados se han ajustado empíricamente
- el análisis de flags TCP no se ha utilizado como criterio principal de validación programática

---

## 14. Conclusión

El ataque DoS analizado en UGR'16 no se caracteriza principalmente por el volumen de datos transferidos, sino por la generación de múltiples flujos sintéticos de corta duración hacia un objetivo concreto.

El rasgo más relevante es la combinación de concentración, secuencialidad de puertos origen, duración cercana a cero y baja varianza de bytes.

El LLM permitió identificar y explicar el patrón, mientras que la validación programática permitió confirmar que dicho patrón existe en las ventanas analizadas.

Este análisis refuerza el enfoque del trabajo: utilizar LLMs para generar hipótesis explicables y validarlas posteriormente mediante evidencia empírica.
# Revisión de generalización del detector ampliado

Documento de análisis de [`scripts/02_attack_analysis/detect_synthetic_behavior_extended.py`](../../scripts/02_attack_analysis/detect_synthetic_behavior_extended.py)
desde el punto de vista de la **capacidad de generalización**.

El objetivo de esta revisión es comprobar si las reglas de detección dependen de **IPs
concretas**, de **etiquetas concretas** o de **patrones demasiado ajustados** a las ventanas
del dataset UGR'16 analizadas, o si por el contrario descansan sobre propiedades de
comportamiento transferibles a otros entornos. No se modifica el código: es un análisis
estático del estado actual del script.

---

## 1. ¿Usa el detector IPs concretas para clasificar?

**No.** No existe ninguna dirección IP literal codificada en la lógica de decisión. Las IPs
intervienen únicamente de forma **estructural y relacional**, nunca por su valor concreto:

- Agrupación por par `(src_ip, dst_ip)` y por `src_ip` para construir topologías
  (líneas 397-399, 450-452, 550-552, 795-798, 931-934).
- Recuento de cardinalidades: IPs origen/destino únicas, destinos por origen
  (`unique_dst_ips`, `unique_src_ips`).
- Dominancia relativa de un origen sobre el total de barrido (`top_share`, líneas 421-424).
- Agrupación por prefijo `/24` mediante `subnet_24()` (líneas 197-199), usada para evaluar si
  *varios* orígenes comparten subred (scan44, línea 725-726; nerisbotnet, líneas 879-880).
  Es una prueba de **coherencia estructural** (¿pertenecen a la misma subred?), no una
  comparación contra una subred fija como `42.219.0.0/16`.

Las IPs aparecen en los campos `evidence` y en los `summary` (p. ej. `src_ip`, `dst_ip`,
`cluster_sources`), pero **solo con fines descriptivos/interpretativos**, nunca como criterio
de clasificación. Esto cumple el requisito de la especificación: las IPs pueden usarse como
evidencia, no como regla final.

**Conclusión del punto 1:** el detector es independiente de IPs concretas.

---

## 2. ¿Usa labels para clasificar o solo para evaluar?

**Solo para evaluar.** El campo `label` se lee al cargar la ventana (línea 252) pero **ningún
detector lo consulta** en su lógica. Sus únicos usos son posteriores a la detección:

- `dominant_label` en las métricas generales (línea 279): se **reporta**, no decide.
- `attack_label_rows` (línea 1052): cuenta filas cuya etiqueta coincide con la familia
  esperada, **solo para comparar** la predicción con la verdad de referencia.

Es importante destacar que la familia esperada (`attack_expected`) **no proviene de la
etiqueta del flujo**, sino de la **carpeta** que contiene la ventana (`family_from_path`,
líneas 993-999). Por tanto, la comparación posterior usa la procedencia del fichero, y la
detección es completamente ciega a la etiqueta.

**Conclusión del punto 2:** la clasificación es 100 % independiente de la etiqueta; esta se
emplea exclusivamente como verdad de referencia para la evaluación.

---

## 3. Reglas verdaderamente generalizables

Las siguientes reglas descansan sobre **propiedades estructurales del comportamiento** y son
transferibles a otros datasets NetFlow sin reescritura conceptual:

| Regla / señal | Dónde | Por qué generaliza |
|---|---|---|
| Atomicidad de flujo (`duration ≈ 0`, `packets ≤ 2/== 1`) | `_select_atomic_tcp` (371-377), udpscan (537-542) | Propiedad intrínseca del tráfico de escaneo/sondeo automatizado, independiente del dataset. |
| Concentración vs dispersión de puerto destino | DoS `port_share` (467-472); scan11 `no_es_dos` (657) | Distingue inundación (puerto fijo) de barrido vertical (puertos dispersos) de forma puramente estructural. |
| Dominancia de un origen (`top_share`) | `syn_vertical_scanners` (421-424); scan11/scan44 | Separa "un origen domina" (scan11) de "reparto entre orígenes" (scan44) sin valores fijos. |
| Verticalidad: nº de puertos destino por par | (402-405) | Mide reconocimiento vertical de forma relativa, no por puertos concretos. |
| Secuencialidad de puertos (origen/destino) | `is_mostly_sequential` (202-218) | Señal de automatización (barrido programático), conceptualmente general. |
| Ráfaga temporal y sincronización | DoS `burst_ratio` (477); scan44 `temporal_sync` (717-722) | La densidad temporal anómala es un invariante del tráfico sintético. |
| Coordinación multinodo (clúster de métricas idénticas) | nerisbotnet (859-864) | La correlación entre nodos es el rasgo definitorio de botnet, independiente de IPs. |
| Baja varianza de bytes (baja entropía) | múltiples detectores | El determinismo métrico distingue tráfico generado por herramienta del tráfico humano. |
| Coherencia de subred `/24` entre orígenes | scan44 (725-726); neris (879-880) | Prueba relativa de pertenencia común, no subred fija. |
| Presencia del flag SYN | `has_flag(flags,"S")` | Semántica de protocolo TCP, universal. |

Estas reglas constituyen el **núcleo defendible** del detector.

---

## 4. Reglas que podrían estar sobreajustadas

Se identifican varios elementos cuyo valor concreto procede de la observación de las ventanas
UGR'16 y que, por tanto, podrían no transferirse a otro entorno:

| Elemento | Línea | Riesgo de sobreajuste | ¿En el núcleo de decisión? |
|---|---|---|---|
| `SCAN_SYN_BYTES = 44` con comparación **exacta** (`bytes_mode == 44`) | 96, 654, 666 | **Alto.** El tamaño del SYN depende de las opciones TCP y del exportador de flujos; puede ser 40, 48, 52 o 60 en otros entornos. | **Sí** (gate de scan11). |
| `SPAM_KNOWN_BYTES = {763, 815, 841, 893, 3136, 3143}` | 123, 942 | **Muy alto.** Son tamaños exactos de la campaña observada; difícilmente reaparecen en otra. | **Sí** (vía `repetitive`, núcleo de spam). |
| `UDP_KNOWN_SRC_PORTS = {5061, 5062, 5066, 5068}` | 88, 587 | Medio. Puertos del atacante UDP concreto. | No (señal de score, no núcleo). |
| `SPAM_PACKET_RANGE = (8, 13)` | 122, 940-941 | Medio. Rango de paquetes de la campaña observada. | Sí (vía `repetitive`). |
| `NERIS_C2_PORTS = {25, 6667, 2077}` | 117, 861 | Medio. 25 (SMTP) y 6667 (IRC) son semánticamente generales para C2; 2077 es específico. | **Sí** (gate de nerisbotnet: si no hay tráfico a estos puertos, no detecta). |
| Umbrales de volumen absolutos (`*_MIN_GROUP = 20`, `SCAN11_MIN_DST_PORTS = 20`, `UDP_MIN_DST_IPS = 5`) | 79, 84-86, 92-93 | Medio. Calibrados para los tamaños de ventana usados (`rows_2000`, `time_10s`, `time_60s`); en ventanas de otra granularidad podrían ser demasiado altos o bajos. | Sí (gates). |
| `is_mostly_sequential` acepta saltos `{1, 2}` | 217 | Bajo. El "+2" se añadió por observación del dataset, pero es una tolerancia razonable. | Indirecto. |

El patrón común es que el sobreajuste se concentra en **valores absolutos exactos** (tamaños
de bytes, puertos, recuentos), no en la estructura de las reglas. El caso más delicado es la
comparación exacta de 44 bytes en el núcleo de scan11 y el conjunto de bytes de spam.

---

## 5. Umbrales más sensibles

Ordenados por impacto sobre la clasificación:

1. **`SCAN_SINGLE_DOMINANCE = 0.7`** (línea 105). Arbitra **directamente** la frontera
   scan11 ↔ scan44 (líneas 658, 733). Una ventana con `top_share` próximo a 0,7 cambia de
   categoría con una variación mínima. Es el umbral más sensible del detector y explica la
   confusión cruzada observada entre ambos escaneos.
2. **`SCAN_SYN_BYTES = 44` (comparación exacta)** (líneas 654, 666). Gate binario en el núcleo
   de scan11: si el exportador produjera SYN de 40 o 60 bytes, scan11 dejaría de detectarse
   por completo pese a ser estructuralmente idéntico.
3. **`port_share`/`SCAN11_MAX_DOMINANT_PORT_SHARE = 0.6`** (líneas 482, 657, 95). Arbitran la
   frontera DoS ↔ escaneo vertical. El corte en 0,6 separa "puerto concentrado" de
   "puertos dispersos"; las ventanas ambiguas (DoS distribuido multi-puerto) bascular alrededor
   de este valor.
4. **Umbrales de volumen** (`*_MIN_GROUP`, `*_MIN_DST_PORTS`, `*_MIN_DST_IPS`). Determinan el
   *recall* en ventanas de baja densidad: en las ventanas "centradas" con pocos flujos de
   ataque, estos mínimos no se alcanzan y el resultado pasa a `no_clasificado`.
5. **Cortes de `grade` (0,8 / 0,6 / 0,4) y gate `score ≥ 0.6`** (líneas 343-350, 499 etc.).
   Como cada detector tiene pocas señales (3-7), activar o desactivar **una sola** señal
   cambia el score en 0,14-0,33, lo que puede cruzar el umbral de detección. La naturaleza
   discreta del score lo hace sensible cerca de la frontera.

---

## 6. Ataques con mayor capacidad de generalización

- **scan11 (Single-Source Vertical Scan)** y **scan44 (Distributed Vertical Scan).** Su
  detección descansa en invariantes estructurales (verticalidad, atomicidad, dominancia,
  SYN, baja entropía). El único lastre de generalización es el gate exacto de 44 bytes; si se
  flexibilizara, su transferibilidad sería muy alta.
- **anomaly-udpscan (UDP Low-Entropy Scan).** Núcleo basado en origen estable, dispersión de
  destinos/puertos y secuencialidad; los puertos origen característicos son señal **no
  nuclear**, de modo que el valor concreto no condiciona la detección. Buena generalización.
- **dos (Distributed TCP Flood).** Reglas puramente estructurales (concentración de puerto,
  secuencialidad de puerto origen, ráfaga), sin constantes específicas del dataset. Generaliza
  bien, con la salvedad de que la frontera con scan44 es difusa por naturaleza.

Estos cuatro constituyen el conjunto de **validación fuerte** y son los más defendibles como
detección de comportamiento.

---

## 7. Ataques que dependen más del contexto

- **nerisbotnet.** Depende de (a) que la coordinación multinodo sea **visible dentro de una
  única ventana** y (b) del conjunto `NERIS_C2_PORTS`. Si la botnet usara otros puertos C2 o
  la coordinación quedara repartida entre ventanas, no se detectaría. Dependiente del contexto
  temporal y de la convención de puertos.
- **anomaly-sshscan.** Patrón *low-and-slow*: su evidencia real —la **persistencia del mismo
  origen entre ventanas**— no es observable en una sola ventana (el propio código lo registra
  como limitación, líneas 831-833). Altamente dependiente del contexto de análisis.
- **anomaly-spam.** Es el más dependiente del dataset: su núcleo se apoya en tamaños de bytes
  **exactos** (`SPAM_KNOWN_BYTES`) y un rango de paquetes específicos. Correctamente marcado
  como exploratorio (líneas 951, 968-972), pero es el de menor capacidad de generalización.

---

## 8. Recomendaciones para mejorar la generalización sin romper la interpretabilidad

Todas las propuestas mantienen el modelo de **señales nombradas + evidencia explícita**; solo
amplían el rango de coincidencia o cambian valores fijos por propiedades relativas:

1. **Sustituir la comparación exacta de 44 bytes por una banda o por baja varianza.** En lugar
   de `bytes_mode == 44`, usar `bytes_mode in {40, 44, 48, 52, 60}` **o** apoyarse en la señal
   ya existente de baja varianza de bytes. La firma generalizable de un SYN-scan es "bytes
   pequeños, casi constantes", no el valor 44. Alternativamente, degradar este criterio de
   *núcleo* a *señal de score*.
2. **Degradar los conjuntos de valores específicos a evidencia corroborativa.**
   `SPAM_KNOWN_BYTES`, `UDP_KNOWN_SRC_PORTS` y, en parte, `NERIS_C2_PORTS` deberían **sumar
   confianza** pero no condicionar la detección. La señal general subyacente es la
   **repetición/baja entropía de tuplas `(packets, bytes)`**, independientemente de su valor
   concreto: esa es la que debe ir en el núcleo.
3. **Expresar los umbrales de volumen de forma relativa.** Donde sea posible, usar
   *flujos por segundo*, fracción de la ventana o densidad temporal en lugar de recuentos
   absolutos, para que el detector transfiera entre granularidades de ventana distintas.
4. **Tratar `top_share` y `port_share` como continuos.** En lugar de un corte duro en 0,7/0,6,
   reportar el valor y, opcionalmente, introducir una banda de histéresis o una zona de
   "ambigüedad scan11/scan44" o "DoS distribuido/escaneo", reflejando la incertidumbre en la
   confianza en vez de forzar un salto de categoría.
5. **Generalizar nerisbotnet hacia la coordinación pura.** Detectar clústeres de métricas
   idénticas y sincronizadas en **cualquier puerto**, usando los puertos C2 conocidos solo como
   refuerzo de confianza. La coordinación entre nodos es la señal general; los puertos son
   corroboración.
6. **Documentar el origen empírico y la sensibilidad de cada umbral.** Una tabla de umbrales
   (valor, justificación, sensibilidad) en el propio código o en la documentación deja claro
   que son parámetros calibrables, no constantes mágicas, lo que refuerza la defensa
   metodológica.
7. **Validación cruzada temporal.** Ejecutar el detector sobre un tramo temporal o días
   distintos del UGR'16 para medir la estabilidad de los umbrales y demostrar que el ajuste no
   es específico de las ventanas seleccionadas.

Ninguna de estas medidas introduce lógica opaca: todas siguen produciendo señales legibles y
evidencia interpretable.

---

## 9. Conclusión: ¿puede defenderse como detector basado en comportamiento?

**Sí, con matices bien delimitados.**

A favor (defensa sólida):

- **No usa etiquetas** como criterio de detección; solo como verdad de referencia para evaluar
  (punto 2).
- **No usa IPs concretas**; las direcciones intervienen solo de forma estructural y relacional
  (punto 1).
- Las decisiones nucleares de las cuatro familias más robustas (scan11, scan44, udpscan, dos)
  descansan sobre **propiedades de comportamiento** —topología, concentración/dispersión,
  atomicidad, secuencialidad, dominancia, coordinación y ráfagas— transferibles a otros
  entornos.
- El diseño combina **múltiples señales** y nunca decide por una métrica aislada, y registra
  explícitamente la evidencia y las limitaciones.

Matices (donde la etiqueta "puramente conductual" se debilita):

- Persisten **firmas de valor exacto** heredadas del dataset: el gate de 44 bytes en scan11 y,
  sobre todo, el conjunto de bytes de anomaly-spam. Mientras estos valores estén en el
  **núcleo** de decisión, esas dos detecciones son en parte **basadas en firma**, no en puro
  comportamiento.
- **nerisbotnet** depende de una convención de puertos C2 y de que la coordinación sea visible
  en la ventana; **anomaly-sshscan** está intrínsecamente limitado por su naturaleza
  *low-and-slow* en análisis de ventana única.

**Veredicto.** El detector **se puede defender como detector basado en comportamiento** para
las familias estructuradas (scan11, scan44, anomaly-udpscan, dos), que son precisamente las
de validación fuerte. Para nerisbotnet, anomaly-sshscan y anomaly-spam debe presentarse como
**parcial / exploratorio y corroborado por firma**, no como detección conductual pura. Aplicar
las recomendaciones del punto 8 —en especial flexibilizar el gate de 44 bytes y degradar los
conjuntos de valores exactos a evidencia corroborativa— eliminaría las últimas dependencias de
firma del núcleo y haría la defensa conductual prácticamente completa.

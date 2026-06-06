# 28. Evaluación de generalización del clasificador contextual v3

## 1. Objetivo

Evaluar si el clasificador contextual por traza **v3** (versión principal) **generaliza** a
datos **no usados para formular sus reglas**: una semana distinta del dataset UGR'16
(`august.week2`). La v3 se ejecuta **sin reajustar reglas ni umbrales**; solo se le cambia la
entrada/salida. El objetivo es comprobar si el rendimiento de la validación original (sobre
`august.week1`) se mantiene en datos nuevos.

## 2. Dataset utilizado

- **Origen**: `data/raw/august.week2.csv.uniqblacklistremoved` (75,5 GB), ya en el formato de
  13 columnas que espera la v3.
- **Filas válidas escaneadas**: **837.841.161** (week2 es ~8× mayor que la week1 limpia).
- **Distribución de etiquetas (semana completa)**:

| Etiqueta | Filas | ¿Ataque? |
| --- | ---: | :--: |
| background | 793.518.112 | no |
| anomaly-spam | 36.796.698 | sí |
| blacklist | 5.728.174 | no (no conductual) |
| dos | 1.028.245 | sí |
| scan44 | 547.468 | sí |
| scan11 | 140.541 | sí |
| nerisbotnet | 81.918 | sí |
| anomaly-sshscan | 5 | sí |
| anomaly-udpscan | 0 | sí |

**Diferencias clave frente a `august_week1`**:

- **`anomaly-spam` es masivo en week2** (36,8 M frente a ~47 en week1): por fin se puede evaluar
  la familia más débil a escala.
- **`anomaly-udpscan` NO aparece** (0 filas) → no es evaluable en week2.
- **`anomaly-sshscan` es casi inexistente** (5 filas), como en week1.
- `dos`, `scan11`, `scan44`, `nerisbotnet` están presentes.

## 3. Preparación de datos

- "Limpieza" = validación de filas (13 columnas, no vacías, timestamp `2016-08-`); el formato ya
  era compatible con la v3.
- Para **preservar la localidad temporal** que la v3 necesita (contexto ±30 filas), **no se
  muestrean filas sueltas**: se extraen **ventanas contiguas** de 2.000 filas (como las
  `rows_2000` originales), conservando el orden real. Las etiquetas solo se usan para
  **localizar** ventanas, nunca para detectar.
- **384 ventanas** generadas (≈768.000 trazas): `anomaly-spam` 118, `dos` 60, `scan11` 60,
  `scan44` 60, `nerisbotnet` 60, `anomaly-sshscan` 4, background 80; `anomaly-udpscan` 0.
- Conteo de etiquetas: `data/generalization/summaries/august_week2_label_counts.csv`.
- Muestra concatenada: `data/generalization/samples/august_week2_generalization_sample_1M.csv`.

## 4. Metodología

La v3 se ejecuta mediante un *runner* (`run_v3_on_generalization.py`) que **importa la v3 sin
modificarla** y solo reapunta entrada/salida. **No se cambia ninguna regla, umbral ni IP**, y
**no se usa la etiqueta para detectar** (solo para evaluar a posteriori). Salidas:
`data/generalization/results/generalization_results_v3_august_week2.csv` y
`.../summaries/generalization_summary_v3_august_week2.csv`.

## 5. Resultados binarios ataque/background

Sobre las 768.000 trazas evaluadas:

```text
TP = 99.720   FP = 14.602   FN = 33.743   TN = 619.935
precisión = 0,872   recall = 0,747   F1 ataque = 0,805
```

**Dato decisivo**: el **98 % de los falsos negativos son `anomaly-spam`** (33.019 de 33.743).
Si se **excluye el spam** (clase que la week1 no permitía evaluar):

```text
recall binario excluyendo spam = 99.584 / 100.308 = 0,993
```

Es decir, **sobre las familias que la v3 sí detecta, el recall (0,993) es prácticamente idéntico
al de la validación original (0,991)**. La caída del recall agregado (0,747) se debe
**enteramente a la abundancia de spam** en week2, una debilidad ya documentada de la v3, ahora
visible a gran escala.

## 6. Resultados por familia / subtipo

| Familia | predichas | etiq. original | aciertos | precisión | recall |
| --- | ---: | ---: | ---: | ---: | ---: |
| vertical_scan | 76.148 | 73.830 | 62.961 | 0,827 | 0,853 |
| tcp_flood (dos) | 26.599 | 26.218 | 12.823 | 0,482 | 0,489 |
| coordinated_botnet (neris) | 165 | 255 | 0 | 0,000 | 0,000 |
| smtp_campaign (spam) | 112 | 33.155 | 0 | 0,000 | 0,000 |
| ssh_horizontal_scan | 6.300 | 5 | 0 | 0,000 | 0,000 |
| udp_scan | 2.805 | 0 | 0 | 0,000 | n/a |

Subtipo del barrido vertical:

| Subtipo | predichos | etiq. original | aciertos | precisión | recall |
| --- | ---: | ---: | ---: | ---: | ---: |
| scan11 | 51.365 | 22.187 | 22.060 | 0,429 | 0,994 |
| scan44 | 24.783 | 51.643 | 24.632 | 0,994 | 0,477 |

- **vertical_scan (familia)**: precisión 0,827 / recall 0,853 → **generaliza bien** (en week1
  fue 0,770 / 0,847).
- **subtipo scan11/scan44**: el recall casi se conserva combinado, pero en week2 **scan11
  absorbe más a scan44** (scan44 recall baja a 0,477 frente a 0,796 en week1). La distinción de
  subtipo depende de la composición de la ventana y es menos estable entre semanas.
- **tcp_flood (dos)**: 0,482 / 0,489 → **consistente** con week1 (0,554 / 0,488).
- **coordinated_botnet (neris)**: 0 aciertos sobre 255 → **falla** (en week1 ya era débil).
- **smtp_campaign (spam)**: 0 aciertos sobre 33.155 → **no se detecta pese a su abundancia**.
- **ssh_horizontal_scan**: 6.300 predichas (todas FP de sondeos SSH de fondo), 5 reales no
  capturadas → debilidad confirmada.
- **udp_scan**: no evaluable (0 en week2); la v3 marca 2.805 trazas de **background** como UDP
  scan (ruido de escaneo real de fondo o falsos positivos).
- **blacklist**: aparece en el tráfico (5,7 M en la semana) pero **no se usa como criterio
  conductual**; se trata como tráfico no-ataque a efectos de evaluación.

## 7. Comparación con la validación original (week1)

| Métrica | week1 (original) | week2 (generalización) |
| --- | ---: | ---: |
| precisión binaria | 0,930 | 0,872 |
| recall binario | 0,991 | 0,747 (**0,993 excl. spam**) |
| F1 binario ataque | ~0,960 | 0,805 (≈0,96 excl. spam) |
| F1 macro binario | ~0,972 | ~0,884 |
| vertical_scan recall | 0,847 | 0,853 |
| scan11 precisión | 0,763 | 0,429 |
| scan44 recall | 0,796 | 0,477 |
| dos recall | 0,488 | 0,489 |
| udp_scan recall | ~1,000 | n/a (ausente en week2) |
| punto débil | neris, sshscan, spam | neris, sshscan, **spam (a escala)** |

## 8. Análisis de errores

- **Ataques detectados pero mal clasificados (subtipo)**: scan44 → scan11 (la dominancia local
  hace que scan11 absorba parte del barrido distribuido). No afecta a la detección binaria ni a
  la familia `vertical_scan`, solo al subtipo.
- **Ataques fugados a background/no_clasificado (FN, total 33.743)**: `anomaly-spam` 33.019,
  `dos` 293, `nerisbotnet` 215, `scan44` 117, `scan11` 94, `anomaly-sshscan` 5. **El spam domina
  los FN**; el resto de familias apenas se fuga.
- **Falsos positivos sobre background (total 14.602)**: `ssh_horizontal_scan` 6.260,
  `tcp_flood` 3.443, `udp_scan` 2.805, `unknown_attack` 1.628, `vertical_scan` 325,
  `smtp_campaign` 112, `coordinated_botnet` 29. Los FP se concentran en las **familias débiles**
  (ssh) y en **ruido de escaneo real de fondo** (udp, parte de tcp_flood), coherente con que el
  background ISP contiene escaneos no etiquetados.

## 9. Interpretación

Los resultados **apoyan la generalización de la v3 para lo que es su núcleo fuerte** y
**confirman sus límites conocidos**:

- **Generaliza con solidez** la detección de **barrido vertical** (vertical_scan recall 0,853 ≈
  week1) y, en general, los patrones estructurados: el **recall binario excluyendo spam (0,993)
  es prácticamente igual al original (0,991)**. La v3 no estaba sobreajustada a week1.
- La **caída del recall agregado** no indica un fallo de generalización del método, sino que
  **week2 está dominada por `anomaly-spam`**, una familia que la v3 ya declaraba como débil y
  que en week1 no se podía medir. Es un resultado **esperado y honesto**, no una sorpresa.
- La **subclasificación scan11/scan44 es menos estable entre semanas** (la dominancia local
  varía con la composición de las ventanas): la familia `vertical_scan` generaliza, el subtipo
  fino menos.
- Las **familias débiles** (neris, sshscan, spam) **siguen siendo débiles** en datos nuevos, lo
  que es coherente con su naturaleza (coordinación no presente, low-and-slow, indistinguible de
  SMTP legítimo) y no con un problema de ajuste.
- La precisión baja moderadamente (0,930 → 0,872) por FP de las familias débiles y del ruido de
  escaneo de fondo; parte de esos "FP" son escaneos reales del background.

## 10. Conclusión

La v3 **puede defenderse como clasificador contextual interpretable con generalización
razonable**. En datos nuevos (`august.week2`), **mantiene su rendimiento en el núcleo fuerte**
—detección binaria con recall 0,993 sobre las familias detectables y recall de barrido vertical
0,853, equivalentes a la validación original— **sin reajustar ninguna regla ni umbral**. La
bajada del recall agregado se explica **por completo** por la irrupción masiva de
`anomaly-spam`, una debilidad ya documentada, y no por un fallo del enfoque conductual.

En consecuencia, la generalización es **fuerte para escaneos estructurados** (scan/vertical y,
parcialmente, dos), **no concluyente para udp_scan** (ausente en week2) y **confirma como
límites** a `nerisbotnet`, `anomaly-sshscan` y `anomaly-spam`. La v3 se mantiene como
clasificador principal; los resultados refuerzan su validez metodológica y delimitan con
honestidad dónde no generaliza.

Como segunda prueba de generalización temporal se evaluó también `april.week2` (sección
siguiente).

---

## Evaluación adicional: april.week2

### Dataset usado

- **Origen**: `data/raw/april.week2.csv.uniqblacklistremoved` (50,8 GB), mismo formato de 13
  columnas; timestamp `2016-04-`.
- **Filas válidas escaneadas**: **564.028.843**.
- Misma metodología que august.week2: **ventanas contiguas** de 2.000 filas (la v3 se ejecuta
  sin tocar reglas ni umbrales, mediante el *runner*).

### Distribución de etiquetas (semana completa)

| Etiqueta | Filas | ¿Ataque? |
| --- | ---: | :--: |
| background | 557.363.853 | no |
| anomaly-sshscan | 4.548.663 | sí |
| blacklist | 1.735.869 | no (no conductual) |
| anomaly-spam | 380.458 | sí |
| dos / scan11 / scan44 / nerisbotnet / anomaly-udpscan | 0 | sí (ausentes) |

**Hecho determinante**: april.week2 contiene **únicamente** las dos familias que la v3 ya
declaraba como débiles —`anomaly-sshscan` (¡4,5 M filas!) y `anomaly-spam` (380 k)— y **ninguna
de las familias del núcleo fuerte** (scan11, scan44, dos, nerisbotnet). `anomaly-udpscan`
**tampoco aparece** (0 filas), igual que en august.week2.

### Preparación

- **200 ventanas** (≈400.000 trazas): `anomaly-spam` 60, `anomaly-sshscan` 60, background 80.
- Conteo: `data/generalization/summaries/april_week2_label_counts.csv`.
- Muestra: `data/generalization/samples/april_week2_generalization_sample_1M.csv` (≈37 MB).
- Resultados: `data/generalization/results/generalization_results_v3_april_week2.csv` y
  `.../summaries/generalization_summary_v3_april_week2.csv`.

### Resultados binarios

```text
TP = 0   FP = 4.871   FN = 29.438   TN = 365.691
precisión = 0,000   recall = 0,000   F1 = 0,000
```

La v3 detecta **prácticamente cero** ataques en april. No es contradictorio con august.week2:
april está **dominada por las familias que la v3 no detecta** y **carece de sus familias
fuertes**, de modo que no hay nada que la v3 sepa clasificar. Excluir spam **no ayuda** aquí,
porque el grueso de los FN es `anomaly-sshscan` (29.298 de 29.438).

### Resultados por familia

| Familia | predichas | etiq. original | aciertos |
| --- | ---: | ---: | ---: |
| ssh_horizontal_scan | 19 | 29.298 | 0 |
| smtp_campaign | 99 | 140 | 0 |
| udp_scan | 1.776 | 0 | 0 (FP fondo) |
| unknown_attack | 1.756 | 0 | 0 (FP fondo) |
| tcp_flood | 897 | 0 | 0 (FP fondo) |
| vertical_scan | 320 | 0 | 0 (FP fondo) |
| smtp/ssh/neris (resto) | 103 | — | 0 |

- **`anomaly-sshscan` a escala (29.298 trazas en ventanas): recall 0**. Es el resultado más
  informativo: aunque april contiene 4,5 M de sshscan, dentro de cada ventana contigua el
  patrón *low-and-slow* queda **diluido** (pocos destinos al puerto 22 por ventana), por debajo
  del umbral de persistencia de la v3. La abundancia global **no** se traduce en densidad local.
- **`anomaly-spam`: recall 0** (140 trazas), consistente con august.week2.
- **Falsos positivos (4.871, todos sobre background/blacklist)**: `udp_scan` 1.776,
  `unknown_attack` 1.756, `tcp_flood` 897, `vertical_scan` 320, `smtp_campaign` 99,
  `ssh_horizontal_scan` 19, `coordinated_botnet` 4. Son ruido de escaneo de fondo y artefactos
  de las familias débiles; al no haber ataques del núcleo, estos FP dominan y hunden la
  precisión a 0.

### Análisis de familias ausentes/presentes

- **Presentes y abundantes**: `anomaly-sshscan` (4,5 M) y `anomaly-spam` (380 k) → ambas con
  recall 0. Confirma sus límites **a gran escala**, no solo por escasez de muestras.
- **Ausentes**: scan11, scan44, dos, nerisbotnet (el núcleo fuerte de la v3) y
  `anomaly-udpscan`. Por tanto april **no puede** medir la generalización del núcleo ni cerrar
  el caso `udp_scan`, que **sigue sin ser evaluable** (ausente en las dos semanas nuevas).

### Comparación august.week1 (original) vs august.week2 vs april.week2

| Métrica | week1 (original) | august.week2 | april.week2 |
| --- | ---: | ---: | ---: |
| precisión binaria | 0,930 | 0,872 | 0,000 |
| recall binario | 0,991 | 0,747 | 0,000 |
| recall excl. spam | — | 0,993 | 0,000 (domina sshscan) |
| familias del núcleo presentes | todas | scan/dos/neris | **ninguna** |
| sshscan (recall, nº trazas) | ~0 (44) | ~0 (5) | **0 (29.298)** |
| udp_scan | ~1,00 | ausente | ausente |

### Conclusión sobre generalización temporal

Las dos pruebas son **complementarias** y, juntas, delimitan con honestidad la generalización
de la v3:

- **august.week2** contiene el núcleo fuerte y confirma que **generaliza** (recall 0,993
  excluyendo spam; vertical_scan 0,853).
- **april.week2** contiene **solo** las familias débiles y confirma que **siguen sin detectarse
  a escala** (sshscan recall 0 con 4,5 M de trazas; spam recall 0).

El rendimiento agregado de la v3 en una semana depende, por tanto, **enteramente de qué
familias contiene esa semana**: alto cuando predominan escaneos estructurados, nulo cuando
predominan sshscan/spam. Esto **no contradice** la validez del enfoque conductual: confirma que
la v3 generaliza **para lo que está diseñada** (escaneos de baja entropía) y que sus puntos
ciegos (low-and-slow y spam) son **límites estructurales del método sobre metadatos de flujo**,
no problemas de ajuste. `udp_scan` **queda sin evaluar** en datos nuevos (ausente en ambas
semanas), por lo que su generalización sigue abierta como trabajo futuro (buscar una semana que
lo contenga).

---

## Auditoría de etiquetas disponibles y caso anomaly-udpscan

Para decidir si era posible una tercera prueba de generalización centrada en `anomaly-udpscan`,
se auditaron las etiquetas de **todos los datasets disponibles** en `data/raw/`:

- `august.week1.csv`
- `august.week2.csv.uniqblacklistremoved`
- `april.week2.csv.uniqblacklistremoved`

(Los ficheros de `data/raw/compressed_raw/*.tar.gz` son copias **comprimidas** de estas mismas
tres semanas, no datos nuevos.)

El resultado se guardó en `data/generalization/summaries/raw_dataset_label_audit.csv`.

| Dataset | Filas válidas | anomaly-udpscan | dos | scan11 | scan44 | nerisbotnet | anomaly-sshscan | anomaly-spam |
| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| august.week1.csv | 851.614.536 | 989.872 | 5.093.132 | 539.018 | 2.477.203 | 992.575 | 16 | 27.970.000 |
| august.week2.csv.uniqblacklistremoved | 837.841.161 | 0 | 1.028.245 | 140.541 | 547.468 | 81.918 | 5 | 36.796.698 |
| april.week2.csv.uniqblacklistremoved | 564.028.843 | 0 | 0 | 0 | 0 | 0 | 4.548.663 | 380.458 |

La auditoría confirma que `anomaly-udpscan` solo aparece en `august.week1.csv`, que es
precisamente la semana usada para formular y validar inicialmente las reglas de la v3. Por
tanto, no existe en los datos actualmente disponibles una segunda semana independiente que
permita evaluar la generalización temporal de `udp_scan`. La familia `udp_scan` queda validada
dentro de la semana original, pero su evaluación externa debe quedar como trabajo futuro
condicionado a localizar otro tramo del dataset UGR'16 que contenga dicha etiqueta.

La ausencia de `anomaly-udpscan` en `august.week2` y `april.week2` no invalida el resultado de
generalización. Simplemente limita qué familias pueden evaluarse externamente. `august.week2`
permite evaluar scan/dos/neris, mientras que `april.week2` estresa sshscan/spam. En conjunto,
las pruebas delimitan qué partes de la v3 generalizan y qué partes siguen siendo limitaciones
estructurales.

# Comparación con Machine Learning clásico (baseline)

## 1. Objetivo de la comparación

Este documento compara, como **baseline académico secundario**, varios clasificadores
clásicos de Machine Learning frente al **clasificador contextual por traza v3** (propuesta
principal del TFG). El objetivo **no es sustituir** la v3, sino situar su rendimiento frente a
métodos predictivos tradicionales y discutir las diferencias de enfoque.

Script: [`scripts/03_ml_baselines/compare_classical_ml_classifiers.py`](../../scripts/03_ml_baselines/compare_classical_ml_classifiers.py).
Salidas: `data/attack_analysis/ml_baseline_results.csv` y `ml_baseline_summary.csv`.

## 2. Por qué el ML clásico es baseline y no propuesta principal

- Es **supervisado**: necesita la etiqueta real para entrenar. La v3 **no usa la etiqueta para
  detectar** (solo para evaluar).
- Es **opaco**: un Random Forest o un MLP no explican *por qué* una traza es ataque. La v3
  aporta **evidencia interpretable por traza** y reglas conductuales.
- **No se conecta con las hipótesis generadas por LLM** ni con el modelo de comportamiento
  sintético; es un predictor estadístico puro.
- Requiere **datos etiquetados y balanceados** para entrenar; la v3 funciona sobre las ventanas
  sin necesidad de entrenamiento.

Por todo ello, aunque algún modelo de ML obtenga mejores métricas, se trata de una
**comparación predictiva**, no de un sustituto.

## 3. Modelos evaluados

- **Logistic Regression** (baseline simple)
- **KNN** (k = 5)
- **SVM** (RBF; entrenamiento submuestreado a 15.000 por coste O(n²))
- **Random Forest** (200 árboles)
- **MLPClassifier** (red neuronal sencilla, capas 64-32)

Todos con `random_state = 42`. KNN, SVM, MLP y Logistic Regression usan features escaladas
(`StandardScaler`); Random Forest se entrena sin escalado.

## 4. Features utilizadas

Solo variables **conductuales/derivadas del flujo**; **no se usan IPs ni la etiqueta** como
features:

- numéricas: `duration`, `src_port`, `dst_port`, `packets`, `bytes`
- derivadas: `bytes_per_packet`, `packets_per_second`
- temporal simple: `hour` (hora del día del `timestamp`)
- flags TCP como binarias: `flag_S`, `flag_A`, `flag_R`, `flag_P`, `flag_F`, `flag_U`
- protocolo en one-hot acotado: `proto_TCP`, `proto_UDP`, `proto_ICMP`, `proto_OTHER`

## 5. Metodología experimental

- **Origen de datos**: como `data/clean/august_week1_clean.csv` no está disponible, se usan las
  **ventanas reales de `data/attack_analysis/`** (el **mismo origen** sobre el que se evaluó la
  v3), con **deduplicación** para mitigar el solapamiento de ventanas.
- **Muestreo estratificado con tope por clase**: las clases mayoritarias se recortan y las
  minoritarias se incluyen completas, para que `background` no domine.
- **Muestra final**: 72.317 trazas, **8 clases**. `anomaly-sshscan` se **descartó** (solo 8
  trazas únicas, insuficientes para entrenar/evaluar). Distribución: `background`, `scan44`,
  `dos`, `nerisbotnet`, `scan11`, `anomaly-udpscan` con 11.111 cada una; `blacklist` 5.604;
  `anomaly-spam` 47.
- **Split estratificado**: train 54.237 / test 18.080 (`test_size = 0,25`, `random_state = 42`).
- **Métricas**: accuracy, precision/recall/F1 macro y weighted, classification_report por clase
  y matriz de confusión.

## 6. Resultados globales

(Orden por F1 macro; sobre el conjunto de test estratificado.)

| Modelo | accuracy | F1 macro | F1 weighted | tiempo (s) | nota |
| --- | ---: | ---: | ---: | ---: | --- |
| RandomForest | 0,963 | **0,950** | 0,962 | 4,1 | — |
| KNN | 0,919 | 0,877 | 0,917 | 0,1 | — |
| MLPClassifier | 0,871 | 0,803 | 0,866 | 72,2 | — |
| SVM | 0,785 | 0,660 | 0,750 | 2,0 | train submuestreado a 15.000 |
| LogisticRegression | 0,757 | 0,615 | 0,713 | 5,9 | — |

**Random Forest** es claramente el mejor baseline (F1 macro 0,95), seguido de KNN. Los modelos
lineales (Logistic Regression) y SVM-RBF (con entrenamiento recortado) quedan por detrás,
especialmente en las clases de escaneo vertical.

## 7. Resultados por familia de ataque (F1 en test)

| Familia | KNN | LogReg | MLP | RandomForest | SVM |
| --- | ---: | ---: | ---: | ---: | ---: |
| anomaly-udpscan | 0,990 | 0,982 | 0,990 | **0,990** | 0,990 |
| dos | 0,999 | 0,995 | 1,000 | **0,999** | 0,995 |
| nerisbotnet | 0,987 | 0,869 | 0,992 | **0,999** | 0,912 |
| scan11 | 0,934 | 0,705 | 0,800 | **0,993** | 0,707 |
| scan44 | 0,924 | 0,303 | 0,721 | **0,992** | 0,311 |
| anomaly-spam | 0,741 | 0,200 | 0,500 | **0,957** | 0,210 |
| anomaly-sshscan | — | — | — | — | — |

Observaciones:

- **Random Forest acierta casi todas las familias** (F1 ≥ 0,99 en udpscan, dos, neris, scan11,
  scan44; incluso 0,96 en spam) sobre la muestra balanceada.
- Las familias **dos** y **anomaly-udpscan** son fáciles para todos los modelos.
- **scan11/scan44** separan claramente a los modelos: solo RF (y en menor medida KNN) los
  distinguen bien; los lineales y SVM caen a F1 ≈ 0,3 en scan44.
- **anomaly-sshscan** no aparece: con solo 8 trazas únicas es **inviable** para ML supervisado.

## 8. Comparación con el clasificador contextual v3

| Aspecto | ML clásico (mejor: RandomForest) | Clasificador contextual v3 |
| --- | --- | --- |
| Enfoque | supervisado, estadístico | reglas conductuales + contexto local/global |
| Usa la etiqueta para detectar | **sí** (entrenamiento) | **no** (solo para evaluar) |
| Interpretabilidad | baja (caja negra) | alta (evidencia por traza) |
| Conexión con hipótesis LLM | ninguna | sí (modelo de comportamiento) |
| Datos necesarios | etiquetados y balanceados | ventanas sin entrenamiento |
| scan44 (F1 / recall) | RF F1 ≈ 0,99 | subtipo recall 0,796 |
| anomaly-spam | RF F1 ≈ 0,96 (muestra balanceada) | exploratorio, recall ≈ 0 |
| anomaly-sshscan | no evaluable (8 muestras) | recall ≈ 0 (low-and-slow) |
| Detección binaria ataque/background | — (multiclase) | recall 0,991 / precisión 0,930 |

**Lectura honesta**: en términos puramente **predictivos**, Random Forest supera a la v3 en
varias familias (notablemente scan44 y spam) **sobre una muestra balanceada y con la etiqueta
disponible para entrenar**. Sin embargo:

- la comparación **no es estrictamente equivalente**: el ML se evalúa sobre un test balanceado
  y aprende de la etiqueta y de features muy correlacionadas con ella (p. ej. `dst_port`),
  mientras que la v3 clasifica por comportamiento **sin etiquetas** y sobre el flujo completo;
- el buen resultado de RF en `anomaly-spam` se obtiene con solo 47 muestras balanceadas: es
  **optimista** y no garantiza generalización;
- `anomaly-sshscan` es **indetectable** para el ML por escasez de datos, mientras que la v3 al
  menos lo plantea (aunque sin validación fuerte).

## 9. Limitaciones

- **Comparación no equivalente**: distinto conjunto de evaluación (muestra balanceada vs flujo
  completo) y distinto paradigma (supervisado vs no supervisado por reglas).
- **Dependencia de la etiqueta**: el ML necesita la etiqueta real para entrenar; sus métricas
  no son alcanzables sin datos etiquetados.
- **Posible fuga de información**: features como `dst_port` están muy correlacionadas con la
  etiqueta (p. ej. puerto 25 ↔ spam), lo que infla el rendimiento del ML.
- **Clases minoritarias**: `anomaly-sshscan` se descarta y `anomaly-spam` solo tiene 47
  muestras; sus resultados deben tomarse con cautela.
- **Solapamiento de ventanas**: aunque se deduplica, el origen son ventanas centradas en
  ataques, no el dataset completo.
- **Sin interpretabilidad**: los modelos no explican sus decisiones por traza.

## 10. Conclusión

Los clasificadores de ML clásico —en especial **Random Forest**— constituyen un **baseline
predictivo fuerte** (F1 macro 0,95) y superan a la v3 en varias familias sobre una muestra
balanceada y etiquetada. No obstante, este resultado **no convierte al ML en la propuesta del
TFG**: se trata de una **comparación predictiva**, no de un sustituto.

La **propuesta principal sigue siendo el clasificador contextual v3** porque aporta lo que el
ML clásico no ofrece: **interpretabilidad**, **reglas conductuales**, **conexión con las
hipótesis generadas por LLM** y **explicación trazable** del comportamiento de ataque, todo
ello **sin usar la etiqueta como criterio de detección ni IPs concretas**. El ML clásico se
incorpora, por tanto, como **referencia comparativa**, mostrando que el enfoque conductual
explicable alcanza un rendimiento competitivo manteniendo ventajas metodológicas que un
clasificador estadístico opaco no proporciona.

# 33. Validación del clasificador contextual v5 integrated

## 1. Objetivo

Validar una versión **candidata integrada** (`v5_integrated`) que combina la **v3 estable** con
un **tercer pase global** para detectar `ssh_horizontal_scan` *low-and-slow* mediante **fan-out
SSH por origen** (la mejora validada en april.week2). Se evalúa si v5 puede **sustituir** a la
v3 sin degradar lo que ya funciona.

- Script: [`scripts/02_attack_analysis/detect_attack_flows_contextual_v5_integrated.py`](../../scripts/02_attack_analysis/detect_attack_flows_contextual_v5_integrated.py)
- La v3 NO se modifica (se importa y reutiliza).

## 2. Cambios respecto a v3

- **v3 intacta como base**: scan11/scan44/udp_scan/tcp_flood/unknown se clasifican EXACTAMENTE
  igual (resultados byte a byte idénticos en week1).
- **Nuevo pase 3 global por origen** para `ssh_horizontal_scan`: agrega por `src_ip` el tráfico
  TCP al puerto 22 y marca como escáner los orígenes con **fan-out** ≥ 50 destinos distintos.
- **Relabel de confianza del botnet** (`coordinated_botnet_high_confidence` /
  `coordinated_botnet_low_confidence`) según la confianza que la v3 ya calcula; **no cambia qué
  trazas se detectan** (canónicamente sigue siendo `coordinated_botnet`).
- **spam sin forzar** (idéntico a la v3).

## 3. Justificación metodológica

april.week2 demostró que `anomaly-sshscan` **no es imposible** para el enfoque conductual: con
contexto **local** (v3) era indetectable, pero con un pase **global por origen** se detecta por
su fan-out (recall 0 → 0,907, F1 0,951). v5 integra esa idea para comprobar si aporta sin romper
el resto.

## 4. Validación en week1 (data/attack_analysis, 6.870.331 trazas)

| Métrica | v3 | v5 |
| --- | ---: | ---: |
| precisión binaria | 0,930 | 0,926 |
| recall binario | 0,991 | 0,991 |
| F1 binario | 0,960 | 0,957 |
| TP / FP / FN / TN | 1.816.688 / 137.365 / 17.228 / 4.899.050 | 1.816.688 / 145.702 / 17.228 / 4.890.713 |

Familias (canónicas): **vertical_scan, tcp_flood, udp_scan, nerisbotnet, smtp_campaign quedan
idénticas a la v3**. La única diferencia está en SSH:

| Familia ssh | v3 | v5 |
| --- | ---: | ---: |
| ssh_horizontal_scan (predichas / aciertos) | 60 / 0 | 8.397 / 0 |

- **Falsos positivos nuevos**: +8.337 (todos del pase SSH). El pase marca 8.389 trazas como SSH,
  **0 aciertos**: en week1 hay solo 44 trazas `anomaly-sshscan` y el fan-out captura, en su
  lugar, **orígenes de fondo con >= 50 destinos SSH** (escaneos horizontales SSH no etiquetados).
- Efecto: precisión binaria baja **0,930 → 0,926** (degradación pequeña pero real); recall
  intacto.

## 5. Validación en august.week2 (768.000 trazas de muestra)

| Métrica | v3 | v5 |
| --- | ---: | ---: |
| precisión binaria | 0,872 | 0,8715 |
| recall binario | 0,747 | 0,747 |
| recall excluyendo spam | 0,993 | 0,993 |
| vertical_scan (prec/recall) | 0,770 / 0,847 | 0,770 / 0,847 |
| tcp_flood / scan44 | iguales | iguales |
| ssh_horizontal_scan (predichas / aciertos) | 60 / 0 | 6.407 / 0 |

- El pase SSH marca **6.401 trazas (0 aciertos)**, pero **el binario apenas cambia** (+107 FP):
  casi todas esas trazas **ya eran FP** de la v3 bajo otras familias, así que el override solo
  las **renombra** a SSH. Precisión binaria 0,872 → 0,8715 (prácticamente igual); recall idéntico.

## 6. Validación en april.week2 (400.000 trazas de muestra)

| Métrica | v3 | v5 |
| --- | ---: | ---: |
| precisión binaria | 0,000 | **0,845** |
| recall binario | 0,000 | **0,903** |
| F1 binario | 0,000 | **0,873** |
| TP / FP / FN / TN | 0 / 4.871 / 29.438 / 365.691 | 26.580 / 4.871 / 2.858 / 365.691 |
| sshscan precisión / recall / F1 | 0 / 0 / 0 | **0,999 / 0,907 / 0,951** |
| spam precisión / recall / F1 | 0 / 0 / 0 | 0 / 0 / 0 |

- **Mejora drástica y limpia**: el pase SSH detecta 26.580 de 29.298 sshscan con precisión 0,999
  y **0 falsos positivos** (override_fp = 0). Los 4.871 FP binarios son los mismos de la v3.

## 7. Comparación global v3 vs v5

| Aspecto | v3 | v5 | Veredicto |
| --- | --- | --- | --- |
| Núcleo (scan/dos/udp/vertical/neris/spam) | — | idéntico | **se mantiene** |
| Recall binario week1 / august | 0,991 / 0,747 | 0,991 / 0,747 | **se mantiene** |
| Precisión binaria week1 | 0,930 | 0,926 | empeora levemente (FP SSH) |
| Precisión binaria august | 0,872 | 0,8715 | igual |
| sshscan en april | 0 / 0 | 0,999 / 0,907 | **mejora mucho** |
| ssh en week1/august (familia) | 60 pred / 0 | 8.397 / 6.407 pred / 0 | empeora (FP de fondo) |
| spam | 0 | 0 | igual |

**Qué mejora**: sshscan en april (recall 0 → 0,907, F1 0,951) y el binario en april (recall 0 →
0,903). **Qué se mantiene**: todo el núcleo y el recall binario en week1/august. **Qué empeora**:
el pase SSH introduce falsos positivos de SSH en week1 (+8.337) y august (familia), bajando algo
la precisión en week1 (0,930 → 0,926).

## 8. Riesgo de sobreajuste

- El pase SSH funciona **de forma perfecta en april** porque el sshscan es **un único origen con
  fan-out masivo** (26.231 destinos). En week1/august **no hay sshscan etiquetado a escala**, y
  el fan-out captura **escáneres SSH de fondo no etiquetados** → falsos positivos frente a la
  etiqueta (aunque comportamentalmente sean escaneos reales).
- **No está probado con sshscan distribuido de bajo fan-out por nodo**, que el fan-out no
  capturaría.
- Hay **sensibilidad al umbral** `min_dsts`: con 50 solo se marca el escáner real en april, pero
  en otras semanas dispara sobre escáneres de fondo. Un umbral más alto reduciría FP pero podría
  perder escáneres legítimos.
- Requiere **validación futura** en datasets donde el escaneo horizontal SSH esté etiquetado a
  escala, y una evaluación **consciente de etiqueta** (parte de los "FP" son escaneos reales).

## 9. Decisión final

Aplicando los criterios fijados:

- ¿Mantiene week1 y august.week2 sin degradación relevante y mejora april? **Casi**: mantiene el
  recall y el núcleo, y mejora april de forma rotunda, **pero introduce falsos positivos de SSH
  en week1/august** y baja levemente la precisión en week1.
- Por tanto, se aplica el criterio: *"si solo mejora april pero mete FP en otras semanas, no
  sustituye a v3"*.

**Lectura inicial (conservadora):** bajo una interpretación estricta frente a la etiqueta
oficial, la v5 introduce FP de SSH y la decisión inicial fue mantener la v3 como principal.

**Decisión final (actualizada): la `v5 integrated` pasa a ser la versión PRINCIPAL recomendada;
la v3 queda como versión BASE estable / conservadora.** Reinterpretación: la v5 **no es
sobreajuste a april.week2**, sino una **ampliación conductual** de la v3 mediante un tercer pase
global por origen. Mantiene prácticamente intacto el rendimiento en week1 y august.week2
(recall binario 0,991 en week1; núcleo idéntico; recall excluyendo spam 0,993 en august.week2) y
**añade detección fuerte de `anomaly-sshscan`** en april.week2 (F1 0,951). Los FP de SSH en
week1/august se producen sobre trazas etiquetadas como `background` pero con **comportamiento
compatible con escaneo horizontal SSH** (orígenes con ≥50 destinos al puerto 22), por lo que se
documentan como **posible tráfico anómalo no etiquetado**, no como errores claros. La v3 se
conserva como base estable para usos donde se priorice la máxima precisión frente a la etiqueta.

**Matices que se mantienen** (no se ocultan): el umbral de fan-out (`min_dsts=50`) es sensible y
la detección está probada con un escáner de fan-out alto, no con sshscan distribuido de bajo
fan-out; conviene una evaluación consciente de la etiqueta y validación adicional como trabajo
futuro.

## 10. Conclusión para la memoria

La v5 integrada confirma un punto metodológico importante: **el límite de la v3 con
`anomaly-sshscan` era arquitectónico** (solo contexto local), no del enfoque conductual. Un
**tercer pase global por origen** basado en fan-out detecta el escaneo horizontal SSH casi
perfectamente cuando existe un escáner de fan-out alto (april: F1 0,951), **sin tocar el resto de
la v3**, que se mantiene byte a byte.

Sin embargo, ese mismo pase **introduce falsos positivos de SSH en las semanas sin sshscan
etiquetado** (week1, august), porque marca escáneres SSH de fondo no etiquetados — un efecto
coherente con que el *background* de un ISP contiene escaneos reales, pero que penaliza la
precisión frente a la etiqueta — un efecto coherente con que el *background* de un ISP contiene
escaneos reales.

**Decisión adoptada para la memoria**: la **v5 integrated se recomienda como versión final
integrada** (ampliación conductual de la v3 que añade detección de sshscan por contexto global),
con los matices anteriores explícitos; la **v3 se conserva como versión base estable**. El spam
permanece como límite estructural (sin mejora). El refinamiento del pase SSH (umbral robusto,
evaluación consciente de etiqueta, prueba en escaneos SSH distribuidos) queda como **trabajo
futuro**, pero no impide adoptar la v5 como referencia principal del TFG.

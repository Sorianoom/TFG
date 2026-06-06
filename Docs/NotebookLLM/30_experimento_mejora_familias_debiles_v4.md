# Experimento de mejora de familias débiles (v4 experimental)

Experimento para intentar mejorar las familias **débiles** de la v3
(`anomaly-spam`, `anomaly-sshscan`, `nerisbotnet`) sin sobreajustar, sin usar IPs
concretas ni la etiqueta para detectar, y sin reintroducir bytes exactos como firma.

- Script experimental: [`scripts/02_attack_analysis/detect_attack_flows_contextual_v4_experimental.py`](../../scripts/02_attack_analysis/detect_attack_flows_contextual_v4_experimental.py)
- Salidas: `data/attack_analysis/flow_level_detection_results_v4_experimental.csv` y `..._summary_v4_experimental.csv`
- **La v3 NO se modifica** y sigue siendo el clasificador principal recomendado.

La v4 mantiene **idéntica** la lógica de scan11/scan44/udp_scan/tcp_flood/unknown_attack;
solo cambia el pase 2 para ssh/spam/neris.

---

## 1. Qué se cambió en la v4

- **anomaly-sshscan**: agregación temporal por `src_ip` hacia el puerto 22 (span, sub-ventanas
  de 5/15/30/60 min, incompletitud, ausencia de sesiones completas) con **confianza graduada**
  (low/medium/high) y umbral mínimo de destinos bajado a 3.
- **nerisbotnet**: se separa `coordinated_botnet` en
  **`coordinated_botnet_high_confidence`** (clúster C2 o coordinación persistente muy fuerte:
  ≥25 orígenes en ≥5 buckets) y **`coordinated_botnet_low_confidence`** (la señal exploratoria
  de la v3: ≥15 orígenes en ≥4 buckets).
- **anomaly-spam**: señal **`smtp_campaign_low_confidence`** (fan-out + concentración temporal +
  pocos paquetes/flujo + baja varianza de bytes, **sin valores de bytes concretos**).

---

## 2. Comparación numérica v3 vs v4

### Detección binaria

| Métrica binaria | v3 | v4 experimental |
| --- | ---: | ---: |
| precisión ataque | 0,930 | 0,930 |
| recall ataque | 0,991 | 0,991 |
| F1 binario | 0,960 | 0,960 |
| TP / FP / FN / TN | 1816688 / 137365 / 17228 / 4899050 | 1816688 / 137361 / 17228 / 4899054 |

**Sin cambios** (4 FP menos, irrelevante). La v4 no degrada la detección binaria.

### Por familia (precisión / recall canónicos)

| Familia | v3 | v4 experimental |
| --- | ---: | ---: |
| vertical_scan | 0,770 / 0,847 | 0,770 / 0,847 (idéntico) |
| scan11 (subtipo) | 0,763 / 0,997 | 0,763 / 0,997 (idéntico) |
| scan44 (subtipo) | 0,762 / 0,796 | 0,762 / 0,796 (idéntico) |
| anomaly-udpscan | 0,938 / ~1,00 | 0,938 / ~1,00 (idéntico) |
| dos (tcp_flood) | 0,554 / 0,488 | 0,554 / 0,488 (idéntico) |
| nerisbotnet (combinado) | 0,269 / 0,044 | 0,266 / 0,044 |
| anomaly-sshscan | 0,000 / 0,000 (60 pred) | 0,000 / 0,000 (128 pred) |
| anomaly-spam | 0,000 / 0,000 (1098 pred) | 0,000 / 0,000 (1134 pred) |

### Desglose granular de la v4 (lo relevante del experimento)

| Familia granular v4 | predichas | aciertos | precisión |
| --- | ---: | ---: | ---: |
| coordinated_botnet_high_confidence | 5.842 | 4.420 | **0,757** |
| coordinated_botnet_low_confidence | 10.801 | 0 | 0,000 |
| ssh_horizontal_scan | 128 | 0 | 0,000 |
| smtp_campaign_low_confidence | 1.134 | 0 | 0,000 |

---

## 3. Lectura por familia

### nerisbotnet — única mejora real
El split funciona como se esperaba: **todos los aciertos (4.420) caen en
`coordinated_botnet_high_confidence`**, que alcanza **precisión 0,757** frente al 0,269 de la
`coordinated_botnet` combinada de la v3. El ruido se concentra en
`coordinated_botnet_low_confidence` (10.801 predichas, **0 aciertos**), explícitamente marcada
como exploratoria. El **recall no mejora** (0,044, igual que la v3): el split no detecta más
neris, pero **separa con claridad lo fiable de lo exploratorio**. La regla **no es específica**
del dataset (se basa en coordinación C2 + persistencia, no en IPs ni bytes), por lo que es
generalizable.

### anomaly-sshscan — empeora
Bajar el umbral a 3 destinos y graduar la confianza **aumenta los falsos positivos** (de 60 a
128 predichas) **sin un solo acierto**. La señal real (44 trazas low-and-slow) sigue siendo
inalcanzable dentro de las ventanas. Este cambio **debe descartarse**.

### anomaly-spam — sin mejora
`smtp_campaign_low_confidence` predice 1.134 trazas con **0 aciertos** (igual que la v3). El
relabel a baja confianza es honesto, pero **no aporta detección**. Sigue siendo caso
exploratorio.

### Resto (scan11, scan44, udpscan, dos, binario)
**Idénticos a la v3** por diseño (no se tocó su lógica). No hay degradación.

---

## 4. Falsos positivos nuevos y falsos negativos corregidos

- **Falsos positivos nuevos**: `anomaly-sshscan` +68 (60→128) y `anomaly-spam` +36 (1098→1134),
  todos FP. `nerisbotnet` combinado +181. A nivel binario es irrelevante (esas trazas ya eran
  "attack" en la v3). El split de neris **no añade FP nuevos a binario**, solo los **reetiqueta**
  como `low_confidence`.
- **Falsos negativos corregidos**: **ninguno**. El recall no mejora en ninguna familia débil
  (neris 0,044; ssh 0; spam 0 se mantienen). La v4 **no recupera** ataques que la v3 perdía.

En síntesis: la v4 **no corrige falsos negativos**; su único efecto positivo es **separar la
precisión** de nerisbotnet (aislando un subconjunto de alta confianza con precisión 0,757).

---

## 5. Decisión

Aplicando los criterios fijados:

- ¿Empeora scan11/scan44/udpscan o la precisión binaria? **No** (idénticos). → no obliga a
  rechazar por degradación.
- ¿Mejora solo con reglas sospechosamente específicas? **No**: la mejora de neris es un **split
  de confianza** basado en coordinación/persistencia, no en IPs ni bytes concretos.
- ¿Mejora de forma razonable? **Parcialmente**: solo el split de nerisbotnet, y solo en
  **precisión del subconjunto de alta confianza**, sin ganar recall.

**Recomendación:**

1. **Mantener la v3 como clasificador contextual por traza principal.** La v4 no mejora la
   detección (recall) de ninguna familia débil ni la binaria.
2. **Adoptar como trabajo futuro / refinamiento** únicamente el **split de nerisbotnet en
   high/low confidence**: aporta una `coordinated_botnet_high_confidence` con precisión 0,76
   (vs 0,27), útil para presentar el botnet de forma más fiable, sin coste en el resto.
3. **Descartar** el cambio de `anomaly-sshscan` (aumenta FP sin recall).
4. **Mantener `anomaly-spam`** como caso exploratorio (el relabel a baja confianza es honesto
   pero no aporta detección).

La v4 se conserva como **variante experimental**, no como sustituta de la v3.

---

## 6. Conclusión

El experimento confirma que las familias débiles de la v3 lo son por **límites del dato**, no
por falta de afinado: `anomaly-sshscan` (low-and-slow, señal demasiado escasa en las ventanas)
y `anomaly-spam` (indistinguible del SMTP legítimo con metadatos de flujo) **no mejoran** sin
caer en sobreajuste, y forzarlas solo añade falsos positivos. El único avance defendible es el
**split de confianza en nerisbotnet**, que **separa** una señal de alta precisión (C2 +
coordinación persistente fuerte) de la exploratoria, sin tocar el resto del clasificador ni la
detección binaria.

Por tanto, **la v3 sigue siendo la propuesta principal**. La v4 aporta un refinamiento puntual
(neris high/low) proponible como trabajo futuro, y deja documentado —de forma honesta— que
sshscan y spam permanecen como límites del enfoque sobre este dataset.

# Informe Técnico: Modelo de Comportamiento de Tráfico Sintético (UGR'16)

## 1. Introducción: El Desafío de la Detección en Entornos ISP

La monitorización y defensa de redes de Proveedores de Servicios de Internet (ISP) exige un análisis avanzado debido a la masividad y heterogeneidad de los datos procesados. El dataset **UGR'16** se posiciona como un estándar de referencia, fundamentado en la captura de tráfico real mediante colectores **NetFlow v9** en un ISP español.

Para un sistema de detección de intrusiones (IDS), es fundamental distinguir entre tráfico legítimo y tráfico malicioso:

- **Tráfico legítimo** → comportamiento *cicloestacionario*, con patrones periódicos (día/noche, laboral/fin de semana)
- **Tráfico sintético** → comportamiento *determinista y algorítmico*, con baja variabilidad

El dataset se divide en:

- **CALIBRACIÓN (marzo–junio 2016)**  
  Línea base de comportamiento normal

- **TEST (julio–agosto 2016)**  
  Incluye tráfico real + ataques + anomalías no controladas (ej. spam)

---

## 2. Pipeline Jerárquico de Detección

El modelo de detección se organiza en tres fases:

### Fase 1: Detección de Anomalía Sintética

Identificación de flujos con características no humanas:

- `Duration ≈ 0.000s`
- Baja entropía (payloads homogéneos)
- Alta densidad temporal (múltiples flujos en el mismo instante)

Esto indica tráfico generado automáticamente.

---

### Fase 2: Análisis Estructural

Evaluación de la organización del tráfico:

- Dispersión de IPs (fan-out)
- Secuencialidad de puertos (`ΔPort = ±1`)
- Ruptura de la cicloestacionariedad

---

### Fase 3: Clasificación

Clasificación basada en **invariantes estructurales**, no en firmas:

- DoS
- UDP Scan
- Botnet

---

## 3. Modelo DoS (Denegación de Servicio)

Ataque orientado al agotamiento del plano de control.

**Características:**

- **Topología:** `1 → 1`
- **Comportamiento:** ráfaga de múltiples flujos de duración ≈ 0
- **Protocolo:** TCP (SYN / RST)
- **Automatización:** en el origen
- **Firma clave:** secuencialidad en `src_port`

---

## 4. Modelo UDP Scan (Reconocimiento de Superficie)

Ataque de enumeración de servicios.

**Características:**

- **Topología:** `1 → Muchos`
- **Estrategia:** exploración del espacio de destino
- **Puerto origen:** fijo (ej. 5061)
- **Puerto destino:** secuencial
- **Protocolo:** UDP
- **Duración:** ≈ 0.000s
- **Payload:** varianza de bytes extremadamente baja (~430B)

---

## 5. Modelo NerisBotnet (Coordinación Distribuida)

Infraestructura de bots coordinados.

**Características:**

- **Topología:** híbrida (`1 → Muchos` y `Muchos → 1`)
- **Automatización:** distribuida en la red
- **Puerto C2:** 6667 (IRC)
- **Sincronización:** múltiples nodos actúan en el mismo instante
- **Clave:** pérdida de independencia estadística entre nodos

---

## 6. Tabla Comparativa

| Métrica | DoS | UDP Scan | NerisBotnet |
|--------|-----|----------|-------------|
| Densidad de flujos | Muy alta | Alta | Variable |
| Dispersión de IPs | 1 → 1 | 1 → Muchos | Híbrida |
| Puertos | Src secuencial | Dst secuencial | C2 fijo |
| Varianza de bytes | Muy baja | Muy baja | Variable |
| Duración | ≈ 0.000s | ≈ 0.000s | Variable |
| Protocolo | TCP | UDP | TCP/UDP |

---

## 7. Conclusión Técnica

La detección no depende del volumen, sino de **invariantes estructurales**.

La diferencia clave entre ataques es la **localización de la automatización**:

- **DoS → Origen**  
  Generación masiva de flujos

- **UDP Scan → Destino**  
  Exploración sistemática del espacio de red

- **Botnet → Red**  
  Coordinación distribuida y sincronizada

Este enfoque permite construir sistemas IDS robustos y generalizables, capaces de detectar ataques incluso cuando cambian IPs o puertos.
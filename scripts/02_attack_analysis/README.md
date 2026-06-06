# Análisis de ataques y detección basada en comportamiento

Esta carpeta contiene scripts para analizar ventanas temporales del dataset UGR'16 y validar un detector heurístico basado en comportamiento.

## Scripts principales

### `list_attack_types.py`

Lista los tipos de ataque presentes en el dataset limpio.

### `extract_time_window.py`

Extrae ventanas temporales alrededor de ocurrencias de ataques concretos.

### `detect_synthetic_behavior.py`

Aplica un modelo heurístico sobre ventanas temporales ya extraídas para detectar:

- DoS
- UDP Scan
- NerisBotnet

El detector no analiza flujos aislados, sino patrones agregados dentro de una ventana temporal.

## Modelo implementado

El detector se basa en invariantes estructurales:

- duración cercana a cero
- baja varianza de bytes
- secuencialidad de puertos
- concentración o dispersión de IPs
- coordinación distribuida hacia puertos C2

## Resultados actuales

- DoS: 3/3 ventanas detectadas
- UDP Scan: 3/3 ventanas detectadas
- NerisBotnet: 1/3 ventanas detectadas cuando existe evidencia C2 suficiente
- Normal: 0 falsos positivos sobre los perfiles normales analizados

## Salida

El script genera:

`data/attack_analysis/behavior_detection_results.csv`
# Generación de datasets balanceados

Esta carpeta contiene scripts para la construcción de datasets
con distintas proporciones de tráfico normal y malicioso.

## Objetivo

Generar diferentes escenarios de balanceo para analizar su impacto
en el rendimiento y comportamiento de los modelos.

## Configuraciones

- 50% normal / 50% malicioso
- 60% normal / 40% malicioso
- 70% normal / 30% malicioso

## Estructura

Para cada configuración:

1. Extracción de tráfico normal  
2. Generación del dataset balanceado  
3. Validación de etiquetas  

## Ejemplo (60/40)

- `extract_background_60_40.py`
- `merge_balanced_dataset_60_40.py`
- `count_labels_60_40.py`

## Nota

El dataset original presenta un fuerte desbalance (~98% tráfico normal),
por lo que esta fase es clave para el análisis posterior.
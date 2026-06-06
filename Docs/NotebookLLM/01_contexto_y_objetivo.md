# Contexto y objetivo del proyecto

## Contexto

Este TFG estudia el uso de modelos de lenguaje grandes (LLMs) como apoyo al análisis de tráfico de red y detección explicable de anomalías en el dataset UGR'16.

El trabajo no tiene como objetivo principal entrenar un modelo de Machine Learning propio, sino analizar cómo un LLM puede ayudar a:

- interpretar ventanas de tráfico NetFlow
- comparar tráfico normal y malicioso
- extraer patrones estructurales
- generar hipótesis técnicas
- formalizar reglas de comportamiento
- explicar los ataques de forma comprensible

## Objetivo principal

Evaluar el uso de LLMs como herramienta de apoyo para el análisis explicativo de ataques en tráfico NetFlow, validando posteriormente las hipótesis generadas mediante scripts programáticos.

## Objetivos específicos

1. Estudiar el dataset UGR'16 y sus tipos de tráfico.
2. Extraer perfiles normales de calibración.
3. Extraer ventanas temporales de ataques.
4. Analizar los patrones de DoS, UDP Scan y NerisBotnet mediante LLMs.
5. Formalizar un modelo de comportamiento sintético.
6. Implementar un detector heurístico para validar las hipótesis.
7. Documentar ventajas, limitaciones y posibilidades del uso de LLMs en ciberseguridad.

## Enfoque del trabajo

El enfoque combina:

- análisis empírico de datos NetFlow
- uso de LLMs para interpretación
- validación programática con Python
- documentación académica de resultados

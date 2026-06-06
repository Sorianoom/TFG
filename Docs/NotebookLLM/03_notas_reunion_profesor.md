# Notas de reunión con el profesor e interpretación técnica

## Idea principal

La indicación principal recibida fue no analizar trazas aisladas ni dividir el dataset únicamente por balanceo de etiquetas, sino estudiar el tráfico dentro de su contexto temporal.

En tráfico de red, una fila aislada rara vez permite entender un ataque. El patrón aparece al observar qué ocurre antes, durante y después del evento.

## Extracción de contexto

Se propuso extraer ventanas alrededor de eventos de ataque:

- filas anteriores al ataque
- filas del ataque
- filas posteriores al ataque

Esto permite observar:

- transición entre tráfico normal y malicioso
- consistencia del etiquetado
- mezcla de background y ataque
- repetición temporal de patrones
- relación entre IPs y puertos antes y después del evento

## Análisis temporal

También se planteó estudiar si el tráfico ocurrido un minuto antes hacia una IP/puerto está relacionado con el tráfico posterior.

Esto es especialmente relevante para:

- beaconing
- botnets
- reconocimiento previo
- persistencia
- coordinación distribuida

## Uso de LLMs

El profesor planteó utilizar LLMs como apoyo para:

- analizar ventanas de tráfico
- generar hipótesis
- estudiar tipos de ataques
- probar prompts
- ayudar a crear código
- explicar patrones complejos

El LLM no se considera un detector final, sino una herramienta de apoyo al análisis.

## No depender de blacklist

Se indicó que la etiqueta `blacklist` no debía ser la base del análisis.

El objetivo es detectar comportamiento malicioso por patrones estructurales, no por listas negras.

## Cambio de enfoque

A partir de estas indicaciones, el trabajo evolucionó desde una idea inicial basada en balanceo de datasets hacia un enfoque basado en:

- ventanas temporales
- análisis de contexto
- comportamiento agregado
- uso de LLMs
- validación de hipótesis
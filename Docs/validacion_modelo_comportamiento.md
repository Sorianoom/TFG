# Validación del modelo de comportamiento sintético

## Resultados

| Tipo de ventana | Ventanas detectadas | Total | Resultado |
|---|---:|---:|---|
| DoS | 3 | 3 | Correcto |
| UDP Scan | 3 | 3 | Correcto |
| NerisBotnet | 1 | 3 | Correcto cuando existe evidencia C2 suficiente |
| Normal | 0 clasificadas como ataque | 3 | Sin falsos positivos |

## Interpretación

El modelo detecta correctamente patrones sintéticos simples como DoS y UDP Scan mediante reglas basadas en duración, baja varianza, secuencialidad de puertos y dispersión/concentración de IPs.

Para NerisBotnet, la detección requiere evidencia de coordinación distribuida hacia un canal de Command & Control. En la tercera ventana se detecta una estructura muchos→1 hacia el puerto 6667/TCP, compatible con comunicación C2. Las dos primeras ventanas no contienen suficiente densidad de tráfico botnet, por lo que el detector no las clasifica.

## Evidencia generada

Los resultados completos del detector se guardan en:

`data/attack_analysis/behavior_detection_results.csv`
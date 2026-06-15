# Validación del modelo de comportamiento sintético

Este directorio contiene las ventanas temporales utilizadas para validar el modelo heurístico de detección basado en comportamiento sobre el dataset UGR'16.

## Ventanas analizadas

- DoS: 3 ventanas
- UDP Scan: 3 ventanas
- NerisBotnet: 3 ventanas
- Normal: 3 perfiles de calibración

## Resultado

El detector clasifica correctamente:

- DoS 1, 2 y 3 como `DoS`
- UDP Scan 1, 2 y 3 como `UDP Scan`
- Perfiles normales como `No clasificado`

El caso NerisBotnet no se clasifica automáticamente en esta fase, ya que requiere un detector específico basado en correlación temporal distribuida entre nodos.

## Conclusión

El experimento valida que las reglas basadas en duración, baja varianza, secuencialidad de puertos y dispersión de IPs permiten detectar patrones sintéticos simples sin depender de IPs concretas.
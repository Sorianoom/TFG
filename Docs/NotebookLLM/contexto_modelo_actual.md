# Contexto del modelo actual

El trabajo analiza tráfico NetFlow del dataset UGR'16 usando LLMs como apoyo explicativo y validación posterior con código.

El tráfico normal se caracteriza por diversidad de IPs, puertos, protocolos, duración, paquetes y bytes, además de comportamiento cicloestacionario.

El modelo actual diferencia ataques según la localización de la automatización:

- DoS: automatización en el origen. Patrón 1→1, TCP, destino y puerto fijos, puertos origen secuenciales, duración cercana a cero y baja varianza.
- UDP Scan: automatización en el espacio de destino/red. Patrón 1→muchos, UDP, origen fijo, puerto origen fijo, múltiples destinos y puertos destino secuenciales.
- scan11: Single-Source Vertical Scan. Patrón 1→1, TCP, un origen contra un host, muchos puertos destino, duración 0.000s, 1 paquete y bytes bajos.
- scan44: Distributed Vertical Scan. Patrón muchos→muchos, TCP, varios orígenes contra varios destinos, muchos puertos destino por host y sincronización temporal.
- NerisBotnet: automatización distribuida orientada a C2. Múltiples nodos sincronizados hacia un destino común, puerto C2 y métricas homogéneas.

El objetivo con anomaly-sshscan es comprobar si encaja como SSH Horizontal Scan, SSH Vertical Scan, SSH Distributed Scan o si requiere otra categoría.
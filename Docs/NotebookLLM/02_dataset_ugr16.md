# Dataset UGR'16

## Descripción general

UGR'16 es un dataset de tráfico de red capturado en un ISP español mediante colectores NetFlow v9.

El dataset contiene tráfico de fondo real, ataques sintéticos y anomalías reales.

## Conjuntos del dataset

El dataset se divide en dos bloques principales:

### Calibración

Corresponde a tráfico de fondo de marzo a junio de 2016.

Se utiliza para estudiar el comportamiento normal de la red y su cicloestacionariedad.

### Test

Corresponde a tráfico de julio y agosto de 2016.

Incluye tráfico de fondo, ataques sintéticos y anomalías reales.

## Datos utilizados en este trabajo

Durante el desarrollo se utilizaron:

- Primera semana de agosto del conjunto de test.
- Segunda semana de abril del conjunto de calibración.

## Etiquetas de ataque identificadas

A partir del script de conteo de etiquetas se identificaron los siguientes ataques:

| Etiqueta | Número de flujos |
|---|---:|
| anomaly-udpscan | 989872 |
| dos | 391599 |
| scan44 | 190584 |
| nerisbotnet | 151525 |
| scan11 | 36144 |
| anomaly-spam | 47 |
| anomaly-sshscan | 8 |

## Consideración sobre blacklist

La etiqueta `blacklist` no se utiliza como criterio principal de detección, ya que el objetivo del trabajo es estudiar comportamiento y no listas negras.

## Importancia de la cicloestacionariedad

UGR'16 permite estudiar la evolución temporal del tráfico, incluyendo diferencias entre:

- día y noche
- horario laboral y no laboral
- días laborables y fines de semana

Esta característica es clave para comparar tráfico normal y anómalo.
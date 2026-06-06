"""
Script: polars_experiment.py

Descripción:
Intento inicial de procesamiento del dataset de tráfico de red utilizando
Polars para gestionar grandes volúmenes de datos de forma eficiente.

Este script:
- Lee el CSV original en modo lazy (scan_csv)
- Renombra columnas manualmente
- Filtra valores nulos en campos clave
- Selecciona un subconjunto de columnas relevantes
- Genera:
    1. Un sample de 1 millón de filas
    2. Un dataset filtrado con tráfico "blacklist"

Entrada:
- data/raw/august.week1.csv

Salida:
- august_week1_sample_1M.csv
- august_week1_blacklist.csv

Uso:
python scripts/experiments/polars_experiment.py

Estado:
- ❌ NO utilizado en el pipeline final

Motivo de descarte:
- Errores de memoria en datasets grandes
- Problemas al procesar filas corruptas o inconsistentes
- Uso de parámetros deprecados (streaming=True)
- Menor robustez frente a datos reales comparado con procesamiento por streaming con csv

Conclusión:
Se optó por una solución basada en lectura secuencial (csv en streaming),
más estable y adecuada para datasets reales con errores estructurales.

Notas:
- Se conserva como referencia de evaluación de herramientas
- Puede ser útil en datasets limpios o preprocesados
"""

import polars as pl

# Lectura lazy del CSV original
df = pl.scan_csv("data/raw/august.week1.csv", has_header=False)

# Renombrado de columnas
df = df.rename({
    "column_1": "timestamp",
    "column_2": "src_ip",
    "column_3": "src_port",
    "column_4": "protocol",
    "column_5": "dst_ip",
    "column_6": "dst_port",
    "column_7": "flags",
    "column_8": "tos",
    "column_9": "packets",
    "column_10": "flows",
    "column_11": "packets_2",
    "column_12": "bytes",
    "column_13": "label"
})

# Filtrado básico de valores nulos
df = df.filter(
    pl.col("timestamp").is_not_null() &
    pl.col("src_ip").is_not_null() &
    pl.col("dst_ip").is_not_null() &
    pl.col("label").is_not_null()
)

# Selección de columnas relevantes
df = df.select([
    "timestamp",
    "src_ip",
    "src_port",
    "protocol",
    "dst_ip",
    "bytes",
    "label"
])

# Generación de muestra de 1M filas
df.head(1_000_000).collect(streaming=True).write_csv(
    "data/samples/august_week1_sample_1M.csv"
)

# Extracción de tráfico blacklist
df.filter(pl.col("label") == "blacklist").collect(streaming=True).write_csv(
    "data/samples/august_week1_blacklist.csv"
)

print("Archivos generados:")
print("- data/samples/august_week1_sample_1M.csv")
print("- data/samples/august_week1_blacklist.csv")
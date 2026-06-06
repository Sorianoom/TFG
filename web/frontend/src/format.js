// Utilidades de formato y de lectura de métricas (compartidas).

export function fmt(x) {
  return x === undefined || x === null
    ? "—"
    : Number(x).toLocaleString("es-ES", { maximumFractionDigits: 3 });
}

// attacks.json trae métricas planas {precision,recall[,f1]} o anidadas
// (sshscan: {v3_estandar:{...}, v5_integrated_april_week2:{...}}).
export function metricRows(metricas) {
  if (!metricas) return [];
  if ("precision" in metricas || "recall" in metricas) {
    return [{ label: "v3 / v5 (núcleo idéntico)", ...metricas }];
  }
  const rows = [];
  if (metricas.v3_estandar) rows.push({ label: "v3 estándar", ...metricas.v3_estandar });
  for (const k of Object.keys(metricas)) {
    if (k.startsWith("v5")) {
      rows.push({ label: "v5 integrated · " + k.replace("v5_integrated_", "").replace(/_/g, "."), ...metricas[k] });
    }
  }
  return rows;
}

// Fila "principal" para tarjetas/tablas (en sshscan, la v5).
export function mainMetric(metricas) {
  const rows = metricRows(metricas);
  return rows[rows.length - 1] || {};
}

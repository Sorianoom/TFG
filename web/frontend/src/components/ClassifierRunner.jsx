import { useEffect, useState } from "react";
import { API_BASE } from "../config";

const MAX_BYTES = 5 * 1024 * 1024;

function fmtPct(x) {
  return x === null || x === undefined ? null : `${(x * 100).toFixed(1)} %`;
}

export default function ClassifierRunner() {
  const [expected, setExpected] = useState(null);
  const [file, setFile] = useState(null);
  const [csvText, setCsvText] = useState(null);
  const [result, setResult] = useState(null);
  const [error, setError] = useState(null);
  const [loading, setLoading] = useState(false);

  useEffect(() => {
    fetch(`${API_BASE}/api/classifier/expected-columns`)
      .then((r) => r.json())
      .then(setExpected)
      .catch(() => setExpected(null));
  }, []);

  function onFile(e) {
    const f = e.target.files?.[0];
    setError(null);
    setResult(null);
    setFile(f || null);
    setCsvText(null);
    if (!f) return;
    if (f.size > MAX_BYTES) {
      setError({ message: `El archivo supera 5 MB (${(f.size / 1024 / 1024).toFixed(1)} MB).` });
      return;
    }
    const reader = new FileReader();
    reader.onload = () => setCsvText(String(reader.result || ""));
    reader.onerror = () => setError({ message: "No se pudo leer el archivo." });
    reader.readAsText(f);
  }

  async function run() {
    if (!csvText) return;
    setLoading(true);
    setError(null);
    try {
      const res = await fetch(`${API_BASE}/api/classifier/run`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ filename: file?.name || "ventana.csv", csv_text: csvText }),
      });
      const data = await res.json();
      if (!res.ok) {
        setResult(null);
        setError({ message: typeof data.detail === "string" ? data.detail : "Error al clasificar." });
      } else {
        setResult(data);
      }
    } catch {
      setError({ message: `No se pudo conectar con el backend (${API_BASE}).` });
    } finally {
      setLoading(false);
    }
  }

  const s = result?.summary;
  const hasLabels = !!result?.rows?.some((r) => r.true_label !== null && r.true_label !== undefined);

  return (
    <section className="csec" id="clasificador">
      <h2 className="csec-title">Probar el clasificador v5</h2>
      <p className="csec-lead">
        Sube una <strong>ventana CSV pequeña</strong> (máximo 5 MB) y el clasificador la analiza traza a
        traza, marcando cada flujo como ataque o tráfico normal y explicando por qué. Si el CSV incluye la
        etiqueta real, también se calcula el acierto.
      </p>

      <div className="clf-bar">
        <label className="clf-file">
          <input type="file" accept=".csv,text/csv" onChange={onFile} />
          <span>{file ? file.name : "Elegir CSV…"}</span>
        </label>
        <button className="clf-go" onClick={run} disabled={!csvText || loading}>
          {loading ? "Analizando…" : "Ejecutar clasificador"}
        </button>
      </div>

      {expected && (
        <p className="muted small">
          Columnas esperadas: <code>{expected.expected_columns.join(", ")}</code>. También acepta el
          formato de UGR'16 (13 columnas, sin cabecera). Motor: {expected.engine}.
        </p>
      )}

      {error && <div className="banner-error">{error.message}</div>}

      {s && (
        <div className="clf-result">
          <div className="clf-cards">
            <div className="clf-card"><strong>{s.total_rows}</strong><span>filas analizadas</span></div>
            <div className="clf-card attack"><strong>{s.predicted_attack}</strong><span>predichas ataque</span></div>
            <div className="clf-card"><strong>{s.predicted_background}</strong><span>predichas normal</span></div>
            <div className="clf-card"><strong>{s.dominant_attack || "—"}</strong><span>ataque dominante</span></div>
            <div className="clf-card"><strong>{(s.average_confidence * 100).toFixed(0)} %</strong><span>confianza media</span></div>
            <div className="clf-card v5"><strong>{fmtPct(s.accuracy) || "—"}</strong><span>acierto</span></div>
          </div>
          <p className={`clf-note ${s.accuracy === null ? "warn" : ""}`}>{s.accuracy_note}</p>

          <div className="table-wrap">
            <table className="data-table">
              <thead>
                <tr>
                  <th>#</th><th>Protocolo</th><th>Puerto destino</th>
                  <th>Predicción</th><th>Familia</th><th>Subtipo</th><th>Confianza</th>
                  {hasLabels && <th>Etiqueta real</th>}
                  {hasLabels && <th>Correcto</th>}
                  <th>Explicación</th>
                </tr>
              </thead>
              <tbody>
                {result.rows.map((r) => (
                  <tr key={r.row} className={r.prediction === "attack" ? "row-attack" : ""}>
                    <td>{r.row}</td>
                    <td>{r.protocol || "—"}</td>
                    <td>{r.dst_port}</td>
                    <td>{r.prediction}</td>
                    <td>{r.family || "—"}</td>
                    <td>{r.subtype || "—"}</td>
                    <td>{r.confidence} <span className="muted">({r.confidence_score})</span></td>
                    {hasLabels && <td>{r.true_label || "—"}</td>}
                    {hasLabels && <td>{r.correct === null ? "—" : r.correct ? "✓" : "✗"}</td>}
                    <td className="explanation-cell">{r.explanation || "Sin explicación disponible"}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
          <p className="muted small">
            Mostrando {s.returned_rows} de {s.total_rows} filas. <strong>Confianza</strong> = cuán segura
            está la regla; <strong>acierto</strong> = comparación con la etiqueta real (solo si el CSV la
            incluye). La validación científica completa está en los scripts de análisis.
          </p>
        </div>
      )}
    </section>
  );
}

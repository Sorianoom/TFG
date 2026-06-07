import { useState } from "react";
import { API_BASE } from "../config";
import { useAiMode } from "../aiMode";

const FLOW_OPTIONS = [20, 50, 100];
const SECTION_LABEL = {
  background_before: "normal (antes)",
  attack: "ataque",
  background_after: "normal (después)",
};

export default function AttackSimulator({ attack }) {
  const [mode] = useAiMode();
  const [attackFlows, setAttackFlows] = useState(50);
  const [result, setResult] = useState(null);
  const [error, setError] = useState(null);
  const [loading, setLoading] = useState(false);

  async function generate(forceOffline) {
    const useMode = forceOffline ? "offline" : (mode === "on" ? "notebooklm" : "offline");
    setLoading(true);
    setError(null);
    try {
      const res = await fetch(`${API_BASE}/api/simulator/generate`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          attack_id: attack.id,
          attack_flows: attackFlows,
          include_context_background: true,
          mode: useMode,
        }),
      });
      const data = await res.json();
      if (!res.ok) {
        setResult(null);
        setError(typeof data.detail === "object" ? data.detail : { message: String(data.detail || "Error") });
      } else {
        setResult(data);
      }
    } catch {
      setError({ message: `No se pudo conectar con el backend (${API_BASE}).` });
    } finally {
      setLoading(false);
    }
  }

  function downloadCsv() {
    if (!result) return;
    const cols = result.columns;
    const csv = [cols.join(","), ...result.rows.map((r) => cols.map((c) => r[c]).join(","))].join("\n");
    const url = URL.createObjectURL(new Blob([csv], { type: "text/csv;charset=utf-8" }));
    const a = document.createElement("a");
    a.href = url;
    a.download = `ventana_${result.attack_id}_${result.mode_used}.csv`;
    a.click();
    URL.revokeObjectURL(url);
  }

  return (
    <section className="detail-block detail-wide sim-section">
      <h2>Simulación del patrón</h2>
      <p className="muted small">
        Crea una <strong>ventana de ejemplo</strong> (datos inventados, no tráfico real) con esta forma:
        <strong> 5 conexiones normales antes</strong>, las <strong>trazas del ataque</strong> en medio y
        <strong> 5 conexiones normales después</strong>. Así se ve el patrón del ataque rodeado de tráfico
        corriente, como aparecería en una captura real.
        Modo IA actual: <strong>{mode === "on" ? "ON (cuaderno NotebookLM del ataque)" : "OFF (plantilla local)"}</strong>.
      </p>
      <p className="sim-howto muted small">
        <strong>IA OFF</strong> usa una plantilla local de la web. <strong>IA ON</strong> consulta el
        cuaderno de NotebookLM de este ataque. En ambos casos:
        <em> NotebookLM no genera libremente el CSV: propone el patrón y unos rangos aproximados, y el
        backend genera las filas y comprueba que el ataque mantenga su forma correcta.</em>
      </p>

      <div className="sim-controls">
        <span className="sim-ctl-label">Trazas de ataque:</span>
        {FLOW_OPTIONS.map((n) => (
          <button
            key={n}
            className={`sim-chip ${attackFlows === n ? "on" : ""}`}
            onClick={() => setAttackFlows(n)}
          >{n}</button>
        ))}
        <button className="sim-go" onClick={() => generate(false)} disabled={loading}>
          {loading ? "Generando…" : "Generar ventana sintética"}
        </button>
      </div>

      {error && (
        <div className="banner-error sim-error">
          <strong>{error.message}</strong>
          {error.reason && <div className="muted small">{error.reason}</div>}
          {error.suggestion && <div className="muted small">{error.suggestion}</div>}
          {error.fallback_mode === "offline" && (
            <button className="sim-fallback" onClick={() => generate(true)}>Generar en IA OFF</button>
          )}
        </div>
      )}

      {result && (
        <div className="sim-result">
          <div className="sim-meta">
            <span className={`sim-badge ${result.mode_used === "notebooklm" ? "ia" : ""}`}>
              {result.mode_used === "notebooklm" ? "IA ON · cuaderno NotebookLM" : "IA OFF · plantilla local"}
            </span>
            <button className="sim-download" onClick={downloadCsv}>⬇ Descargar CSV ({result.summary.total_rows})</button>
          </div>

          <p className="sim-explain">{result.explanation_for_teacher}</p>

          {result.signals?.length > 0 && (
            <div className="chips">
              {result.signals.map((sg, i) => <span className="chip-sig" key={i}>{sg}</span>)}
            </div>
          )}

          <div className="table-wrap">
            <table className="data-table sim-table">
              <thead>
                <tr><th>sección</th>{result.columns.map((c) => <th key={c}>{c}</th>)}</tr>
              </thead>
              <tbody>
                {result.rows.map((r, i) => (
                  <tr key={i} className={`sec-${r.section}`}>
                    <td className="sec-cell">{SECTION_LABEL[r.section] || r.section}</td>
                    {result.columns.map((c) => <td key={c}>{r[c]}</td>)}
                  </tr>
                ))}
              </tbody>
            </table>
          </div>

          <p className="sim-notice">{result.synthetic_notice}</p>
        </div>
      )}
    </section>
  );
}

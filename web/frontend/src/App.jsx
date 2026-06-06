import { useEffect, useState } from "react";
import { API_BASE } from "./config";

// --- Metadatos de presentación (no son datos del backend, solo estilo/texto) ---

const ESTADO_META = {
  "fuerte": { label: "Fuerte", cls: "badge-fuerte" },
  "parcial": { label: "Parcial", cls: "badge-parcial" },
  "exploratorio": { label: "Exploratorio", cls: "badge-exploratorio" },
  "detectable con contexto largo (v5)": { label: "Contexto largo (v5)", cls: "badge-v5" },
};

// Flujo del TFG (mapa mental)
const FLOW = [
  { t: "UGR'16 Dataset", d: "Tráfico real capturado en un ISP." },
  { t: "NetFlow", d: "Flujos de red con metadatos (puertos, bytes, flags…)." },
  { t: "Ventanas de ataque", d: "Extracción de ventanas contiguas por familia." },
  { t: "NotebookLM / LLMs", d: "Interpretación asistida y comparación con tráfico normal." },
  { t: "Hipótesis conductuales", d: "Patrones por localización de la automatización." },
  { t: "Reglas interpretables", d: "Señales medibles, sin ML ni IPs concretas." },
  { t: "Clasificador v5 integrated", d: "Por traza: binario → familia → subtipo + pase SSH global." },
  { t: "Resultados / generalización / ML", d: "Validación en 2 semanas y baseline ML clásico." },
];

const VERSIONS = [
  { v: "v1", t: "Contextual local", d: "Clasifica trazas por contexto local (±30 filas)." },
  { v: "v2", t: "Jerárquico", d: "Separa ataque/background → familia → subtipo (con incertidumbre)." },
  { v: "v3", t: "Local + global por ventana", d: "Resuelve scan11/scan44 y eleva udp_scan. Versión base estable." },
  { v: "v4", t: "Experimento familias débiles", d: "Split de confianza en botnet (experimental, no adoptado)." },
  { v: "v5", t: "Final integrada", d: "Añade tercer pase global SSH por fan-out (low-and-slow). Versión principal.", final: true },
];

function fmt(x) {
  return x === undefined || x === null ? "—" : Number(x).toLocaleString("es-ES", { minimumFractionDigits: 0, maximumFractionDigits: 3 });
}

// Normaliza el campo "metricas" (plano para la mayoría; anidado v3/v5 para sshscan)
function metricRows(metricas) {
  if (!metricas) return [];
  if ("precision" in metricas || "recall" in metricas) {
    return [{ label: "v3 / v5 (núcleo idéntico)", ...metricas }];
  }
  const rows = [];
  if (metricas.v3_estandar) rows.push({ label: "v3 estándar", ...metricas.v3_estandar });
  for (const k of Object.keys(metricas)) {
    if (k.startsWith("v5")) rows.push({ label: "v5 integrated (" + k.replace("v5_integrated_", "") + ")", ...metricas[k] });
  }
  return rows;
}

function defenseLine(a) {
  if (a.id === "anomaly-sshscan") {
    return "Caso clave: con contexto local (v3) era indetectable (0/0). El tercer pase global de la v5 detecta el escaneo horizontal SSH por su fan-out por origen (april.week2: F1 0,951). Demuestra que el límite era arquitectónico, no del enfoque conductual.";
  }
  if (a.estado === "fuerte") return "Patrón estructurado de baja entropía, detectado de forma robusta y que generaliza a datos nuevos.";
  if (a.estado === "parcial") return "Se detecta en parte; la confusión o la cobertura limitada son coherentes con la naturaleza del ataque.";
  return "Caso de baja evidencia: se documenta con honestidad como límite estructural sobre metadatos de flujo, sin forzar resultados.";
}

function Metric({ label, precision, recall, f1 }) {
  return (
    <div className="metric-row">
      <span className="metric-label">{label}</span>
      <span>P {fmt(precision)}</span>
      <span>R {fmt(recall)}</span>
      <span>F1 {fmt(f1)}</span>
    </div>
  );
}

export default function App() {
  const [health, setHealth] = useState(null);
  const [summary, setSummary] = useState(null);
  const [attacksData, setAttacksData] = useState(null);
  const [selected, setSelected] = useState(null);
  const [error, setError] = useState(null);

  useEffect(() => {
    async function load() {
      try {
        const [h, s, a] = await Promise.all([
          fetch(`${API_BASE}/api/health`).then((r) => r.json()),
          fetch(`${API_BASE}/api/summary`).then((r) => r.json()),
          fetch(`${API_BASE}/api/attacks`).then((r) => r.json()),
        ]);
        setHealth(h);
        setSummary(s);
        setAttacksData(a);
      } catch (e) {
        setError(`No se pudo conectar con el backend (${API_BASE}). Arráncalo con: uvicorn main:app --reload`);
      }
    }
    load();
  }, []);

  const ataques = attacksData?.ataques || [];

  return (
    <div className="app">
      <header className="topbar">
        <div>
          <h1>Detección explicativa de anomalías NetFlow · UGR'16</h1>
          <p className="subtitle">Mapa mental del TFG · LLMs + clasificador contextual por traza</p>
        </div>
        <div className="ia-mode">
          <span className="ia-pill ia-on-mode">IA OFF · activo</span>
          <span className="ia-pill ia-off-mode">IA ON (NotebookLM) · pendiente</span>
          <span className={`health-dot ${health ? "ok" : "down"}`} title={health ? "backend ok" : "backend no disponible"}>
            {health ? `backend ok · API ${health.api_version}` : "backend no disponible"}
          </span>
        </div>
      </header>

      {error && <div className="banner-error">{error}</div>}

      {/* 1. Mapa mental / flujo */}
      <section className="card-section">
        <h2>Flujo del proyecto</h2>
        <div className="flow">
          {FLOW.map((b, i) => (
            <div className="flow-step-wrap" key={b.t}>
              <div className={`flow-step ${b.t.includes("v5") ? "flow-step-main" : ""}`}>
                <strong>{b.t}</strong>
                <span>{b.d}</span>
              </div>
              {i < FLOW.length - 1 && <span className="flow-arrow">→</span>}
            </div>
          ))}
        </div>
      </section>

      {/* 3. Resumen del proyecto */}
      <section className="card-section">
        <h2>Resumen del proyecto</h2>
        {summary ? (
          <div className="summary-grid">
            <div>
              <h3>Objetivo</h3>
              <p>{summary.objetivo}</p>
              <h3>Idea clave</h3>
              <p className="idea-clave">
                Los LLMs ayudan a <em>interpretar y formalizar</em> patrones de tráfico, pero la
                detección final se hace con <strong>reglas conductuales interpretables</strong>
                (sin ML, sin IPs concretas, sin usar la etiqueta para detectar).
              </p>
            </div>
            <div>
              <h3>Metodología</h3>
              <ul>{(summary.metodologia || []).map((m, i) => <li key={i}>{m}</li>)}</ul>
              <div className="version-boxes">
                <div className="version-box main">
                  <span className="tag">Versión principal</span>
                  <strong>v5 integrated</strong>
                  <span>{attacksData?.deteccion_binaria_v3 ? `binario P ${fmt(attacksData.deteccion_binaria_v3.precision)} · R ${fmt(attacksData.deteccion_binaria_v3.recall)}` : ""}</span>
                </div>
                <div className="version-box">
                  <span className="tag">Versión base estable</span>
                  <strong>v3</strong>
                  <span>contexto local + global por ventana</span>
                </div>
              </div>
            </div>
          </div>
        ) : !error ? <p className="muted">Cargando resumen…</p> : null}
      </section>

      {/* 4. Ataques */}
      <section className="card-section">
        <h2>Familias de ataque ({ataques.length})</h2>
        <div className="cards">
          {ataques.map((a) => {
            const em = ESTADO_META[a.estado] || { label: a.estado, cls: "badge-parcial" };
            const rows = metricRows(a.metricas);
            const best = rows[rows.length - 1];
            return (
              <button className="attack-card" key={a.id} onClick={() => setSelected(a)}>
                <div className="card-head">
                  <strong>{a.nombre}</strong>
                  <span className={`badge ${em.cls}`}>{em.label}</span>
                </div>
                <span className="familia">{a.familia_conductual}</span>
                <p className="desc">{a.descripcion}</p>
                {best && (
                  <div className="card-metric">
                    {best.label}: P {fmt(best.precision)} · R {fmt(best.recall)}{best.f1 !== undefined ? ` · F1 ${fmt(best.f1)}` : ""}
                  </div>
                )}
                <span className="ver-mas">ver detalle ▸</span>
              </button>
            );
          })}
        </div>
      </section>

      {/* 6. Timeline de versiones */}
      <section className="card-section">
        <h2>Evolución del clasificador</h2>
        <div className="timeline">
          {VERSIONS.map((v) => (
            <div className={`tl-item ${v.final ? "tl-final" : ""}`} key={v.v}>
              <div className="tl-dot">{v.v}</div>
              <div className="tl-body">
                <strong>{v.t}</strong>
                <span>{v.d}</span>
              </div>
            </div>
          ))}
        </div>
      </section>

      {/* 7. Modo IA */}
      <section className="card-section">
        <h2>Modo IA</h2>
        <div className="ia-grid">
          <div className="ia-panel active">
            <h3>IA OFF · activo</h3>
            <p>La web funciona con datos locales servidos por el backend (resumen y fichas por ataque). No requiere conexión a ningún LLM.</p>
          </div>
          <div className="ia-panel pending">
            <h3>IA ON · NotebookLM (pendiente)</h3>
            <p>Espacio reservado para consultas explicativas al LLM en el futuro. Aún no integrado.</p>
            <div className="ia-placeholder">Chat / consultas — próximamente</div>
          </div>
        </div>
      </section>

      <footer className="foot">
        TFG · {summary?.titulo || "Detección explicativa de anomalías NetFlow con LLMs"} · Modo IA OFF
      </footer>

      {/* 5. Detalle de ataque (modal) */}
      {selected && (
        <div className="modal-overlay" onClick={() => setSelected(null)}>
          <div className="modal" onClick={(e) => e.stopPropagation()}>
            <button className="modal-close" onClick={() => setSelected(null)}>✕</button>
            <h2>{selected.nombre}</h2>
            <p className="familia">{selected.familia_conductual} · {selected.categoria_automatizacion}</p>

            <h3>Qué es</h3>
            <p>{selected.descripcion}</p>

            <h3>Patrón técnico</h3>
            <p>{selected.patron_tecnico}</p>

            <h3>Señales usadas por el detector</h3>
            <ul>{(selected.senales_v3 || []).map((s, i) => <li key={i}>{s}</li>)}</ul>

            <h3>Métricas</h3>
            <div className="metrics-box">
              {metricRows(selected.metricas).map((m, i) => <Metric key={i} {...m} />)}
            </div>

            <h3>Limitaciones</h3>
            <p>{selected.limitaciones}</p>

            <h3>Para la defensa</h3>
            <p className="defensa">{defenseLine(selected)}</p>

            <h3>Documentos relacionados</h3>
            <ul className="docs">{(selected.documentos_relacionados || []).map((d, i) => <li key={i}><code>{d}</code></li>)}</ul>
          </div>
        </div>
      )}
    </div>
  );
}

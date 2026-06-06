import { useEffect, useState } from "react";
import { API_BASE } from "./config";

// --- Metadatos de presentación (estilo/texto; no son datos del backend) ---

const NAV = [
  { id: "mapa", label: "Mapa" },
  { id: "ataques", label: "Ataques" },
  { id: "detector", label: "Detector v5" },
  { id: "resultados", label: "Resultados" },
  { id: "ml", label: "ML baseline" },
  { id: "defensa", label: "Modo defensa" },
  { id: "ia", label: "IA" },
];

const ESTADO_META = {
  "fuerte": { label: "Fuerte", cls: "badge-fuerte" },
  "parcial": { label: "Parcial", cls: "badge-parcial" },
  "exploratorio": { label: "Exploratorio", cls: "badge-exploratorio" },
  "detectable con contexto largo (v5)": { label: "Contexto largo (v5)", cls: "badge-v5" },
};

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

const PASSES = [
  {
    n: "Pase 1", t: "Contexto local",
    items: [
      "Analiza trazas individuales con su contexto cercano (±30 filas).",
      "Detecta patrones básicos de ataque: atomicidad, ráfagas, concentración.",
    ],
  },
  {
    n: "Pase 2", t: "Contexto global por ventana",
    items: [
      "Mejora la distinción scan11 / scan44.",
      "Confirma udp_scan por dispersión de destinos.",
      "Reduce unknown_attack.",
    ],
  },
  {
    n: "Pase 3", t: "Contexto global por origen SSH", main: true,
    items: [
      "Detecta anomaly-sshscan mediante fan-out SSH.",
      "Un origen que contacta muchos destinos por el puerto 22.",
      "No usa IPs concretas ni etiquetas.",
      "Mejora sshscan en april.week2: precisión 0,999 / recall 0,907 / F1 0,951.",
    ],
  },
];

const DEFENSE = [
  { t: "1. Problema", d: "Detectar y explicar ataques en tráfico de red real, distinguiéndolos del ruido de fondo de un ISP." },
  { t: "2. Dataset UGR'16 y NetFlow", d: "Tráfico real de un ISP en flujos NetFlow: metadatos por flujo (IPs, puertos, bytes, paquetes, flags), sin payload." },
  { t: "3. Uso de LLMs / NotebookLM", d: "Interpretan patrones y generan hipótesis técnicas; NO detectan por sí mismos (se validan con código)." },
  { t: "4. Hipótesis conductuales", d: "Cada ataque se define por la localización de su automatización (origen, destino/red, servicios, coordinación)." },
  { t: "5. Clasificador v5", d: "Por traza, en 3 pases (local + global por ventana + global por origen SSH), con reglas interpretables." },
  { t: "6. Resultados", d: "Detección binaria fuerte (P 0,930 / R 0,991 en week1); escaneos bien detectados; sshscan recuperado en april con v5." },
  { t: "7. Comparación ML", d: "Random Forest alcanza F1 macro 0,95 como baseline; es supervisado y opaco, no sustituye a v5." },
  { t: "8. Limitaciones", d: "nerisbotnet/spam débiles; udp_scan sin generalización externa; FP de SSH en semanas sin sshscan etiquetado." },
  { t: "9. Conclusión", d: "LLMs + reglas conductuales = detección explicable y trazable. v5 es la versión final recomendada; v3, base estable." },
];

// Interpretación breve por ataque (presentación)
const INTERP = {
  "scan11": "Barrido vertical de un origen; detección robusta y generaliza.",
  "scan44": "Barrido vertical distribuido; el subtipo es menos estable entre semanas.",
  "anomaly-udpscan": "Escaneo UDP; recall casi perfecto, pero sin generalización externa (ausente en week2/april).",
  "dos": "Inundación TCP; se confunde en parte con el escaneo distribuido.",
  "nerisbotnet": "Coordinación C2; parcial. El split high/low confidence (v4) queda como línea futura.",
  "anomaly-sshscan": "Low-and-slow; la v5 lo detecta por fan-out SSH global (april.week2).",
  "anomaly-spam": "SMTP de bajo volumen; exploratorio, no resuelto (límite estructural).",
};

function fmt(x) {
  return x === undefined || x === null ? "—" : Number(x).toLocaleString("es-ES", { maximumFractionDigits: 3 });
}

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

// Métrica "principal" a mostrar en tablas (para sshscan, la fila v5)
function mainMetric(metricas) {
  const rows = metricRows(metricas);
  return rows[rows.length - 1] || {};
}

function defenseLine(a) {
  if (a.id === "anomaly-sshscan") {
    return "Caso clave: con contexto local (v3) era indetectable (0/0). El tercer pase global de la v5 detecta el escaneo horizontal SSH por su fan-out por origen (april.week2: F1 0,951). El límite era arquitectónico, no del enfoque conductual.";
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

function Badge({ estado }) {
  const em = ESTADO_META[estado] || { label: estado, cls: "badge-parcial" };
  return <span className={`badge ${em.cls}`}>{em.label}</span>;
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
        setHealth(h); setSummary(s); setAttacksData(a);
      } catch (e) {
        setError(`No se pudo conectar con el backend (${API_BASE}). Arráncalo con: uvicorn main:app --reload`);
      }
    }
    load();
  }, []);

  const ataques = attacksData?.ataques || [];
  const ml = summary?.comparacion_ml;

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
          <span className={`health-dot ${health ? "ok" : "down"}`}>
            {health ? `backend ok · API ${health.api_version}` : "backend no disponible"}
          </span>
        </div>
      </header>

      <nav className="nav">
        {NAV.map((n) => <a key={n.id} href={`#${n.id}`}>{n.label}</a>)}
      </nav>

      {error && <div className="banner-error">{error}</div>}

      {/* MAPA: flujo + resumen */}
      <section id="mapa" className="card-section">
        <h2>Flujo del proyecto</h2>
        <div className="flow">
          {FLOW.map((b, i) => (
            <div className="flow-step-wrap" key={b.t}>
              <div className={`flow-step ${b.t.includes("v5") ? "flow-step-main" : ""}`}>
                <strong>{b.t}</strong><span>{b.d}</span>
              </div>
              {i < FLOW.length - 1 && <span className="flow-arrow">→</span>}
            </div>
          ))}
        </div>

        <h2 style={{ marginTop: 28 }}>Resumen del proyecto</h2>
        {summary ? (
          <div className="summary-grid">
            <div>
              <h3>Objetivo</h3>
              <p>{summary.objetivo}</p>
              <h3>Idea clave</h3>
              <p className="idea-clave">
                Los LLMs ayudan a <em>interpretar y formalizar</em> patrones, pero la detección final
                es con <strong>reglas conductuales interpretables</strong> (sin ML, sin IPs concretas,
                sin usar la etiqueta para detectar).
              </p>
            </div>
            <div>
              <h3>Versiones</h3>
              <div className="version-boxes">
                <div className="version-box main">
                  <span className="tag">Principal</span><strong>v5 integrated</strong>
                  <span>{attacksData?.deteccion_binaria_v3 ? `binario P ${fmt(attacksData.deteccion_binaria_v3.precision)} · R ${fmt(attacksData.deteccion_binaria_v3.recall)}` : ""}</span>
                </div>
                <div className="version-box">
                  <span className="tag">Base estable</span><strong>v3</strong>
                  <span>local + global por ventana</span>
                </div>
              </div>
              <div className="timeline">
                {VERSIONS.map((v) => (
                  <div className={`tl-item ${v.final ? "tl-final" : ""}`} key={v.v}>
                    <div className="tl-dot">{v.v}</div>
                    <div className="tl-body"><strong>{v.t}</strong><span>{v.d}</span></div>
                  </div>
                ))}
              </div>
            </div>
          </div>
        ) : !error ? <p className="muted">Cargando resumen…</p> : null}
      </section>

      {/* ATAQUES: tarjetas + qué mira cada ataque */}
      <section id="ataques" className="card-section">
        <h2>Familias de ataque ({ataques.length})</h2>
        <div className="cards">
          {ataques.map((a) => {
            const best = mainMetric(a.metricas);
            return (
              <button className="attack-card" key={a.id} onClick={() => setSelected(a)}>
                <div className="card-head"><strong>{a.nombre}</strong><Badge estado={a.estado} /></div>
                <span className="familia">{a.familia_conductual}</span>
                <p className="desc">{a.descripcion}</p>
                <div className="card-metric">
                  {best.label || "métrica"}: P {fmt(best.precision)} · R {fmt(best.recall)}{best.f1 !== undefined ? ` · F1 ${fmt(best.f1)}` : ""}
                </div>
                <span className="ver-mas">ver detalle ▸</span>
              </button>
            );
          })}
        </div>

        <h2 style={{ marginTop: 28 }}>Qué mira cada ataque</h2>
        <div className="table-wrap">
          <table className="data-table">
            <thead><tr><th>Ataque</th><th>Familia</th><th>Señales usadas</th><th>Estado</th><th>Limitación</th></tr></thead>
            <tbody>
              {ataques.map((a) => (
                <tr key={a.id}>
                  <td><strong>{a.nombre}</strong></td>
                  <td>{a.familia_conductual}</td>
                  <td className="cell-list">{(a.senales_v3 || []).join("; ")}</td>
                  <td><Badge estado={a.estado} /></td>
                  <td className="muted">{a.limitaciones}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </section>

      {/* DETECTOR v5: 3 pases */}
      <section id="detector" className="card-section">
        <h2>Cómo funciona el clasificador v5</h2>
        <p className="muted">Tres pases en cascada, de lo local a lo global, todos con reglas interpretables.</p>
        <div className="passes">
          {PASSES.map((p) => (
            <div className={`pass ${p.main ? "pass-main" : ""}`} key={p.n}>
              <div className="pass-head"><span className="pass-n">{p.n}</span><strong>{p.t}</strong></div>
              <ul>{p.items.map((it, i) => <li key={i}>{it}</li>)}</ul>
            </div>
          ))}
        </div>
      </section>

      {/* RESULTADOS finales */}
      <section id="resultados" className="card-section">
        <h2>Resultados finales</h2>
        <div className="table-wrap">
          <table className="data-table">
            <thead><tr><th>Ataque</th><th>Familia</th><th>Estado</th><th>Precisión</th><th>Recall</th><th>F1</th><th>Interpretación</th></tr></thead>
            <tbody>
              {ataques.map((a) => {
                const m = mainMetric(a.metricas);
                return (
                  <tr key={a.id}>
                    <td><strong>{a.nombre}</strong></td>
                    <td>{a.familia_conductual}</td>
                    <td><Badge estado={a.estado} /></td>
                    <td>{fmt(m.precision)}</td>
                    <td>{fmt(m.recall)}</td>
                    <td>{m.f1 !== undefined ? fmt(m.f1) : "—"}</td>
                    <td className="muted">{INTERP[a.id] || ""}</td>
                  </tr>
                );
              })}
            </tbody>
          </table>
        </div>
        {attacksData?.deteccion_binaria_v3 && (
          <p className="muted" style={{ marginTop: 10 }}>
            Detección binaria (ataque/background) v5/v3 en week1: P {fmt(attacksData.deteccion_binaria_v3.precision)} ·
            R {fmt(attacksData.deteccion_binaria_v3.recall)} · F1 ≈ {fmt(attacksData.deteccion_binaria_v3.f1_ataque_aprox)}.
          </p>
        )}
      </section>

      {/* ML baseline */}
      <section id="ml" className="card-section">
        <h2>Comparación con ML clásico</h2>
        <div className="ml-box">
          <p>{ml?.objetivo || "Baseline académico predictivo, no sustituto de la v5."}</p>
          <ul>
            <li><strong>Mejor modelo:</strong> {ml?.mejor_modelo || "Random Forest (F1 macro ≈ 0,95)"}.</li>
            <li><strong>Modelos comparados:</strong> {(ml?.modelos || ["LogisticRegression", "KNN", "SVM", "RandomForest", "MLPClassifier"]).join(", ")}.</li>
            <li><strong>Por qué no sustituye a v5:</strong> el ML clásico es <em>supervisado</em> (usa la etiqueta para entrenar), <em>opaco</em> y depende de features correlacionadas; la v5 usa <strong>reglas conductuales explicables</strong>, sin etiquetas para detectar.</li>
          </ul>
          {ml?.conclusion && <p className="idea-clave">{ml.conclusion}</p>}
        </div>
      </section>

      {/* Modo defensa */}
      <section id="defensa" className="card-section">
        <h2>Modo defensa · 15 minutos</h2>
        <p className="muted">Guion compacto para la presentación.</p>
        <div className="defense">
          {DEFENSE.map((d, i) => (
            <div className="defense-item" key={i}>
              <strong>{d.t}</strong><span>{d.d}</span>
            </div>
          ))}
        </div>
      </section>

      {/* IA */}
      <section id="ia" className="card-section">
        <h2>Modo IA</h2>
        <div className="ia-grid">
          <div className="ia-panel active">
            <h3>IA OFF · activo</h3>
            <p>La web funciona con datos locales servidos por el backend. No requiere conexión a ningún LLM.</p>
          </div>
          <div className="ia-panel pending">
            <h3>IA ON · NotebookLM (pendiente)</h3>
            <p>Espacio reservado para consultas explicativas al LLM. Aún no integrado.</p>
            <div className="ia-placeholder">Chat / consultas — próximamente</div>
          </div>
        </div>
      </section>

      <footer className="foot">
        TFG · {summary?.titulo || "Detección explicativa de anomalías NetFlow con LLMs"} · Modo IA OFF
      </footer>

      {/* Detalle de ataque (modal) */}
      {selected && (
        <div className="modal-overlay" onClick={() => setSelected(null)}>
          <div className="modal" onClick={(e) => e.stopPropagation()}>
            <button className="modal-close" onClick={() => setSelected(null)}>✕</button>
            <h2>{selected.nombre}</h2>
            <p className="familia">{selected.familia_conductual} · {selected.categoria_automatizacion}</p>
            <h3>Qué es</h3><p>{selected.descripcion}</p>
            <h3>Patrón técnico</h3><p>{selected.patron_tecnico}</p>
            <h3>Señales usadas por el detector</h3>
            <ul>{(selected.senales_v3 || []).map((s, i) => <li key={i}>{s}</li>)}</ul>
            <h3>Métricas</h3>
            <div className="metrics-box">{metricRows(selected.metricas).map((m, i) => <Metric key={i} {...m} />)}</div>
            <h3>Limitaciones</h3><p>{selected.limitaciones}</p>
            <h3>Para la defensa</h3><p className="defensa">{defenseLine(selected)}</p>
            <h3>Documentos relacionados</h3>
            <ul className="docs">{(selected.documentos_relacionados || []).map((d, i) => <li key={i}><code>{d}</code></li>)}</ul>
          </div>
        </div>
      )}
    </div>
  );
}

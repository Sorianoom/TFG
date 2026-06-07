import FloatingAttacks from "./FloatingAttacks";
import ClassifierRunner from "./ClassifierRunner";
import { PASSES, VERSIONS, INTERP, ML_COMPARISON, V5_FAMILY, V5_BINARY, estadoMeta } from "../attackMeta";
import { mainMetric, fmt } from "../format";
import { navigate } from "../useHashRoute";

export default function Home({ attacks }) {
  return (
    <>
      <section className="hero">
        <h1 className="hero-title">Detección explicativa de anomalías NetFlow con LLMs</h1>
        <p className="hero-sub">
          Un sistema interactivo para explorar cómo los LLMs ayudan a interpretar tráfico UGR'16,
          formalizar patrones conductuales y construir un clasificador contextual v5 basado en reglas
          explicables.
        </p>

        <FloatingAttacks attacks={attacks} />

        <a className="scroll-hint" href="#detalles">cómo funciona ↓</a>
      </section>

      <div className="home-sections" id="detalles">
        {/* Probar el clasificador v5 (subida de CSV) */}
        <ClassifierRunner />

        {/* Cómo funciona el clasificador v5 */}
        <section className="csec">
          <h2 className="csec-title">Cómo funciona el clasificador v5</h2>
          <div className="passes">
            {PASSES.map((p) => (
              <div className={`pass ${p.main ? "pass-main" : ""}`} key={p.n}>
                <span className="pass-n">{p.n}</span>
                <strong>{p.t}</strong>
                <span className="muted">{p.d}</span>
              </div>
            ))}
          </div>
        </section>

        {/* Resultados finales */}
        <section className="csec">
          <h2 className="csec-title">Resultados finales</h2>
          <div className="results-cards">
            {attacks.map((a) => {
              const m = mainMetric(a.metricas);
              const em = estadoMeta(a.estado);
              return (
                <button className="res-card" key={a.id} onClick={() => navigate(`#/attacks/${a.id}`)} style={{ "--ec": em.color }}>
                  <div className="res-head">
                    <strong>{a.nombre}</strong>
                    <span className="res-badge">{em.label}</span>
                  </div>
                  <span className="res-fam">{a.familia_conductual}</span>
                  <span className="res-metric">P {fmt(m.precision)} · R {fmt(m.recall)}{m.f1 !== undefined ? ` · F1 ${fmt(m.f1)}` : ""}</span>
                  <span className="res-interp">{INTERP[a.id]}</span>
                </button>
              );
            })}
          </div>
        </section>

        {/* Comparaciones */}
        <section className="csec">
          <h2 className="csec-title">Comparaciones</h2>
          <p className="csec-lead">
            Para que la comparación sea lo más justa posible, miramos la clasificación por familias de
            ataque, no solo "ataque o tráfico normal". Aun así no es del todo equivalente, y lo explicamos:
            los modelos ML se resumen en un único número sobre una muestra equilibrada, mientras que la v5
            se entiende mejor familia por familia.
          </p>

          <div className="cmp-grid">
            <div className="cmp-chart">
              <h3 className="cmp-h3">ML clásico — F1 macro</h3>
              <p className="muted small">
                Una barra por modelo. F1 macro = media del F1 entre las 8 clases (incluye tráfico normal;
                no incluye SSH Scan), sobre una muestra equilibrada (~2778 ejemplos por clase).
              </p>
              {ML_COMPARISON.map((m) => (
                <div className="bar-row" key={m.name}>
                  <span className="bar-label">{m.name} <span className="muted">· {m.note}</span></span>
                  <span className="bar-track">
                    <span className="bar-fill" style={{ width: `${m.f1 * 100}%` }} />
                  </span>
                  <span className="bar-val">{fmt(m.f1)}</span>
                </div>
              ))}
              <p className="cmp-note">
                Random Forest se estudió como baseline fuerte, pero se deja fuera de esta visualización
                principal para no desplazar el foco hacia un modelo supervisado especialmente potente.
              </p>
            </div>

            <div className="cmp-chart cmp-v5col">
              <h3 className="cmp-h3">v5 — F1 por familia</h3>
              <p className="muted small">
                Una barra por familia de ataque, con la semana en la que se mide. Cada familia tiene una
                dificultad distinta.
              </p>
              {V5_FAMILY.map((f) => (
                <div className="bar-row" key={f.name} title={`precisión ${fmt(f.p)} · recall ${fmt(f.r)}`}>
                  <span className="bar-label">
                    {f.name} <span className="ds-tag">{f.dataset}</span>
                  </span>
                  <span className="bar-track">
                    <span className="bar-fill v5" style={{ width: `${f.f1 * 100}%` }} />
                  </span>
                  <span className="bar-val">{fmt(f.f1)}</span>
                </div>
              ))}
              <p className="cmp-note">
                La v5 no se resume en un único F1 macro en esta vista porque sus familias se validan en
                escenarios diferentes: el núcleo en august.week1 y el SSH Scan en april.week2. Ningún
                conjunto de datos contiene todas las familias a la vez, así que un único promedio mezclaría
                semanas distintas.
              </p>
            </div>
          </div>

          <div className="cmp-interp">
            Los modelos ML se entrenan con etiquetas y se resumen con F1 macro multiclase sobre una muestra
            balanceada. La v5 aplica reglas explicables y sus resultados se leen mejor por familia, porque
            cada familia tiene una dificultad distinta. Como contexto, la v5 distingue ataque de tráfico
            normal con F1 {fmt(V5_BINARY.f1)} y recall {fmt(V5_BINARY.recall)} ({V5_BINARY.dataset}), y
            además explica por qué marca cada caso.
          </div>
        </section>

        {/* Versiones del clasificador */}
        <section className="csec">
          <h2 className="csec-title">Versiones del clasificador</h2>
          <div className="timeline">
            {VERSIONS.map((v) => (
              <div className={`tl-item ${v.final ? "tl-final" : ""}`} key={v.v}>
                <div className="tl-dot">{v.v}</div>
                <div className="tl-body"><strong>{v.t}</strong><span>{v.d}</span></div>
              </div>
            ))}
          </div>
        </section>

        {/* IA mini */}
        <section className="csec">
          <div className="ia-mini">
            <span className="ia-mini-pill">IA explicativa — próximamente</span>
            <span className="muted">Integración con NotebookLM para consultas en lenguaje natural (aún no activa).</span>
          </div>
        </section>
      </div>
    </>
  );
}

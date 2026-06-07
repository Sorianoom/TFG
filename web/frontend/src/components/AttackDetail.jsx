import { useEffect } from "react";
import AttackDiagram from "./AttackDiagram";
import AttackSimulator from "./AttackSimulator";
import { estadoMeta, TECH, NOT_USED_COMMON } from "../attackMeta";
import { navigate } from "../useHashRoute";
import { fmt, metricRows } from "../format";

export default function AttackDetail({ attack }) {
  useEffect(() => {
    window.scrollTo(0, 0);
  }, [attack?.id]);

  if (!attack) {
    return (
      <div className="detail">
        <button className="detail-back" onClick={() => navigate("#/")}>← Volver</button>
        <p className="muted">Ataque no encontrado.</p>
      </div>
    );
  }

  const em = estadoMeta(attack.estado);
  const rows = metricRows(attack.metricas);
  const isSsh = attack.id === "anomaly-sshscan";
  const tech = TECH[attack.id] || {};
  const notUsed = [...NOT_USED_COMMON, ...(tech.not_used || [])];

  return (
    <div className="detail">
      <button className="detail-back" onClick={() => navigate("#/")}>← Volver a la portada</button>

      <header className="detail-head" style={{ "--ec": em.color }}>
        <div>
          <h1>{attack.nombre}</h1>
          <p className="detail-fam">{attack.familia_conductual} · {attack.categoria_automatizacion}</p>
        </div>
        <span className="badge-estado" style={{ "--ec": em.color }}>{em.label}</span>
      </header>

      <p className="detail-lead">{attack.descripcion}</p>

      <div className="diagram-wrap">
        <AttackDiagram id={attack.id} accent={em.color} />
        <span className="diagram-cap">Patrón conductual (esquemático)</span>
      </div>

      <div className="detail-stack">
        {tech.plain_explanation && (
          <section className="detail-block plain-block">
            <h2>En palabras simples</h2>
            <p>{tech.plain_explanation}</p>
          </section>
        )}

        {tech.technical_features && (
          <section className="detail-block">
            <h2>Características que mira el detector</h2>
            <div className="feature-grid">
              {tech.technical_features.map((f, i) => (
                <div className="feature-card" key={i}>
                  <strong>{f.name}</strong>
                  <span className="feature-desc">{f.description}</span>
                  <span className="feature-why"><em>Por qué importa:</em> {f.why_it_matters}</span>
                </div>
              ))}
            </div>
          </section>
        )}

        {tech.detection_steps && (
          <section className="detail-block">
            <h2>Proceso de detección</h2>
            <ol className="steps">
              {tech.detection_steps.map((s, i) => <li key={i}>{s}</li>)}
            </ol>
          </section>
        )}

        {tech.rule_pseudocode && (
          <section className="detail-block">
            <h2>Regla simplificada</h2>
            <p className="muted small">Pseudocódigo ilustrativo: resume la lógica, no es el script real completo.</p>
            <pre className="code-block"><code>{tech.rule_pseudocode}</code></pre>
          </section>
        )}

        <section className="detail-block">
          <h2>Qué no usa</h2>
          <p className="muted small">El detector se basa en el comportamiento del tráfico, no en estos atajos:</p>
          <div className="chips">
            {notUsed.map((n, i) => <span className="chip-no" key={i}>✕ {n}</span>)}
          </div>
        </section>

        <section className="detail-block">
          <h2>¿Cómo se ve en una tabla NetFlow?</h2>
          <p>{attack.patron_tecnico}</p>
          <p className="muted small">
            NetFlow es el resumen de cada conexión de red (quién habla con quién, por qué puerto,
            cuántos paquetes y bytes), <strong>sin el contenido del mensaje</strong>. Cada fila de la
            tabla es una conexión. Puedes ver una tabla de ejemplo de este patrón en
            “Simulación del patrón”, más abajo.
          </p>
        </section>

        <section className="detail-block">
          <h2>Métricas</h2>
          {isSsh ? (
            <div className="ssh-metrics">
              <div className="ssh-card v3">
                <span className="ssh-tag">v3 estándar (solo contexto local)</span>
                <strong>P 0 · R 0 · F1 0</strong>
                <span className="muted">Indetectable: mirando solo el contexto cercano, el sondeo lento no deja señal.</span>
              </div>
              <div className="ssh-card v5">
                <span className="ssh-tag">v5 integrated · april.week2</span>
                <strong>P 0,999 · R 0,907 · F1 0,951</strong>
                <span className="muted">Detectado mirando el comportamiento global de cada origen (su fan-out al puerto 22).</span>
              </div>
            </div>
          ) : (
            <div className="metrics-box">
              {rows.map((m, i) => (
                <div className="metric-row" key={i}>
                  <span className="metric-label">{m.label}</span>
                  <span>P {fmt(m.precision)}</span>
                  <span>R {fmt(m.recall)}</span>
                  <span>F1 {fmt(m.f1)}</span>
                </div>
              ))}
            </div>
          )}
          <p className="muted small">
            Precisión = qué parte de las alertas son correctas. Recall = qué parte de los ataques reales
            se detectan. F1 = ambas combinadas en un solo número.
          </p>
        </section>

        {tech.validation_context && (
          <section className="detail-block">
            <h2>Contexto de validación</h2>
            <p>{tech.validation_context}</p>
          </section>
        )}

        <section className="detail-block">
          <h2>Limitaciones</h2>
          <p>{attack.limitaciones}</p>
          {isSsh && (
            <p className="note-ssh">
              Matiz honesto: en semanas sin <code>anomaly-sshscan</code> etiquetado, este pase puede
              marcar escáneres SSH de fondo que están etiquetados como tráfico normal (background) pero
              que se comportan como un escaneo. Se interpretan como posibles anomalías no etiquetadas,
              no como un fallo del enfoque.
            </p>
          )}
        </section>

        {tech.defense_explanation && (
          <section className="detail-block defense-block">
            <h2>Para explicarlo al tribunal</h2>
            <p>{tech.defense_explanation}</p>
          </section>
        )}

        <section className="detail-block">
          <h2>¿Qué papel tiene NotebookLM en este ataque?</h2>
          <p>
            Este ataque tiene <strong>su propio cuaderno de NotebookLM</strong>: un modelo de lenguaje al
            que se le ha dado la documentación y los resúmenes de <strong>{attack.nombre}</strong>. Cuando
            activas el <strong>modo IA ON</strong>:
          </p>
          <ul>
            <li>El <strong>chat</strong> (abajo a la derecha) responde tus preguntas consultando ese cuaderno.</li>
            <li>El <strong>simulador</strong> le pide a ese cuaderno el patrón y unos rangos realistas; el backend genera las filas manteniendo la forma del ataque.</li>
          </ul>
          <p className="muted small">
            NotebookLM <strong>no decide la detección</strong> ni inventa datos libremente: aporta
            interpretación y contexto. Quien detecta son las reglas explicables del clasificador v5.
          </p>
        </section>

        <AttackSimulator attack={attack} />
      </div>
    </div>
  );
}

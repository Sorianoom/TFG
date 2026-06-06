import { useRef, useState } from "react";
import { ATTACK_ORDER, SHORT_NAME, FLOAT_POS, estadoMeta } from "../attackMeta";
import { navigate } from "../useHashRoute";

// Zona central: burbujas de ataque flotando, con parallax suave según el ratón.
export default function FloatingAttacks({ attacks }) {
  const [par, setPar] = useState({ x: 0, y: 0 });
  const ref = useRef(null);

  const byId = Object.fromEntries(attacks.map((a) => [a.id, a]));
  const ordered = ATTACK_ORDER.map((id) => byId[id]).filter(Boolean);

  function onMove(e) {
    const r = ref.current?.getBoundingClientRect();
    if (!r) return;
    // desplazamiento normalizado [-1, 1] respecto al centro
    const nx = (e.clientX - (r.left + r.width / 2)) / (r.width / 2);
    const ny = (e.clientY - (r.top + r.height / 2)) / (r.height / 2);
    setPar({ x: nx, y: ny });
  }
  function onLeave() {
    setPar({ x: 0, y: 0 });
  }

  return (
    <div className="floating" ref={ref} onMouseMove={onMove} onMouseLeave={onLeave}>
      {ordered.map((a, i) => {
        const pos = FLOAT_POS[a.id] || { left: 50, top: 50, depth: 1 };
        const em = estadoMeta(a.estado);
        const px = -par.x * pos.depth * 14;
        const py = -par.y * pos.depth * 14;
        return (
          <button
            key={a.id}
            className="bubble-wrap"
            style={{ left: `${pos.left}%`, top: `${pos.top}%`, transform: `translate(${px}px, ${py}px)` }}
            onClick={() => navigate(`#/attacks/${a.id}`)}
            aria-label={`Ver detalle de ${a.nombre}`}
          >
            <span
              className={`bubble ${a.id === "anomaly-sshscan" ? "bubble-key" : ""}`}
              style={{ animationDuration: `${6 + (i % 4)}s`, animationDelay: `${(i % 5) * 0.6}s` }}
            >
              <span className="bubble-inner" style={{ "--ec": em.color }}>
                <span className="b-dot" />
                <span className="b-name">{SHORT_NAME[a.id] || a.nombre}</span>
                <span className="b-fam">{a.familia_conductual}</span>
                <span className="b-badge">{em.label}</span>
              </span>
            </span>
          </button>
        );
      })}
    </div>
  );
}

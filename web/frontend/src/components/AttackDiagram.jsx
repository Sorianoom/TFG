// Diagrama SVG simple del patrón conductual de cada ataque.
// No pretende ser exacto: ilustra la forma del tráfico (origen/destino/coordinación).

const W = 360;
const H = 180;
const LINE = "#3a4355";

function Node({ x, y, r = 15, label, fill = "#1c2230", stroke = "#3a4355", accent }) {
  return (
    <g>
      <circle cx={x} cy={y} r={r} fill={fill} stroke={accent || stroke} strokeWidth="1.5" />
      {label && (
        <text x={x} y={y + r + 13} textAnchor="middle" className="diag-label">
          {label}
        </text>
      )}
    </g>
  );
}

function Line({ x1, y1, x2, y2, accent, dashed }) {
  return (
    <line
      x1={x1} y1={y1} x2={x2} y2={y2}
      stroke={accent || LINE} strokeWidth="1.4"
      strokeDasharray={dashed ? "4 4" : undefined} opacity="0.75"
    />
  );
}

function FanOut({ accent, portLabel }) {
  // 1 origen -> muchos destinos
  const sx = 56, sy = H / 2;
  const ys = [28, 64, 100, 136];
  const dx = 300;
  return (
    <>
      {ys.map((y, i) => <Line key={i} x1={sx} y1={sy} x2={dx} y2={y} accent={accent} />)}
      <Node x={sx} y={sy} r={17} label="origen" accent={accent} fill="#20303a" />
      {ys.map((y, i) => <Node key={i} x={dx} y={y} r={11} accent={accent} />)}
      <text x={dx} y={H - 6} textAnchor="middle" className="diag-label">{portLabel}</text>
    </>
  );
}

export default function AttackDiagram({ id, accent }) {
  let body = null;

  if (id === "scan11" || id === "scan44") {
    const sources = id === "scan11" ? [H / 2] : [40, 90, 140];
    const ports = [44, 70, 96, 122];
    const sx = 56;
    const hostX = 252;
    body = (
      <>
        {sources.map((sy, si) =>
          ports.map((py, pi) => (
            <Line key={`${si}-${pi}`} x1={sx} y1={sy} x2={hostX} y2={py} accent={accent} />
          ))
        )}
        {sources.map((sy, si) => (
          <Node key={si} x={sx} y={sy} r={13} label={si === sources.length - 1 ? "orígenes" : ""} accent={accent} fill="#20303a" />
        ))}
        <rect x={hostX - 4} y={28} width={84} height={112} rx={10} fill="#161b22" stroke="#3a4355" />
        {ports.map((py, pi) => (
          <circle key={pi} cx={hostX + 38} cy={py} r={7} fill="#1c2230" stroke={accent} strokeWidth="1.3" />
        ))}
        <text x={hostX + 38} y={H - 6} textAnchor="middle" className="diag-label">host · muchos puertos</text>
      </>
    );
  } else if (id === "anomaly-udpscan") {
    body = <FanOut accent={accent} portLabel="destinos UDP" />;
  } else if (id === "anomaly-sshscan") {
    body = <FanOut accent={accent} portLabel="destinos · puerto 22" />;
  } else if (id === "dos") {
    // muchos flujos -> un servicio
    const ys = [28, 64, 100, 136];
    const sx = 56, tx = 296, ty = H / 2;
    body = (
      <>
        {ys.map((y, i) => <Line key={i} x1={sx} y1={y} x2={tx} y2={ty} accent={accent} />)}
        {ys.map((y, i) => <Node key={i} x={sx} y={y} r={10} accent={accent} />)}
        <Node x={tx} y={ty} r={22} label="servicio objetivo" accent={accent} fill="#2a1d1d" />
      </>
    );
  } else if (id === "nerisbotnet") {
    // malla de nodos -> C2 central
    const cx = W / 2, cy = H / 2;
    const bots = [
      { x: 60, y: 40 }, { x: 60, y: 140 }, { x: 300, y: 40 },
      { x: 300, y: 140 }, { x: 40, y: 90 }, { x: 320, y: 90 },
    ];
    body = (
      <>
        {bots.map((b, i) => <Line key={`c${i}`} x1={cx} y1={cy} x2={b.x} y2={b.y} accent={accent} dashed />)}
        {bots.map((b, i) => <Node key={i} x={b.x} y={b.y} r={11} accent={accent} />)}
        <Node x={cx} y={cy} r={20} label="coordinación / C2" accent={accent} fill="#20303a" />
      </>
    );
  }

  return (
    <svg className="attack-diagram" viewBox={`0 0 ${W} ${H}`} role="img" aria-label={`Diagrama del patrón de ${id}`}>
      {body}
    </svg>
  );
}

import { useEffect, useState } from "react";
import { API_BASE } from "./config";
import { useHashRoute, parseAttackId } from "./useHashRoute";
import Home from "./components/Home";
import AttackDetail from "./components/AttackDetail";

export default function App() {
  const [health, setHealth] = useState(null);
  const [summary, setSummary] = useState(null);
  const [attacksData, setAttacksData] = useState(null);
  const [error, setError] = useState(null);
  const hash = useHashRoute();

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

  const attacks = attacksData?.ataques || [];
  const attackId = parseAttackId(hash);

  return (
    <div className="app">
      {error && <div className="banner-error">{error}</div>}

      {!attacksData && !error && <div className="loading">Cargando…</div>}

      {attacksData && (
        attackId
          ? <AttackDetail attack={attacks.find((a) => a.id === attackId)} />
          : <Home attacks={attacks} />
      )}

      <footer className="foot">
        <span>TFG · Detección explicativa de anomalías NetFlow (UGR'16) · clasificador v5 · modo IA OFF</span>
        <span className={`health-dot ${health ? "ok" : "down"}`} title={API_BASE}>
          {health ? "backend ok" : "backend off"}
        </span>
      </footer>
    </div>
  );
}

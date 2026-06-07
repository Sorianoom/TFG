import { useEffect, useState } from "react";
import { API_BASE } from "./config";
import { useHashRoute, parseAttackId } from "./useHashRoute";
import { useAiMode } from "./aiMode";
import AiToggle from "./components/AiToggle";
import Home from "./components/Home";
import AttackDetail from "./components/AttackDetail";
import FloatingAttackChat from "./components/FloatingAttackChat";

export default function App() {
  const [health, setHealth] = useState(null);
  const [attacksData, setAttacksData] = useState(null);
  const [aiStatus, setAiStatus] = useState(null);
  const [error, setError] = useState(null);
  const hash = useHashRoute();
  const [aiMode] = useAiMode();

  useEffect(() => {
    async function load() {
      try {
        const [h, a, ai] = await Promise.all([
          fetch(`${API_BASE}/api/health`).then((r) => r.json()),
          fetch(`${API_BASE}/api/attacks`).then((r) => r.json()),
          fetch(`${API_BASE}/api/ai/status`).then((r) => r.json()).catch(() => null),
        ]);
        setHealth(h); setAttacksData(a); setAiStatus(ai);
      } catch (e) {
        setError(`No se pudo conectar con el backend (${API_BASE}). Arráncalo con: uvicorn main:app --reload`);
      }
    }
    load();
  }, []);

  const attacks = attacksData?.ataques || [];
  const attackId = parseAttackId(hash);
  const currentAttack = attackId ? attacks.find((a) => a.id === attackId) : null;
  const iaOnUnavailable = aiMode === "on" && aiStatus && !aiStatus.ia_on_available;

  return (
    <div className="app">
      <div className="topbar-global">
        <a className="brand" href="#/">NetFlow · UGR'16 · v5</a>
        <AiToggle aiStatus={aiStatus} />
      </div>

      {iaOnUnavailable && (
        <div className="banner-warn">
          Modo IA ON activado, pero NotebookLM no está disponible ({aiStatus?.reason}). La web sigue
          funcionando en modo IA OFF (plantillas locales y respuestas básicas).
        </div>
      )}

      {error && <div className="banner-error">{error}</div>}

      {!attacksData && !error && <div className="loading">Cargando…</div>}

      {attacksData && (
        attackId
          ? <AttackDetail attack={currentAttack} />
          : <Home attacks={attacks} />
      )}

      {currentAttack && <FloatingAttackChat attack={currentAttack} aiStatus={aiStatus} />}

      <footer className="foot">
        <span>TFG · Detección explicativa de anomalías NetFlow (UGR'16) · clasificador v5</span>
        <span className={`health-dot ${health ? "ok" : "down"}`} title={API_BASE}>
          {health ? "backend ok" : "backend off"}
        </span>
      </footer>
    </div>
  );
}

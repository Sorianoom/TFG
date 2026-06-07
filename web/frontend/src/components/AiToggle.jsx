import { useAiMode } from "../aiMode";

// Interruptor global Modo IA: OFF / ON. Se muestra arriba en todas las páginas.
export default function AiToggle({ aiStatus }) {
  const [mode, setMode] = useAiMode();
  const available = !!aiStatus?.ia_on_available;
  const on = mode === "on";

  return (
    <div className="ai-toggle">
      <span className="ai-toggle-label">Modo IA</span>
      <button
        className={`ai-switch ${on ? "on" : "off"}`}
        role="switch"
        aria-checked={on}
        onClick={() => setMode(on ? "off" : "on")}
        title={available ? "NotebookLM disponible" : (aiStatus?.reason || "NotebookLM no disponible")}
      >
        <span className="ai-switch-track"><span className="ai-switch-knob" /></span>
        <span className="ai-switch-text">{on ? "ON" : "OFF"}</span>
      </button>
      {on && !available && (
        <span className="ai-toggle-warn" title={aiStatus?.reason}>IA ON no disponible · usando IA OFF</span>
      )}
    </div>
  );
}

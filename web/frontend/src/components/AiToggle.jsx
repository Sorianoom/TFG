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
        title={
          on
            ? "IA ON: consulta los cuadernos de NotebookLM (puede tardar). Clic para volver a IA OFF."
            : "IA OFF: rápido y local, sin NotebookLM. Clic para activar IA ON."
            + (available ? "" : ` (NotebookLM ahora mismo: ${aiStatus?.reason || "no disponible"})`)
        }
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

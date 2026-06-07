import { useState } from "react";
import { API_BASE } from "../config";
import { useAiMode } from "../aiMode";
import { TECH } from "../attackMeta";

// Chat contextual flotante (esquina inferior derecha). Usa el ataque actual como
// contexto: en IA ON consulta el cuaderno NotebookLM de ese ataque; en IA OFF
// responde con la explicación local del propio ataque.
export default function FloatingAttackChat({ attack, aiStatus }) {
  const [mode] = useAiMode();
  const [open, setOpen] = useState(false);
  const [question, setQuestion] = useState("");
  const [history, setHistory] = useState([]);   // [{role:'user'|'bot', text, source}]
  const [loading, setLoading] = useState(false);

  if (!attack) return null;

  const tech = TECH[attack.id] || {};
  const localAnswer =
    tech.plain_explanation || tech.defense_explanation ||
    `${attack.descripcion || ""}`.trim() ||
    "No hay explicación local disponible para este ataque.";

  const attackIaReady =
    !!aiStatus?.ia_on_available && (aiStatus?.configured_attacks || []).includes(attack.id);

  function pushBot(text, source) {
    setHistory((h) => [...h, { role: "bot", text, source }]);
  }

  async function send() {
    const q = question.trim();
    if (!q || loading) return;
    setHistory((h) => [...h, { role: "user", text: q }]);
    setQuestion("");

    if (mode !== "on") {
      pushBot(
        `${localAnswer}\n\nActiva IA ON para consultar el cuaderno NotebookLM de este ataque.`,
        "local"
      );
      return;
    }
    if (!attackIaReady) {
      pushBot(
        "NotebookLM no está disponible para este ataque. Puedes usar IA OFF.\n\n" + localAnswer,
        "aviso"
      );
      return;
    }

    setLoading(true);
    try {
      const res = await fetch(`${API_BASE}/api/notebooklm/chat`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ attack_id: attack.id, question: q }),
      });
      const data = await res.json();
      if (!res.ok) {
        const d = typeof data.detail === "object" ? data.detail : { message: String(data.detail || "Error") };
        pushBot([d.message, d.reason, d.suggestion].filter(Boolean).join(" "), "aviso");
      } else {
        pushBot(data.answer, "notebooklm");
      }
    } catch {
      pushBot(`No se pudo conectar con el backend (${API_BASE}).`, "aviso");
    } finally {
      setLoading(false);
    }
  }

  if (!open) {
    return (
      <button className="fchat-launch" onClick={() => setOpen(true)} aria-label="Abrir chat del ataque">
        💬 Preguntar
      </button>
    );
  }

  return (
    <div className="fchat-panel" role="dialog" aria-label={`Chat sobre ${attack.nombre}`}>
      <div className="fchat-head">
        <div>
          <strong>Preguntar sobre {attack.nombre}</strong>
          <span className={`fchat-mode ${mode === "on" ? "on" : "off"}`}>
            IA {mode === "on" ? "ON" : "OFF"}
          </span>
        </div>
        <button className="fchat-close" onClick={() => setOpen(false)} aria-label="Cerrar chat">✕</button>
      </div>

      <div className="fchat-body">
        {history.length === 0 && (
          <p className="fchat-hint">
            {mode === "on"
              ? (attackIaReady
                  ? "Pregunta lo que quieras: consultaré el cuaderno NotebookLM de este ataque."
                  : "IA ON activo pero este ataque no tiene cuaderno; responderé con la explicación local.")
              : "Modo IA OFF: respondo con la explicación local del ataque."}
          </p>
        )}
        {history.map((m, i) => (
          <div key={i} className={`fchat-msg ${m.role} ${m.source || ""}`}>
            {m.role === "bot" && (
              <span className="fchat-src">
                {m.source === "notebooklm" ? "NotebookLM" : m.source === "aviso" ? "Aviso" : "Local"}
              </span>
            )}
            <p>{m.text}</p>
          </div>
        ))}
        {loading && <div className="fchat-msg bot"><p className="fchat-loading">Consultando NotebookLM…</p></div>}
      </div>

      <div className="fchat-bar">
        <input
          type="text"
          placeholder={`Ej.: ¿por qué ${attack.nombre} es difícil de detectar?`}
          value={question}
          onChange={(e) => setQuestion(e.target.value)}
          onKeyDown={(e) => { if (e.key === "Enter") send(); }}
          disabled={loading}
        />
        <button className="fchat-send" onClick={send} disabled={loading || !question.trim()}>Enviar</button>
      </div>
    </div>
  );
}

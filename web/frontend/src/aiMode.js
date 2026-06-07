import { useEffect, useState } from "react";

// Estado global del modo IA (OFF/ON), persistido en localStorage y compartido
// entre componentes mediante un evento personalizado.
const KEY = "tfg_ai_mode";

export function getAiMode() {
  try {
    return localStorage.getItem(KEY) === "on" ? "on" : "off";
  } catch {
    return "off";
  }
}

export function setAiMode(mode) {
  const m = mode === "on" ? "on" : "off";
  try {
    localStorage.setItem(KEY, m);
  } catch {
    /* ignore */
  }
  window.dispatchEvent(new CustomEvent("aimodechange", { detail: m }));
}

export function useAiMode() {
  const [mode, setMode] = useState(getAiMode);
  useEffect(() => {
    const handler = () => setMode(getAiMode());
    window.addEventListener("aimodechange", handler);
    window.addEventListener("storage", handler);
    return () => {
      window.removeEventListener("aimodechange", handler);
      window.removeEventListener("storage", handler);
    };
  }, []);
  return [mode, setAiMode];
}

import { useEffect, useState } from "react";

// Router por hash mínimo, sin dependencias.
// Rutas: "#/" (home) y "#/attacks/<id>" (detalle).
export function useHashRoute() {
  const [hash, setHash] = useState(() => window.location.hash || "#/");
  useEffect(() => {
    const onChange = () => setHash(window.location.hash || "#/");
    window.addEventListener("hashchange", onChange);
    return () => window.removeEventListener("hashchange", onChange);
  }, []);
  return hash;
}

export function navigate(to) {
  window.location.hash = to;
}

// Devuelve el id de ataque si la ruta es "#/attacks/<id>", si no null.
export function parseAttackId(hash) {
  const m = (hash || "").match(/^#\/attacks\/([^/?#]+)/);
  return m ? decodeURIComponent(m[1]) : null;
}

// URL base del backend FastAPI.
// - En desarrollo (vite dev): http://127.0.0.1:8000 (backend en otro puerto).
// - En producción (build servido por el propio backend): "" -> llamadas relativas a /api/...
// Se puede forzar con VITE_API_BASE (o VITE_API_BASE_URL) en un .env.
const isDev = import.meta.env.DEV;
export const API_BASE =
  import.meta.env.VITE_API_BASE ||
  import.meta.env.VITE_API_BASE_URL ||
  (isDev ? "http://127.0.0.1:8000" : "");

// Alias por compatibilidad con el nombre sugerido.
export const API_BASE_URL = API_BASE;

// URL base del backend FastAPI.
// Se puede cambiar creando un archivo .env con: VITE_API_BASE=http://otra-url
export const API_BASE = import.meta.env.VITE_API_BASE || "http://127.0.0.1:8000";

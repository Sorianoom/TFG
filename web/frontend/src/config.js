// URL base del backend FastAPI.
// - En desarrollo: http://127.0.0.1:8000
// - En producción: se configura mediante una variable de entorno de Vercel.
const isDev = import.meta.env.DEV;

export const API_BASE =
  import.meta.env.VITE_API_BASE ||
  import.meta.env.VITE_API_BASE_URL ||
  (isDev ? "http://127.0.0.1:8000" : "");

export const API_BASE_URL = API_BASE;
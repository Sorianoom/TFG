import { defineConfig } from "vite";
import react from "@vitejs/plugin-react";

// Frontend del TFG (modo IA OFF). Puerto 5173 para coincidir con el CORS del backend.
export default defineConfig({
  plugins: [react()],
  server: {
    port: 5173,
    host: true,
  },
});

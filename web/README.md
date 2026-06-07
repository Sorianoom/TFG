# web/ — Web interactiva del TFG

Web pública y explicativa de la detección de anomalías NetFlow (UGR'16) con LLMs + clasificador
contextual **v5** (base estable: v3). Pensada para profesores/tribunal: lenguaje claro, jerga
explicada.

```text
web/
├── backend/   # API FastAPI (datos, simulador, chat NotebookLM, clasificador v5)
├── frontend/  # React + Vite (portada con ataques flotantes, páginas por ataque)
└── data/      # JSON pequeños del proyecto (resumen, fichas por ataque)
```

## Arranque rápido

```bash
# 1) Backend
cd web/backend && pip install -r requirements.txt && uvicorn main:app --reload
# 2) Frontend (otra terminal)
cd web/frontend && npm install && npm run dev   # http://localhost:5173
```

## Modos IA (OFF / ON)

Interruptor global arriba de la web (se guarda en el navegador):

- **IA OFF** (por defecto, siempre funciona): el simulador usa plantillas locales y el chat da
  respuestas locales básicas. No depende de NotebookLM.
- **IA ON**: el simulador y el chat de cada ataque usan **su propio cuaderno de NotebookLM**. Si un
  ataque no tiene cuaderno o NotebookLM no está disponible, esa función avisa y se vuelve a IA OFF.

NotebookLM se configura **por ataque** con variables de entorno en `web/backend/.env` (no se
versiona; ver `web/backend/.env.example`). Nunca se guardan credenciales en el repositorio.

## Qué se puede hacer

- **Explorar ataques**: portada con los 7 ataques flotantes; cada uno abre su página con explicación,
  diagrama, señales, regla simplificada, métricas y limitaciones.
- **Simular un ataque**: genera una ventana sintética (5 trazas normales + N de ataque + 5 normales)
  y descárgala en CSV. Son datos sintéticos para enseñar el patrón; la validación real se hizo con
  UGR'16.
- **Preguntar por ataque**: chat conectado al cuaderno NotebookLM del ataque (en IA ON).
- **Probar el clasificador v5**: sube una ventana CSV pequeña (≤5 MB) y obtén la predicción por
  traza. Si el CSV incluye la etiqueta real, se calcula el **acierto**; si no, solo se muestra la
  **confianza** del detector.

> El clasificador de la web es un **wrapper seguro basado en la lógica v5** para ventanas pequeñas
> (reutiliza la v3 real sin modificarla + el override SSH de la v5). La validación científica
> completa está en `scripts/02_attack_analysis/`.

Detalles de endpoints y configuración: `web/backend/README.md`. Detalles de la interfaz:
`web/frontend/README.md`.

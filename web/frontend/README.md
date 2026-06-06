# frontend/ — React + Vite (Fase 3, modo IA OFF)

Mapa mental interactivo del TFG: detección explicativa de anomalías NetFlow (UGR'16) con LLMs +
clasificador contextual. **Modo IA OFF**: consume el backend FastAPI (datos locales); no integra
ningún LLM todavía.

- Versión principal mostrada: **v5 integrated** · Versión base estable: **v3**.

**Navegación superior (sticky)**: Mapa · Ataques · Detector v5 · Resultados · ML baseline ·
Modo defensa · IA.

## Qué muestra

1. **Mapa** — *Flujo del proyecto* (mapa mental): UGR'16 → NetFlow → ventanas → NotebookLM/LLMs →
   hipótesis conductuales → reglas interpretables → clasificador v5 → resultados/generalización/ML;
   y *Resumen del proyecto*: objetivo, idea clave (el LLM interpreta; la detección es por reglas
   conductuales), versión principal v5 + base v3 y timeline v1 → v5.
2. **Ataques** — 7 tarjetas (scan11, scan44, anomaly-udpscan, dos, nerisbotnet, anomaly-sshscan,
   anomaly-spam) con estado (color) y métrica principal (clic → modal de detalle), más la tabla
   *Qué mira cada ataque* (familia · señales · estado · limitación).
3. **Detector v5** — *Cómo funciona el clasificador v5*: los 3 pases (contexto local → global por
   ventana → global por origen SSH/fan-out), con el tercer pase destacado.
4. **Resultados** — tabla *Resultados finales* (ataque · familia · estado · P · R · F1 ·
   interpretación) + detección binaria v5/v3 en week1.
5. **ML baseline** — *Comparación con ML clásico*: Random Forest (F1 macro ≈ 0,95) como baseline y
   por qué no sustituye a la v5 (supervisado/opaco vs reglas explicables).
6. **Modo defensa** — guion compacto de 9 puntos para una presentación de ~15 minutos.
7. **IA** — IA OFF (activo) e IA ON / NotebookLM (panel reservado, pendiente).

**Detalle de ataque** (modal): qué es, patrón técnico, señales del detector, métricas (v3/v5),
limitaciones, nota para la defensa y documentos relacionados. Cuida especialmente
`anomaly-sshscan` (v3 0/0 → v5 P 0,999 / R 0,907 / F1 0,951 por fan-out SSH global).

Estilo oscuro, moderno y responsive básico, pensado para una pantalla de defensa.

## Requisitos

- Node.js 18+ y npm.
- El **backend** debe estar corriendo (sirve los JSON y permite CORS desde el puerto 5173).

## Ejecución

**1) Backend** (en una terminal):

```bash
cd web/backend
pip install -r requirements.txt
uvicorn main:app --reload
```

**2) Frontend** (en otra terminal):

```bash
cd web/frontend
npm install
npm run dev
```

Abrir el navegador en `http://localhost:5173`.

## Configuración del backend

Por defecto el frontend usa `http://127.0.0.1:8000` (ver `src/config.js`). Para cambiarlo, crear
un archivo `web/frontend/.env` con:

```text
VITE_API_BASE=http://otra-direccion:puerto
```

## Estructura

```text
web/frontend/
├── index.html
├── package.json
├── vite.config.js
├── README.md
└── src/
    ├── main.jsx      # punto de entrada React
    ├── App.jsx       # toda la UI (mapa mental, resumen, ataques, detalle, timeline, IA)
    ├── config.js     # URL base del backend (configurable por .env)
    └── styles.css    # tema oscuro
```

## Nota

Si el backend no está disponible, la web muestra un aviso claro indicando cómo arrancarlo. No se
integran LLMs reales en esta fase (modo IA OFF).

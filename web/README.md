# Web interactiva del TFG

Visualización del sistema de **detección explicativa de ataques NetFlow (UGR'16)** basado en
**LLMs + clasificador contextual v3**.

## Objetivo

Ofrecer una interfaz sencilla para explorar, de forma interpretable:

- el modelo de comportamiento por familia de ataque,
- las señales conductuales que usa el clasificador contextual **v3**,
- las métricas reales (detección binaria, por familia y subtipo),
- el estado de cada familia (fuerte / parcial / exploratorio),
- el resumen del proyecto (metodología, generalización, limitaciones).

La web **no ejecuta el clasificador ni usa los CSV grandes**: trabaja con **JSON pequeños**
generados a partir de la documentación y los *summaries* del proyecto.

## Arquitectura propuesta

```text
web/
├── frontend/   # React + Vite (UI; pendiente)
├── backend/    # FastAPI (sirve los JSON y, en el futuro, el modo IA ON; pendiente)
├── data/       # JSON locales (attacks.json, project_summary.json)  [LISTO]
├── services/   # Lógica de servicios (carga de datos, futura integración NotebookLM; pendiente)
└── README.md
```

- **Frontend**: React + Vite, estilo simple y moderno (oscuro si es sencillo).
- **Backend**: FastAPI, expone los JSON locales mediante una API mínima.
- **Datos**: JSON local en `web/data/` (sin datos pesados).

## Modos de funcionamiento

- **IA OFF (primera fase, en curso)**: la web funciona con **datos locales** (los JSON de
  `web/data/`). No requiere conexión ni LLM. Es el modo por defecto.
- **IA ON / NotebookLM (preparado, NO integrado)**: en el futuro permitirá consultar
  explicaciones generadas por el LLM. Se deja la estructura (`services/`) preparada, pero **no
  se integra todavía**.

## Fases

1. **Fase 1 (actual)**: estructura base + JSON iniciales (`attacks.json`, `project_summary.json`).
2. **Fase 2**: backend FastAPI mínimo que sirva los JSON (`/api/attacks`, `/api/summary`).
3. **Fase 3**: frontend React + Vite que consuma la API y muestre fichas por ataque y resumen.
4. **Fase 4**: pulido de UI (tema oscuro, navegación, enlaces a documentos).
5. **Fase 5 (futuro)**: modo IA ON con NotebookLM (sin integrar aún).

## Cómo se ejecutará (futuro)

```text
# Backend (cuando exista)
cd web/backend
pip install -r requirements.txt
uvicorn main:app --reload

# Frontend (cuando exista)
cd web/frontend
npm install
npm run dev
```

De momento **no se instalan dependencias** ni se levanta nada: solo existe la estructura y los
datos locales.

## Fuente de datos

Los JSON de `web/data/` se han generado a partir de la documentación del proyecto
(`Docs/NotebookLLM/`) y de los *summaries* (`data/**/summaries`). Las métricas son las reales
de la validación del clasificador **v3** (documentos 26, 27, 28).

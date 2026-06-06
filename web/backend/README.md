# backend/ — API FastAPI (Fase 2, modo IA OFF)

API mínima que sirve los **datos locales** de `web/data/` para la web del TFG (mapa mental
interactivo). No ejecuta el clasificador ni usa CSV grandes: solo lee los JSON pequeños.

- Versión principal recomendada: **v5 integrated** · Versión base estable: **v3**.
- El modo IA ON (NotebookLM) **no** está integrado todavía (futuro, vía `web/services/`).

## Objetivo

Exponer, mediante una API sencilla y robusta, el conocimiento del proyecto (resumen y fichas
por familia de ataque) para que el frontend (Fase 3, React + Vite) lo consuma.

## Endpoints

| Método | Ruta | Devuelve |
| --- | --- | --- |
| GET | `/` | Índice de endpoints |
| GET | `/api/health` | Estado: `status`, `project`, `classifier` (v5 integrated), `base_classifier` (v3), `api_version` |
| GET | `/api/summary` | Contenido de `web/data/project_summary.json` |
| GET | `/api/attacks` | Contenido de `web/data/attacks.json` |
| GET | `/api/attacks/{attack_id}` | Ficha de un ataque; **404** con mensaje + `available_ids` si no existe |

Manejo de errores: archivo de datos no encontrado (**503**), JSON mal formado (**500**), ataque
inexistente (**404** con lista de ids disponibles). Las rutas se resuelven con `pathlib`
respecto a la ubicación del script, por lo que funciona **desde la raíz del proyecto o desde
`web/backend`**.

CORS habilitado para el frontend de desarrollo: `http://localhost:5173` y `http://127.0.0.1:5173`.

## Instalación

```bash
cd web/backend
pip install -r requirements.txt
```

## Ejecución

```bash
cd web/backend
uvicorn main:app --reload
```

(También funciona desde la raíz del proyecto: `uvicorn web.backend.main:app --reload`.)

## URLs de prueba

```text
http://127.0.0.1:8000/api/health
http://127.0.0.1:8000/api/summary
http://127.0.0.1:8000/api/attacks
http://127.0.0.1:8000/api/attacks/anomaly-sshscan
```

Documentación automática de la API (Swagger): `http://127.0.0.1:8000/docs`.

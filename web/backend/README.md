# backend/ — API FastAPI (modo IA OFF/ON)

API que sirve los **datos locales** de `web/data/`, expone el **simulador de ataques sintéticos**,
un **chat por ataque** (NotebookLM) y un **wrapper web del clasificador v5** para ventanas CSV
pequeñas. Lee JSON pequeños y trabaja en memoria; no usa CSV grandes ni `data/raw` ni `data/clean`.

- Versión principal recomendada: **v5 integrated** · Versión base estable: **v3**.
- Dos modos: **IA OFF** (plantillas locales y respuestas básicas, siempre disponible) e **IA ON**
  (NotebookLM **por cuaderno de ataque**, vía `services/notebooklm_service.py`). El modo IA ON está
  **preparado** pero no requiere credenciales en el repo; si no está configurado, la web sigue
  funcionando en IA OFF.

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
| GET | `/api/ai/status` | Si IA ON está disponible + qué ataques tienen cuaderno (`configured_attacks`/`missing_attacks`) |
| POST | `/api/simulator/generate` | Genera una **ventana** NetFlow sintética (5 normal + N ataque + 5 normal) |
| POST | `/api/notebooklm/chat` | Pregunta libre al cuaderno NotebookLM del ataque (IA ON) |
| GET | `/api/classifier/expected-columns` | Columnas esperadas para subir una ventana al clasificador |
| POST | `/api/classifier/run` | Ejecuta el wrapper web del clasificador v5 sobre una ventana CSV (≤5 MB) |

Manejo de errores: archivo de datos no encontrado (**503**), JSON mal formado (**500**), ataque
inexistente (**404** con lista de ids disponibles). Las rutas se resuelven con `pathlib`
respecto a la ubicación del script, por lo que funciona **desde la raíz del proyecto o desde
`web/backend`**.

CORS habilitado (GET/POST) para el frontend de desarrollo: `http://localhost:5173` y
`http://127.0.0.1:5173`.

## Configurar NotebookLM por ataque

Cada ataque tiene **su propio cuaderno** de NotebookLM (no un id global). Copia `.env.example` a
`web/backend/.env` (no se versiona) y rellena lo que tengas:

```bash
NOTEBOOKLM_ENABLED=true
NOTEBOOKLM_AUTH_PATH=C:/ruta/local/a/credenciales   # solo la ruta, nunca el contenido
NOTEBOOKLM_DOS_ID=...
NOTEBOOKLM_SCAN11_ID=...
NOTEBOOKLM_SCAN44_ID=...
NOTEBOOKLM_UDPSCAN_ID=...
NOTEBOOKLM_NERISBOTNET_ID=...
NOTEBOOKLM_SSHSCAN_ID=...
NOTEBOOKLM_SPAM_ID=...
# Solo si vas a usar IA ON:
pip install -r requirements-ai.txt
```

`config.py` expone `notebook_id_for(attack_id)` y `notebook_map()`. `GET /api/ai/status` informa de
qué ataques tienen cuaderno (`configured_attacks`) y cuáles faltan (`missing_attacks`). Si un ataque
no tiene cuaderno, su modo IA ON responde **503** y la web cae a IA OFF para ese ataque.

## Simulador de ataques (`POST /api/simulator/generate`)

Genera una **ventana** de tráfico **sintético** (nunca datos reales): 5 trazas normales antes, N de
ataque y 5 normales después. El clasificador **no** se ejecuta aquí: solo generación y vista previa.

Entrada:

```json
{
  "attack_id": "anomaly-sshscan",
  "attack_flows": 50,
  "mode": "offline",
  "include_context_background": true
}
```

`mode` ∈ `offline | notebooklm`; `attack_flows` se limita a 2000. Ataques soportados: `scan11`,
`scan44`, `anomaly-udpscan`, `dos`, `nerisbotnet`, `anomaly-sshscan`, `anomaly-spam`.

Salida: `mode_used`, `attack_id`, `notebook_used`, `window_structure`, `pattern_summary`, `signals`,
`explanation_for_teacher`, `rows`, `summary`, `columns`, `csv_preview`, `synthetic_notice`. Cada fila
lleva un campo `section` (`background_before` / `attack` / `background_after`) para distinguirla
visualmente; ese campo NO va en el CSV. Columnas: `timestamp, src_ip, dst_ip, protocol, src_port,
dst_port, packets, bytes, flags, label`.

- **IA OFF:** `simulator.py` tiene una plantilla por ataque con sus `generation_rules`. El backend
  genera las filas de forma controlada. Siempre disponible.
- **IA ON:** se usa el cuaderno del ataque. **NotebookLM no genera filas CSV**: devuelve una
  descripción estructurada (`pattern_summary`, `background_*_description`, `signals`,
  `generation_rules`, `explanation_for_teacher`). El backend valida esa respuesta y genera las filas.
  **Prioridad estructura > rangos:** NotebookLM puede ayudar a elegir rangos realistas a partir del
  cuaderno, pero el backend mantiene las restricciones principales del patrón para que la simulación
  siga siendo coherente. En la práctica, la estructura (protocolo, puerto destino, `vary_dst_ports`,
  nº de orígenes/destinos, flags, label) viene **siempre de la plantilla** y NotebookLM solo influye
  en `packets_range`/`bytes_range`, que se recortan a los límites del ataque (p. ej. flujos ligeros).
- **Fallback:** si el ataque no tiene cuaderno / IA ON no está lista, responde **503**; si la
  respuesta no es válida, **502**. El frontend ofrece volver a IA OFF.

## Chat por ataque (`POST /api/notebooklm/chat`)

Entrada `{ "attack_id": "scan44", "question": "¿por qué es distribuido?" }`. Busca el cuaderno del
ataque y envía la pregunta vía `notebooklm-py`. Salida `{ attack_id, answer, mode_used, notebook_configured }`.
Si no hay cuaderno o falta `notebooklm-py`, responde **503** con motivo claro (el frontend muestra
una respuesta local básica en IA OFF).

## Clasificador v5 (wrapper web)

`services/classifier_service.py` ejecuta una **versión web segura basada en la lógica v5** para
ventanas pequeñas: importa la v3 real **sin modificarla** (`classify_local`,
`compute_window_aggregates`, `reconcile`) y le añade el override de `ssh_horizontal_scan` por
fan-out al puerto 22 (mejora de la v5), calculado dentro de la ventana. Si no puede importar la v3,
cae a un clasificador **demo** con las reglas principales (se indica en `summary.engine`).

> La validación científica completa está en los scripts de análisis, no en este endpoint.

- `GET /api/classifier/expected-columns`: columnas esperadas (acepta CSV con cabecera por nombre o
  el formato posicional de UGR'16 de 13 columnas sin cabecera) y límite de 5 MB.
- `POST /api/classifier/run` con `{ filename, csv_text }`: valida tamaño y columnas, clasifica en
  memoria y devuelve `summary` + `rows`. No escribe nada en disco.

**Confianza vs acierto:** la **confianza** (`alta/media/baja` + `confidence_score`) refleja cuán
segura está la regla. El **acierto** (`accuracy`) solo se calcula si el CSV incluye la etiqueta real
(`label`/`true_label`/`etiqueta`); compara ataque/normal por traza. Si no hay etiqueta,
`accuracy` es `null` y se muestra: *"No se puede calcular acierto porque el CSV no incluye etiqueta
real. Se muestra confianza del detector."*

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

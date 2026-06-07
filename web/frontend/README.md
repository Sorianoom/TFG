# frontend/ — React + Vite (web pública, modo IA OFF/ON)

Web pública, simple e interactiva del TFG: detección explicativa de anomalías NetFlow (UGR'16) con
LLMs + clasificador contextual v5. Consume el backend FastAPI.

- Versión principal: **v5 integrated** · base estable: **v3**.
- Sin librerías de routing: navegación interna por **hash** (`#/attacks/<id>`), sin dependencias extra.
- **Interruptor IA global** (arriba, en todas las páginas): **OFF** (plantillas locales y respuestas
  básicas) / **ON** (NotebookLM por cuaderno de ataque). El estado se guarda en `localStorage`
  (`aiMode.js`). Si IA ON no está disponible, se muestra un aviso y todo cae a IA OFF.

## Estructura de la web

### Portada (`#/`)

- **Hero** casi a pantalla completa: título, subtítulo y zona central con los **7 ataques flotando**
  (burbujas clicables con nombre corto, familia, estado y color por estado). Animación de flotación,
  hover con escala/brillo y **parallax** suave según el ratón (desactivado en móvil).
- Debajo, secciones **compactas**: *Cómo funciona el clasificador v5* (3 pases), *Resultados finales*
  (tarjetas resumidas), *Comparaciones* (dos gráficos de barras CSS: F1 macro de ML clásico —KNN, MLP,
  SVM, Logistic Regression, sin Random Forest— frente al F1 por familia de la v5, cada familia con la
  semana en que se mide), *Versiones del clasificador* (timeline v1→v5) y una caja mini *IA explicativa
  — próximamente*. La sección explica que un único F1 macro de la v5 no sería justo porque sus familias
  se validan en escenarios distintos (núcleo en august.week1, SSH Scan en april.week2).
- **Probar el clasificador v5** (`components/ClassifierRunner.jsx`): opción principal de la home.
  Sube una ventana CSV pequeña (≤5 MB), valida columnas y la clasifica traza a traza mostrando
  resumen (filas, ataque/normal, ataque dominante, confianza media, acierto) y una tabla por traza.
  Distingue **confianza** (certeza de la regla) de **acierto** (solo si el CSV trae etiqueta real).
  Consume `GET /api/classifier/expected-columns` y `POST /api/classifier/run`.

### Página de ataque (`#/attacks/<id>`)

Clic en una burbuja (o en una tarjeta de resultados) abre la ruta del ataque, que muestra **solo** ese
ataque con explicaciones pensadas para un profesor de informática no especialista (jerga explicada
entre paréntesis): botón volver, título + familia, estado, descripción, **diagrama SVG** del patrón,
*En palabras simples*, *Características que mira el detector* (señal · qué mide · por qué importa),
*Proceso de detección* (pasos numerados), *Regla simplificada* (pseudocódigo ilustrativo), *Qué no usa*
(chips), *Cómo se ve en NetFlow*, *Métricas* (con su significado), *Contexto de validación*,
*Limitaciones*, *Para explicarlo al tribunal* y *¿Qué papel tiene NotebookLM?*. (La sección de
documentos relacionados se mostrará más adelante, cuando la memoria final esté cerrada.)

Además, cada página de ataque incluye:

- **Simulación del patrón** (`components/AttackSimulator.jsx`): botón *Generar ventana sintética*,
  selector de trazas de ataque (20/50/100) y tabla que distingue visualmente las 5 trazas normales
  antes, el ataque y las 5 normales después; con explicación, señales y descarga CSV. Usa el modo IA
  global: OFF → plantilla local; ON → cuaderno NotebookLM del ataque (con fallback a OFF si falla).
Además, en las páginas de ataque aparece un **chat flotante contextual**
(`components/FloatingAttackChat.jsx`, renderizado desde `App.jsx`): botón "💬 Preguntar" fijo abajo a
la derecha que abre un panel pequeño. Usa el ataque de la ruta actual como contexto. En IA OFF
responde con la explicación local del ataque (de `TECH`) e invita a activar IA ON; en IA ON consulta
`POST /api/notebooklm/chat` con el `attack_id` actual. Si IA ON no está disponible para ese ataque,
muestra un aviso y sigue funcionando. Mantiene un historial mínimo de preguntas/respuestas.

Los textos didácticos por ataque viven en `attackMeta.js` (`TECH`, `NOT_USED_COMMON`); los datos duros
(métricas, patrón, limitaciones, documentos) siguen viniendo de `web/data/attacks.json` vía backend.

Rutas: `#/attacks/scan11`, `#/attacks/scan44`, `#/attacks/anomaly-udpscan`, `#/attacks/dos`,
`#/attacks/nerisbotnet`, `#/attacks/anomaly-sshscan`, `#/attacks/anomaly-spam`.

`anomaly-sshscan` recibe trato especial: v3 estándar 0/0 vs v5 integrated P 0,999 / R 0,907 / F1 0,951
(april.week2), explicación del fan-out SSH por origen y el matiz de posibles escáneres SSH de fondo no
etiquetados como background.

## Requisitos y ejecución

- Node.js 18+ y npm. El **backend** debe estar corriendo (CORS desde el puerto 5173).

```bash
# backend
cd web/backend && pip install -r requirements.txt && uvicorn main:app --reload
# frontend
cd web/frontend && npm install && npm run dev
```

Abrir `http://localhost:5173`. La URL del backend se configura en `src/config.js` (o `.env` con
`VITE_API_BASE`).

## Estructura de archivos

```text
web/frontend/src/
├── main.jsx              # entrada React
├── App.jsx               # barra global + fetch de datos + router por hash (Home / AttackDetail)
├── config.js             # URL base del backend
├── aiMode.js             # estado global del modo IA (localStorage) + hook useAiMode()
├── useHashRoute.js       # hook de routing por hash, navigate(), parseAttackId()
├── format.js             # fmt(), metricRows(), mainMetric()
├── attackMeta.js         # metadatos de presentación (orden, posiciones, textos, pases, versiones)
├── styles.css            # tema oscuro, hero, burbujas flotantes, detalle, responsive
└── components/
    ├── Home.jsx          # hero + clasificador + secciones compactas
    ├── FloatingAttacks.jsx  # zona central flotante con parallax
    ├── AttackDetail.jsx  # página de detalle de un ataque (+ simulación)
    ├── AttackDiagram.jsx # diagrama SVG del patrón por ataque
    ├── AttackSimulator.jsx  # simulación por ventana (5 normal + N ataque + 5 normal)
    ├── FloatingAttackChat.jsx # chat flotante contextual (NotebookLM en IA ON)
    ├── ClassifierRunner.jsx # subida de CSV y ejecución del clasificador v5
    └── AiToggle.jsx      # interruptor IA global (OFF/ON)
```

## Nota

Si el backend no está disponible, la web muestra un aviso claro. El modo IA ON usa NotebookLM solo
si está configurado (ver backend); por defecto funciona en IA OFF. El modo defensa y las tablas
extensas de fases anteriores se han retirado de la
portada para mantenerla limpia.

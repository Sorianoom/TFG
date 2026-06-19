# Relevo del TFG para continuar en otra sesión de Claude

> Documento de traspaso. Resume el estado del TFG y del repositorio para que otra sesión (Claude web, Claude Code en otro portátil, etc.) pueda continuar sin leer la conversación previa.
> Última actualización: 2026-06-19.

---

## 1. Estado general del TFG

- **Título oficial:** *Análisis de trazas de red con LLMs para mejorar las prestaciones de Sistemas de Detección de Intrusiones (IDSs)*.
- **Subtítulo:** *Detección explicativa de anomalías en tráfico NetFlow mediante LLMs y reglas conductuales*.
- **Objetivo:** estudiar cómo los modelos de lenguaje pueden **apoyar** la mejora de las prestaciones de un IDS de red, **sin** convertirse en el motor de detección. Trabaja sobre el dataset público **UGR'16** (tráfico NetFlow real de un ISP).
- **Enfoque final:** clasificador **contextual basado en reglas conductuales** sobre ventanas de tráfico. No es aprendizaje automático: son reglas explícitas y revisables.
- **Papel de LLMs / NotebookLM:** solo **apoyo al análisis** (interpretar patrones, resumir comportamiento, formular hipótesis que luego se comprueban con código y datos). **No detectan, no deciden, no calculan métricas.**
- **Papel del clasificador v5:** es quien realmente detecta. Tres pases en cascada (local, global por ventana, global por origen para el escaneo SSH).
- **Papel de la web:** aplicación interactiva para **visualizar, explicar y probar** el detector. No sustituye a la evaluación experimental.
- **Cerrado:** memoria completa (cap. 1–10 + apéndices A–F), prefacio (resumen ES + abstract EN), figuras y tablas, web funcional, scripts, resultados resumen, repositorio en GitHub.
- **Pendiente / posible:** atender cambios que pida el profesor, preparar el paquete final de entrega y la defensa. Mejoras de trabajo futuro recogidas en §10.6 de la memoria (otros datasets, botnets, despliegue más robusto, etc.).

---

## 2. Estructura de la memoria

- **Ruta del proyecto LaTeX:** `D:\homeMario\Home\Memoria\Plantilla_TFG_latex-UGR\Plantilla_TFG_latex` (en el repo: `Memoria/Plantilla_TFG_latex-UGR/Plantilla_TFG_latex`).
- **Archivo principal:** `proyecto.tex`.
- **Capítulos** (`capitulos/`):
  1. Introducción
  2. Conceptos preliminares
  3. Definición del problema
  4. Estado del arte
  5. Planificación
  6. Herramientas y datos
  7. Algoritmos desarrollados
  8. Experimentos y resultados
  9. Diseño de la plataforma web interactiva
  10. Conclusiones y trabajo futuro
- **Apéndices** (`apendices/`):
  - A. Manual de uso de la web
  - B. Guía para lanzar la web
  - C. Tablas completas de resultados
  - D. Pseudocódigo extendido
  - E. Ejemplos de ventanas sintéticas
  - F. Declaración de uso de herramientas de IA
- **Otros directorios:** `prefacios/` (prefacio: resumen ES + abstract EN en páginas independientes), `portada/`, `imagenes/` (figuras `.pdf` conceptuales y de resultados, capturas `.png` de la web), `bibliografia/bibliografia.bib`.
- **Estado del PDF:** compila correctamente. **126 páginas.** Sin `Reference undefined`, sin `Citation undefined`, sin labels duplicados, sin imágenes perdidas. `proyecto.pdf` **NO se versiona** (está en el `.gitignore` de la memoria).
- **Warnings conocidos e inofensivos:**
  - Sustituciones de fuente: `OT1/cmr/bx/sc` y `OMS/cmtt/m/n`.
  - Avisos de hyperref `destination ... page.1 ... duplicate ignored` (numeración de preliminares).
  - ~120 `Overfull`/`Underfull \hbox` preexistentes del documento (no afectan a márgenes visibles).
- **Notas del preámbulo:** clase `book` (por defecto `twoside`/`openright`). Hay `graphicx` pero **no** `tikz`, `pgfplots`, `subcaption`, `booktabs` ni `amsmath`. Para tablas anchas se usa `\resizebox`; para matemáticas, `\frac`, `\[ \]`, `\hline`.

---

## 3. Resultados principales (cifras verificadas)

Conjunto principal de estudio: **`august.week1`**. Generalización: `august.week2` y `april.week2`.

- **Detección binaria v5 (`august.week1`):** precisión **0,926**, recall **0,991**, **F1 0,957**.
- **Detección binaria v3 (base estable):** precisión 0,930, recall 0,991, F1 0,960.
- **Diferencia v3 → v5:** la v5 añade **8 337** falsos positivos (de 137 365 a 145 702), por el tercer pase SSH en una semana casi sin SSH etiquetado (el pase genera 8 389 predicciones adicionales que aquí cuentan como falsos positivos).
- **Por familia (`august.week1`, v5):** `anomaly-udpscan` F1 0,968 · `scan11` F1 0,864 · `scan44` F1 0,779 · `dos` F1 0,519 · `nerisbotnet` F1 0,076 · `anomaly-sshscan` no representativo aquí (solo 44 trazas etiquetadas).
- **Escaneo SSH (`april.week2`):** precisión 0,999, recall 0,907, **F1 0,951** (es el resultado característico de la v5: con contexto local no se detectaba; con agregación global por origen sí).
- **Generalización binaria por semana:** `august.week1` F1 0,957 · `august.week2` F1 0,805 (P 0,872, R 0,747) · `april.week2` F1 0,873 (P 0,845, R 0,903).
- **Baseline ML clásico (F1 macro sobre clases activas):** KNN 0,942 · MLP 0,889 · SVM 0,780 · Regresión logística 0,760. Es **referencia secundaria**, no la propuesta principal.
- **Random Forest:** alcanzaba ~0,98, pero se interpreta con cautela (posible particularidad de la muestra). **Se documenta en el Cap. 8 pero se ha retirado de la tabla de comparación principal del Apéndice C (C.4).**
- **Versiones anteriores:** v2 binario P 0,961 / R 0,991 (F1 derivado 0,976), pero subtipo `scan11`/`scan44` muy inestable (`scan44` recall ≈ 0,015). v1 fue **etapa exploratoria sin resumen binario homogéneo** (no se reportan métricas).
- **Familias activas (6):** `scan11`, `scan44`, `anomaly-udpscan`, `dos`, `nerisbotnet`, `anomaly-sshscan`. La clase normal es `background`.
- **`anomaly-spam` (campaña SMTP):** **descartada** como resultado activo (poca señal con solo metadatos). La etiqueta auxiliar `blacklist` no es familia activa.
- **Clasificador v5 (resumen lógico):** pase 1 local (ventana ±30 filas), pase 2 global por ventana (separa `scan11` de `scan44`, confirma `anomaly-udpscan`), pase 3 global por origen (fan-out SSH: un origen que contacta ≥ 50 destinos distintos por el puerto 22).

---

## 4. Cambios importantes ya aplicados

- **Resumen y abstract** en **páginas independientes**; el abstract EN lleva título traducido, autor y keywords (sin portada inglesa completa).
- **Estructura comparada con un TFG de referencia:** se mantienen apéndices **con letras A–F** y **bibliografía sin numerar** (no se copió el esquema de "Anexo" único ni bibliografía como capítulo).
- **Tablas y figuras recolocadas** para que no partan párrafos: Cap. 2 (figuras 2.1/2.2 y tablas), Cap. 6 (tabla del CSV NetFlow al final de 6.4, con `\clearpage`), Cap. 9 (figuras ancladas tras el texto que las introduce).
- **Nueva captura principal de la web** (`imagenes/web_pantalla_principal.png`, modo **IA OFF**, ventana limpia) insertada en §9.6 como Figura 9.2.
- **Limpieza de nombres internos de archivos** (CSV/scripts/carpetas) en Cap. 7, Cap. 8 y Apéndice C: se sustituyen por **descripciones funcionales** (qué contiene cada artefacto y para qué sirve). La memoria se entiende sin abrir el repositorio.
- **Explicación funcional** de los datos como CSV (columnas, tipos, dominio; ver Tabla 6.1) y de los artefactos de salida.
- **Tipos de ventana explicados:** `rows_2000` (nº fijo de filas, contexto homogéneo en cantidad, no en duración), `time_10s` (ráfagas y patrones rápidos), `time_60s` (persistencia, coordinación y fan-out; muchas más trazas). Para `time_60s` se dio a NotebookLM un **resumen agregado** en lugar de todas las trazas (NotebookLM solo resumió/interpretó, no detectó).
- **Revisión de Caps. 7 y 8:** tabla de evolución de versiones v1→v5 con cifras verificadas; explicación de VP/FP/FN/VN; reformulación legible del tercer pase SSH (sin el campo interno `SSH_PASE3 override_fp`).
- **Cap. 10 (trabajo futuro):** eliminadas dos tareas ya hechas (capturas/figuras definitivas; visualizaciones/trazabilidad). La lista quedó coherente.
- **Apéndice C actualizado:** C.1 convertida en tabla de evolución de versiones; C.4 sin Random Forest; fuentes de tablas unificadas como "elaboración propia a partir de los resultados experimentales".
- **Apéndice F actualizado:** declaración honesta y transparente del uso de IA (generar/adaptar scripts de comparación ML, configurar procesamiento de datos, código auxiliar, revisión de errores/resultados, apoyo a la web, documentación/figuras/redacción), dejando claro que el autor ejecutó, comprobó, contrastó y decidió, y que la IA no sustituyó la supervisión.
- **Humanizer** aplicado a los textos nuevos: sin punto y coma en prosa, sin raya larga (`---`) en los encabezados de versión de §7.4, sin repeticiones ni frases "meta".

---

## 5. Estado Git / GitHub

- **Rama actual:** `master`.
- **Remoto:** `origin` → `https://github.com/Sorianoom/TFG.git` (debe ser **privado**).
- **Último commit:** `e38a642` — *actualizar gitignore para entrega segura*.
- **Commits relevantes recientes (de más nuevo a más antiguo):**
  - `e38a642` actualizar gitignore para entrega segura
  - `8b630be` aplicar correcciones finales de lectura y formato
  - `db74bd5` separar resumen y abstract en paginas independientes
  - `b41f34e` pulir estilo de resumen abstract y apendice C
  - `9def789` actualizar codigo web scripts y resultados derivados del TFG
  - `94879cf` describir formato de datos CSV y material entregado
  - `0793045` completar memoria con figuras tablas apendices y prefacio
- **Estado esperado de git:** `working tree clean`, `master` al día con `origin/master`.
- **Subido a GitHub (~191 archivos):** memoria LaTeX (fuentes + imágenes), web (`backend/`, `frontend/src/`, configs, `web/data/*.json`, READMEs y guías), scripts (extracción/análisis/clasificación, baseline ML, figuras, automatización NotebookLM), datos **ligeros** (CSV resumen pequeños, muestras sintéticas), documentación de trabajo (`Docs/NotebookLLM/`), `README.MD`, `requirements.txt`.
- **NO subido por seguridad / tamaño (gitignored):** `.env`, sesión de NotebookLM (`storage_state.json`), `.notebooklm/`, datasets completos de UGR'16 (`data/raw/`, `data/clean/`, ventanas por ataque), CSV grandes de resultados por flujo (`*results*.csv`), carpetas `balanced_*`, `node_modules/`, `dist/`, `build/`, `venv/`/`.venv/`, artefactos LaTeX, `proyecto.pdf`, notas privadas (`RELEVO_CLAUDE_TFG.md`, `PENDIENTES_MEMORIA.md`, `00_RESUMEN_MAESTRO_TFG.md`, `NOTAS_MEMORIA.md`, `Guion.md`), muestras con IPs reales (`pruebaScan11/44.csv`).

---

## 6. Qué NO debe tocarse salvo necesidad clara

- No reintroducir **`anomaly-spam`** como resultado activo.
- No volver a usar **nombres de CSV/scripts como explicación principal**; mantener descripciones funcionales.
- No subir **datasets grandes** ni ficheros de varios GB.
- No subir **`.env`, cookies, tokens ni credenciales**.
- No meter **código fuente completo** en la memoria (solo pseudocódigo; el código va en el repo).
- No **numerar la bibliografía como capítulo**.
- No convertir los **apéndices A–F en un único anexo**.
- No cambiar **métricas** sin recalcularlas desde los resultados reales.
- No **exagerar el papel de NotebookLM ni de los LLMs**: son apoyo al análisis, no detectan.

---

## 7. Próximos pasos posibles

1. Clonar el repo en el otro portátil.
2. Compilar el PDF de la memoria.
3. Lanzar la web (reconstruyendo `node_modules/` y `dist/`).
4. Aplicar los cambios que pida el profesor.
5. Generar el paquete final de entrega (cuando se decida).
6. Preparar la defensa.

---

## 8. Comandos útiles

```bash
# Sincronizar y ver estado
git pull
git status

# Compilar la memoria (desde la carpeta del proyecto LaTeX)
cd Memoria/Plantilla_TFG_latex-UGR/Plantilla_TFG_latex
latexmk -pdf -interaction=nonstopmode proyecto.tex
# (latexmk ejecuta BibTeX automáticamente; genera proyecto.pdf)

# Backend de la web (modo IA OFF, suficiente para casi todo)
python -m venv venv            # o .venv
# activar el entorno virtual y luego:
pip install -r web/backend/requirements.txt
cd web/backend
uvicorn main:app               # sirve en http://127.0.0.1:8000

# Frontend (regenerar dependencias y build; no se versionan)
cd web/frontend
npm install
npm run build                  # el backend sirve dist/ en la misma URL :8000

# Workflow básico de cambios
git add <rutas explícitas>
git commit -m "mensaje claro"
git push
```

> Nota: el **modo IA ON** (NotebookLM) es opcional y requiere `pip install notebooklm-py==0.6.0` y un `web/backend/.env` local (no versionado). Sin él, la web funciona en modo IA OFF.

---

## 9. Seguridad

- El repositorio debe **permanecer privado** al menos hasta la defensa.
- El **prefacio incluye el DNI del autor** (página de autorización de biblioteca, parte estándar del TFG). Adecuado en repo privado; **revisar antes de hacer público**.
- **No hacer público** el repo sin una revisión previa.
- Revisar **`Docs/NotebookLLM/`** (documentación de trabajo, incluye notas de reunión y borradores) antes de publicar.
- **No versionar `proyecto.pdf`** salvo que se decida expresamente (hoy está ignorado; lo necesario para recompilar son las fuentes y las imágenes).
- **No subir datos completos de UGR'16** ni resultados pesados; solo los resúmenes ligeros ya incluidos.
- Nunca subir `.env`, `storage_state.json`, cookies, tokens ni claves.

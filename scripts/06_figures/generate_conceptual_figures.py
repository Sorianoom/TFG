#!/usr/bin/env python3
"""Genera las figuras conceptuales (esquemas) de la memoria.

Diagramas sencillos de cajas y flechas hechos con matplotlib (sin TikZ ni
paquetes externos). Son esquemas didacticos, no contienen datos numericos.

Salida (PDF) en: Memoria/Plantilla_TFG_latex-UGR/Plantilla_TFG_latex/imagenes/

Figuras:
    fig_pipeline_general.pdf        (Capitulo 1)
    fig_ids_firmas_vs_anomalias.pdf (Capitulo 2)
    fig_flujo_netflow.pdf           (Capitulo 2)
    fig_arquitectura_web.pdf        (Capitulo 9)

Uso:
    python scripts/06_figures/generate_conceptual_figures.py

No usa seaborn. Solo matplotlib.
"""

from pathlib import Path

import matplotlib

matplotlib.use("Agg")
import matplotlib.pyplot as plt
from matplotlib.patches import FancyBboxPatch

# --- Rutas relativas (sin rutas absolutas) ---
SCRIPT_DIR = Path(__file__).resolve().parent
REPO_ROOT = SCRIPT_DIR.parents[1]
IMG_DIR = (
    REPO_ROOT
    / "Memoria"
    / "Plantilla_TFG_latex-UGR"
    / "Plantilla_TFG_latex"
    / "imagenes"
)

plt.rcParams.update(
    {
        "font.size": 10,
        "pdf.fonttype": 42,  # incrusta fuentes TrueType
    }
)

# Paleta sobria
BLUE_F = "#EAF0F7"   # relleno azul claro
BLUE_E = "#33506E"   # borde azul
GREEN_F = "#E9F3EC"  # relleno verde claro
GREEN_E = "#3F7D54"  # borde verde
GREY_F = "#F0F0F0"   # relleno gris
GREY_E = "#666666"   # borde gris
ARROW = "#33506E"


def rbox(ax, cx, cy, w, h, text, fc=BLUE_F, ec=BLUE_E, fontsize=9, weight="normal"):
    """Caja redondeada centrada en (cx, cy). Devuelve (cx, cy, w, h)."""
    box = FancyBboxPatch(
        (cx - w / 2, cy - h / 2),
        w,
        h,
        boxstyle="round,pad=0.02,rounding_size=0.10",
        linewidth=1.2,
        edgecolor=ec,
        facecolor=fc,
    )
    ax.add_patch(box)
    ax.text(cx, cy, text, ha="center", va="center", fontsize=fontsize,
            fontweight=weight, color="#1a1a1a")
    return (cx, cy, w, h)


def arrow(ax, p1, p2, color=ARROW, rad=0.0, lw=1.3):
    ax.annotate(
        "",
        xy=p2,
        xytext=p1,
        arrowprops=dict(arrowstyle="-|>", color=color, lw=lw,
                        connectionstyle=f"arc3,rad={rad}"),
    )


def _clean(ax, xlim, ylim):
    ax.set_xlim(*xlim)
    ax.set_ylim(*ylim)
    ax.axis("off")
    ax.set_aspect("equal", adjustable="box")


def fig_pipeline():
    """Capitulo 1: flujo general del proyecto (8 etapas)."""
    labels = [
        "UGR'16 /\nNetFlow",
        "Limpieza y\npreparación",
        "Extracción\nde ventanas",
        "Análisis asistido\n(NotebookLM / LLMs)",
        "Reglas\nconductuales",
        "Clasificador\ncontextual v5",
        "Evaluación\nexperimental",
        "Aplicación\nweb",
    ]
    fig, ax = plt.subplots(figsize=(14, 2.6))
    w, h = 1.42, 1.2
    step = 1.70
    x0 = 1.0
    cy = 1.3
    centers = [x0 + i * step for i in range(len(labels))]
    # color especial para la etapa de LLMs (apoyo) y la web
    for i, (cx, txt) in enumerate(zip(centers, labels)):
        if i == 3:
            fc, ec = GREEN_F, GREEN_E
        else:
            fc, ec = BLUE_F, BLUE_E
        rbox(ax, cx, cy, w, h, txt, fc=fc, ec=ec, fontsize=8.2)
    for i in range(len(centers) - 1):
        arrow(ax, (centers[i] + w / 2, cy), (centers[i + 1] - w / 2, cy))
    _clean(ax, (0, centers[-1] + 1.0), (0, 2.6))
    out = IMG_DIR / "fig_pipeline_general.pdf"
    fig.savefig(out, bbox_inches="tight")
    plt.close(fig)
    return out


def fig_ids():
    """Capitulo 2: IDS por firmas vs por anomalias (dos bloques)."""
    fig, ax = plt.subplots(figsize=(10, 4.2))
    w, h = 2.6, 1.0
    centers_x = [3.2, 6.6, 10.0]

    # Fila superior: firmas
    y1 = 3.2
    ax.text(0.2, y1, "IDS por\nfirmas", ha="left", va="center",
            fontsize=10, fontweight="bold", color=BLUE_E)
    firmas = ["Tráfico\nde red", "Comparación con\nfirmas conocidas",
              "Coincidencia\n→ alerta"]
    for cx, txt in zip(centers_x, firmas):
        rbox(ax, cx, y1, w, h, txt, fc=BLUE_F, ec=BLUE_E, fontsize=8.8)
    for i in range(len(centers_x) - 1):
        arrow(ax, (centers_x[i] + w / 2, y1), (centers_x[i + 1] - w / 2, y1))

    # Fila inferior: anomalias
    y2 = 1.0
    ax.text(0.2, y2, "IDS por\nanomalías", ha="left", va="center",
            fontsize=10, fontweight="bold", color=GREEN_E)
    anom = ["Tráfico\nde red", "Modelo de\ncomportamiento normal",
            "Desviación\n→ alerta"]
    for cx, txt in zip(centers_x, anom):
        rbox(ax, cx, y2, w, h, txt, fc=GREEN_F, ec=GREEN_E, fontsize=8.8)
    for i in range(len(centers_x) - 1):
        arrow(ax, (centers_x[i] + w / 2, y2), (centers_x[i + 1] - w / 2, y2),
              color=GREEN_E)

    _clean(ax, (0, 11.6), (0, 4.2))
    out = IMG_DIR / "fig_ids_firmas_vs_anomalias.pdf"
    fig.savefig(out, bbox_inches="tight")
    plt.close(fig)
    return out


def fig_netflow():
    """Capitulo 2: varios paquetes se resumen en un registro NetFlow."""
    fig, ax = plt.subplots(figsize=(8.5, 5.0))

    # Origen y destino con varios paquetes entre ellos
    rbox(ax, 1.6, 6.2, 1.8, 1.0, "Origen", fc=GREY_F, ec=GREY_E, fontsize=9.5)
    rbox(ax, 8.4, 6.2, 1.8, 1.0, "Destino", fc=GREY_F, ec=GREY_E, fontsize=9.5)
    for dy in (0.45, 0.15, -0.15, -0.45):
        arrow(ax, (2.5, 6.2 + dy), (7.5, 6.2 + dy), color=GREY_E, lw=1.0)
    ax.text(5.0, 7.25, "Varios paquetes de una misma comunicación",
            ha="center", va="center", fontsize=8.8, style="italic",
            color="#444444")

    # Flecha "se resume en"
    arrow(ax, (5.0, 5.6), (5.0, 4.5), lw=1.6)
    ax.text(5.25, 5.05, "se resume en", ha="left", va="center",
            fontsize=8.8, style="italic", color="#444444")

    # Registro NetFlow con campos
    campos = ("Registro NetFlow (metadatos)\n\n"
              "IP origen   ·   IP destino\n"
              "Puerto origen   ·   Puerto destino\n"
              "Protocolo   ·   Duración\n"
              "Paquetes   ·   Bytes")
    rbox(ax, 5.0, 2.3, 5.6, 3.4, campos, fc=BLUE_F, ec=BLUE_E, fontsize=9.2)

    _clean(ax, (0, 10), (0.4, 8.0))
    out = IMG_DIR / "fig_flujo_netflow.pdf"
    fig.savefig(out, bbox_inches="tight")
    plt.close(fig)
    return out


def fig_arquitectura():
    """Capitulo 9: arquitectura de la aplicacion web."""
    fig, ax = plt.subplots(figsize=(11, 5.2))
    w, h = 2.3, 1.1

    # Cadena principal: usuario -> frontend -> backend
    usr = rbox(ax, 1.7, 4.3, w, h, "Usuario /\nNavegador",
               fc=GREY_F, ec=GREY_E, fontsize=9)
    front = rbox(ax, 4.9, 4.3, w, h, "Frontend\n(React + Vite)",
                 fc=BLUE_F, ec=BLUE_E, fontsize=9)
    back = rbox(ax, 8.1, 4.3, w, h, "Backend\n(FastAPI / uvicorn)",
                fc=BLUE_F, ec=BLUE_E, fontsize=9)
    arrow(ax, (usr[0] + w / 2, 4.3), (front[0] - w / 2, 4.3))
    arrow(ax, (front[0] + w / 2, 4.3), (back[0] - w / 2, 4.3))

    # Modulos a la derecha del backend (pila vertical)
    mx = 11.2
    mods = [
        ("Datos JSON\n(fichas y resumen)", BLUE_F, BLUE_E),
        ("Clasificador\ncontextual", BLUE_F, BLUE_E),
        ("Simulador\nde ventanas", BLUE_F, BLUE_E),
        ("NotebookLM\n(opcional, IA ON)", GREEN_F, GREEN_E),
    ]
    ys = [6.4, 5.0, 3.6, 2.2]
    for (txt, fc, ec), my in zip(mods, ys):
        rbox(ax, mx, my, 2.5, 1.1, txt, fc=fc, ec=ec, fontsize=8.6)
        # flecha desde el lado derecho del backend hasta cada modulo
        arrow(ax, (back[0] + w / 2, 4.3), (mx - 2.5 / 2, my), rad=0.0, lw=1.1)

    _clean(ax, (0, 13.0), (1.3, 7.3))
    out = IMG_DIR / "fig_arquitectura_web.pdf"
    fig.savefig(out, bbox_inches="tight")
    plt.close(fig)
    return out


def main():
    IMG_DIR.mkdir(parents=True, exist_ok=True)
    outputs = [fig_pipeline(), fig_ids(), fig_netflow(), fig_arquitectura()]
    for o in outputs:
        exists = o.exists()
        size = o.stat().st_size if exists else 0
        print(f"[{'OK' if exists else 'FALLO'}] {o}  ({size} bytes)")


if __name__ == "__main__":
    main()

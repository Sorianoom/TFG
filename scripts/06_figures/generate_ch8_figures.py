#!/usr/bin/env python3
"""Genera las figuras de resultados del Capitulo 8 de la memoria.

Todas las cifras provienen literalmente de las tablas/texto ya redactados en
capitulos/08_ExperimentosYResultados.tex. No se calcula ni se inventa nada:
los valores estan escritos a mano abajo, con su tabla de origen comentada.

Salida (PDF) en: Memoria/Plantilla_TFG_latex-UGR/Plantilla_TFG_latex/imagenes/

Uso:
    python scripts/06_figures/generate_ch8_figures.py

No usa seaborn. Solo matplotlib.
"""

from pathlib import Path

import matplotlib

matplotlib.use("Agg")  # backend sin ventana, para generar ficheros
import matplotlib.pyplot as plt

# --- Rutas (relativas a la ubicacion del script, sin rutas absolutas) ---
SCRIPT_DIR = Path(__file__).resolve().parent
REPO_ROOT = SCRIPT_DIR.parents[1]  # scripts/06_figures -> scripts -> raiz repo
IMG_DIR = (
    REPO_ROOT
    / "Memoria"
    / "Plantilla_TFG_latex-UGR"
    / "Plantilla_TFG_latex"
    / "imagenes"
)

# --- Estilo comun ---
plt.rcParams.update(
    {
        "font.size": 11,
        "axes.titlesize": 12,
        "axes.labelsize": 11,
        "legend.fontsize": 10,
        "figure.dpi": 150,
        "pdf.fonttype": 42,  # incrusta fuentes TrueType (evita Type 3)
        "axes.axisbelow": True,
    }
)

C_V3 = "#4C72B0"   # azul
C_V5 = "#C44E52"   # rojo
C_FAM = "#4C72B0"  # azul para familias en august.week1
C_SSH = "#55A868"  # verde para anomaly-sshscan (april.week2)


def _bar_labels(ax, bars, fmt="{:.3f}"):
    """Escribe el valor encima de cada barra."""
    for b in bars:
        h = b.get_height()
        ax.annotate(
            fmt.format(h),
            xy=(b.get_x() + b.get_width() / 2, h),
            xytext=(0, 3),
            textcoords="offset points",
            ha="center",
            va="bottom",
            fontsize=8,
        )


def fig_v3_vs_v5():
    """F4: binaria v3 vs v5 en august.week1 + recuperacion de SSH en april.week2.

    Fuente: Tabla tab:exp_binaria (binaria august.week1),
            Tabla tab:exp_familia (anomaly-sshscan august.week1 = 0,000),
            Tabla tab:exp_sshscan (anomaly-sshscan april.week2 = 0,951).
    """
    metrics = ["Precision", "Recall", "F1"]
    v3 = [0.930, 0.991, 0.960]
    v5 = [0.926, 0.991, 0.957]

    fig, (ax1, ax2) = plt.subplots(1, 2, figsize=(10, 4.2),
                                   gridspec_kw={"width_ratios": [2, 1]})

    # Panel izquierdo: binaria v3 vs v5 (august.week1)
    x = range(len(metrics))
    w = 0.38
    b1 = ax1.bar([i - w / 2 for i in x], v3, w, label="v3 (base estable)", color=C_V3)
    b2 = ax1.bar([i + w / 2 for i in x], v5, w, label="v5 (final)", color=C_V5)
    _bar_labels(ax1, b1)
    _bar_labels(ax1, b2)
    ax1.set_xticks(list(x))
    ax1.set_xticklabels(metrics)
    ax1.set_ylim(0, 1.08)
    ax1.set_ylabel("Valor")
    ax1.set_title("Detección binaria en august.week1")
    ax1.legend(loc="lower right")
    ax1.grid(axis="y", linestyle=":", alpha=0.5)

    # Panel derecho: anomaly-sshscan (v5) por semana
    weeks = ["august.week1", "april.week2"]
    ssh = [0.000, 0.951]
    bx = ax2.bar(weeks, ssh, color=[C_V3, C_SSH], width=0.55)
    _bar_labels(ax2, bx)
    ax2.set_ylim(0, 1.08)
    ax2.set_ylabel("F1")
    ax2.set_title("anomaly-sshscan (v5)")
    ax2.tick_params(axis="x", labelrotation=15)
    ax2.grid(axis="y", linestyle=":", alpha=0.5)

    fig.tight_layout()
    out = IMG_DIR / "fig_v3_vs_v5_binaria.pdf"
    fig.savefig(out, bbox_inches="tight")
    plt.close(fig)
    return out


def fig_f1_por_familia():
    """F5: F1 por familia (v5).

    Fuente: Tabla tab:exp_familia (august.week1) y Tabla tab:exp_sshscan
            (anomaly-sshscan medido en april.week2).
    """
    familias = [
        "anomaly-udpscan",
        "scan11",
        "scan44",
        "dos",
        "nerisbotnet",
        "anomaly-sshscan",
    ]
    f1 = [0.968, 0.864, 0.779, 0.519, 0.076, 0.951]
    # anomaly-sshscan se mide en april.week2; el resto en august.week1
    colors = [C_FAM, C_FAM, C_FAM, C_FAM, C_FAM, C_SSH]

    fig, ax = plt.subplots(figsize=(8.5, 4.5))
    bars = ax.bar(familias, f1, color=colors, width=0.62)
    _bar_labels(ax, bars)
    ax.set_ylim(0, 1.08)
    ax.set_ylabel("F1")
    ax.set_title("F1 por familia (v5)")
    ax.tick_params(axis="x", labelrotation=20)
    ax.grid(axis="y", linestyle=":", alpha=0.5)

    # nota de contexto de medida
    handles = [
        plt.Rectangle((0, 0), 1, 1, color=C_FAM),
        plt.Rectangle((0, 0), 1, 1, color=C_SSH),
    ]
    ax.legend(
        handles,
        ["Medido en august.week1", "Medido en april.week2"],
        loc="upper right",
    )

    fig.tight_layout()
    out = IMG_DIR / "fig_f1_por_familia.pdf"
    fig.savefig(out, bbox_inches="tight")
    plt.close(fig)
    return out


def fig_generalizacion():
    """F6: binaria por semana (P, R, F1).

    Fuente: Tabla tab:exp_general.
    """
    weeks = ["august.week1", "august.week2", "april.week2"]
    P = [0.926, 0.872, 0.845]
    R = [0.991, 0.747, 0.903]
    F1 = [0.957, 0.805, 0.873]

    x = range(len(weeks))
    w = 0.26
    fig, ax = plt.subplots(figsize=(8.5, 4.3))
    bP = ax.bar([i - w for i in x], P, w, label="Precisión", color="#4C72B0")
    bR = ax.bar(list(x), R, w, label="Recall", color="#DD8452")
    bF = ax.bar([i + w for i in x], F1, w, label="F1", color="#55A868")
    _bar_labels(ax, bP)
    _bar_labels(ax, bR)
    _bar_labels(ax, bF)
    ax.set_xticks(list(x))
    ax.set_xticklabels(weeks)
    ax.set_ylim(0, 1.12)
    ax.set_ylabel("Valor")
    ax.set_title("Generalización: detección binaria (v5) por semana")
    ax.legend(loc="lower center", ncol=3)
    ax.grid(axis="y", linestyle=":", alpha=0.5)

    fig.tight_layout()
    out = IMG_DIR / "fig_generalizacion_semanas.pdf"
    fig.savefig(out, bbox_inches="tight")
    plt.close(fig)
    return out


def main():
    IMG_DIR.mkdir(parents=True, exist_ok=True)
    outputs = [fig_v3_vs_v5(), fig_f1_por_familia(), fig_generalizacion()]
    for o in outputs:
        exists = o.exists()
        size = o.stat().st_size if exists else 0
        print(f"[{'OK' if exists else 'FALLO'}] {o}  ({size} bytes)")


if __name__ == "__main__":
    main()

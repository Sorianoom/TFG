"""
Script: compare_classical_ml_classifiers.py

Comparación SECUNDARIA con métodos clásicos de Machine Learning (baseline
académico) frente al clasificador contextual por traza v3.

IMPORTANTE
----------
El objetivo NO es sustituir la propuesta principal (el clasificador contextual
v3, basado en reglas conductuales interpretables conectadas con hipótesis
generadas por LLM), sino ofrecer una comparación PREDICTIVA con clasificadores
tradicionales. Aunque algún modelo de ML obtenga mejores métricas, NO debe
presentarse como sustituto: la v3 mantiene interpretabilidad, evidencia por
traza y trazabilidad del comportamiento de ataque.

Modelos comparados:
    - Logistic Regression (baseline simple)
    - KNN
    - SVM (RBF)
    - Random Forest
    - MLPClassifier (red neuronal sencilla)

Reglas de diseño:
    - NO se usan IPs concretas como features (se descartan src_ip/dst_ip).
    - NO se usa la etiqueta real como feature (solo como objetivo y para evaluar).
    - Solo variables conductuales/derivadas del flujo.
    - Muestra estratificada con tope por clase (configurable).
    - Train/test estratificado, reproducible con random_state=42.
    - Si SVM/KNN son demasiado lentos, se reduce automáticamente la muestra de
      entrenamiento de ese modelo y se avisa, continuando con el resto.

Origen de datos (en este orden, el primero que exista):
    1. --input <ruta>                         (muestra/fichero indicado)
    2. data/clean/august_week1_clean.csv      (dataset limpio; lectura por chunks)
    3. data/attack_analysis/**/*.csv          (ventanas reales; MISMO origen que la v3)

Salidas:
    - data/attack_analysis/ml_baseline_results.csv   (métricas globales por modelo)
    - data/attack_analysis/ml_baseline_summary.csv   (métricas por clase y modelo)

Uso:
    python scripts/03_ml_baselines/compare_classical_ml_classifiers.py
    python scripts/03_ml_baselines/compare_classical_ml_classifiers.py --sample-size 300000

NOTA: no modifica los clasificadores v1/v2/v3 ni ningún archivo de datos previo.
"""

import argparse
import time
from pathlib import Path

import numpy as np
import pandas as pd

from sklearn.model_selection import train_test_split
from sklearn.preprocessing import StandardScaler
from sklearn.linear_model import LogisticRegression
from sklearn.neighbors import KNeighborsClassifier
from sklearn.svm import SVC
from sklearn.ensemble import RandomForestClassifier
from sklearn.neural_network import MLPClassifier
from sklearn.metrics import (
    accuracy_score, precision_recall_fscore_support,
    classification_report, confusion_matrix,
)

# ---------------------------------------------------------------------------
# Configuración (ajustable)
# ---------------------------------------------------------------------------

RANDOM_STATE = 42

# Tamaño de muestra objetivo (ej.: 100000 / 300000 / 500000). Se reparte con
# tope por clase para no dejar que `background` domine y para incluir las clases
# minoritarias completas.
DEFAULT_SAMPLE_SIZE = 100_000
TEST_SIZE = 0.25
MIN_CLASS_SAMPLES = 10          # clases con menos muestras se descartan (se avisa)

# Topes de entrenamiento para modelos lentos (anti-O(n^2) en SVM, anti-lentitud KNN)
SVM_MAX_TRAIN = 15_000
KNN_MAX_TRAIN = 80_000

BASE_DIR = Path("data/attack_analysis")
CLEAN_CSV = Path("data/clean/august_week1_clean.csv")
RESULTS_FILE = BASE_DIR / "ml_baseline_results.csv"
SUMMARY_FILE = BASE_DIR / "ml_baseline_summary.csv"

# Estructura de columnas de las ventanas NetFlow (sin cabecera)
COLUMN_NAMES = [
    "timestamp", "duration", "src_ip", "dst_ip", "src_port", "dst_port",
    "protocol", "flags", "src_tos", "dst_tos", "packets", "bytes", "label",
]
# Columnas que se cargan (se descartan IPs y ToS; las IPs NO son features)
USECOLS = ["timestamp", "duration", "src_port", "dst_port", "protocol",
           "flags", "packets", "bytes", "label"]

SKIP_SUFFIXES = ("_extraction_summary.csv",)
SKIP_NAMES = {
    "behavior_detection_results.csv", "behavior_detection_results_extended.csv",
    "window_extraction_summary.csv",
    "flow_level_detection_results.csv", "flow_level_detection_summary.csv",
    "flow_level_detection_results_v2.csv", "flow_level_detection_summary_v2.csv",
    "flow_level_detection_results_v3.csv", "flow_level_detection_summary_v3.csv",
    "ml_baseline_results.csv", "ml_baseline_summary.csv",
}

# Familias de ataque sobre las que interesa la comparación
ATTACK_FAMILIES = [
    "scan11", "scan44", "anomaly-udpscan", "dos",
    "nerisbotnet", "anomaly-sshscan", "anomaly-spam",
]


# ---------------------------------------------------------------------------
# 1. Carga de datos
# ---------------------------------------------------------------------------

def _is_window_file(path: Path) -> bool:
    if path.name in SKIP_NAMES:
        return False
    if any(path.name.endswith(s) for s in SKIP_SUFFIXES):
        return False
    return True


def load_from_windows() -> pd.DataFrame:
    """
    Fallback: agrega las ventanas reales de data/attack_analysis/.
    Es el MISMO origen sobre el que se evaluó el clasificador v3, lo que hace la
    comparación directa. Se deduplica para mitigar el solapamiento de ventanas.
    """
    files = sorted(p for p in BASE_DIR.rglob("*.csv") if _is_window_file(p))
    if not files:
        raise FileNotFoundError("No se encontraron ventanas en data/attack_analysis/")

    print(f"[datos] Cargando {len(files)} ventanas de {BASE_DIR} ...")
    frames = []
    for fp in files:
        try:
            df = pd.read_csv(
                fp, header=None, names=COLUMN_NAMES, usecols=USECOLS,
                dtype=str, encoding="utf-8", on_bad_lines="skip",
            )
            frames.append(df)
        except Exception as exc:  # ventana ilegible: se avisa y se continúa
            print(f"  [aviso] no se pudo leer {fp.name}: {exc}")

    data = pd.concat(frames, ignore_index=True)
    print(f"[datos] Filas brutas (con solapamiento): {len(data):,}")

    # Las ventanas (rows_2000, time_10s, time_60s) solapan vistas del mismo
    # tráfico: se eliminan trazas duplicadas para no sesgar el ML.
    data = data.drop_duplicates(subset=USECOLS)
    print(f"[datos] Filas tras deduplicar: {len(data):,}")
    return data


def load_from_clean_csv(sample_size: int) -> pd.DataFrame:
    """
    Lectura por chunks del dataset limpio completo, acumulando hasta un tope por
    clase (para no cargar ~100M de filas en memoria). Solo se usa si el fichero
    existe.
    """
    print(f"[datos] Leyendo {CLEAN_CSV} por chunks ...")
    per_class_cap = max(2_000, sample_size)  # techo holgado por clase
    pools: dict[str, list] = {}
    reader = pd.read_csv(
        CLEAN_CSV, header=None, names=COLUMN_NAMES, usecols=USECOLS,
        dtype=str, chunksize=1_000_000, encoding="utf-8", on_bad_lines="skip",
    )
    for chunk in reader:
        for label, grp in chunk.groupby("label"):
            cur = pools.setdefault(label, [])
            if len(cur) < per_class_cap:
                cur.append(grp.head(per_class_cap - len(cur)))
        if all(sum(len(g) for g in v) >= per_class_cap for v in pools.values()) and len(pools) > 1:
            # todas las clases observadas han alcanzado el tope -> suficiente
            pass
    frames = [pd.concat(v, ignore_index=True) for v in pools.values()]
    return pd.concat(frames, ignore_index=True)


def load_traces(input_path: str | None, sample_size: int) -> pd.DataFrame:
    if input_path:
        p = Path(input_path)
        if p.exists():
            print(f"[datos] Cargando muestra indicada: {p}")
            return pd.read_csv(p, dtype=str, on_bad_lines="skip")
        print(f"[aviso] --input {p} no existe; se ignora.")
    if CLEAN_CSV.exists():
        return load_from_clean_csv(sample_size)
    print("[datos] august_week1_clean.csv no existe -> se usan las ventanas reales (origen de la v3).")
    return load_from_windows()


# ---------------------------------------------------------------------------
# 2. Limpieza y selección/codificación de features (solo conductuales)
# ---------------------------------------------------------------------------

def _to_num(series, default=0.0):
    return pd.to_numeric(series, errors="coerce").fillna(default)


def build_features(data: pd.DataFrame) -> tuple[pd.DataFrame, pd.Series]:
    """
    Construye SOLO features conductuales/derivadas del flujo.
    Excluye explícitamente IPs y la etiqueta.
    """
    df = pd.DataFrame()

    # --- numéricas directas del flujo ---
    df["duration"] = _to_num(data["duration"])
    df["src_port"] = _to_num(data["src_port"]).astype("int64")
    df["dst_port"] = _to_num(data["dst_port"]).astype("int64")
    df["packets"] = _to_num(data["packets"]).astype("int64")
    df["bytes"] = _to_num(data["bytes"]).astype("int64")

    # --- ratios derivados (conductuales) ---
    df["bytes_per_packet"] = df["bytes"] / df["packets"].clip(lower=1)
    df["packets_per_second"] = df["packets"] / df["duration"].clip(lower=0.001)

    # --- feature temporal simple: hora del día ---
    df["hour"] = (
        data["timestamp"].astype(str).str.slice(11, 13)
        .pipe(pd.to_numeric, errors="coerce").fillna(0).astype("int64")
    )

    # --- flags TCP como variables binarias interpretables (sin one-hot enorme) ---
    flags = data["flags"].fillna("").astype(str)
    for letter in ["S", "A", "R", "P", "F", "U"]:
        df[f"flag_{letter}"] = flags.str.contains(letter, regex=False).astype("int8")

    # --- protocolo: one-hot acotado (cardinalidad baja) ---
    proto = data["protocol"].fillna("OTHER").astype(str).str.upper()
    proto = proto.where(proto.isin(["TCP", "UDP", "ICMP"]), "OTHER")
    for p in ["TCP", "UDP", "ICMP", "OTHER"]:
        df[f"proto_{p}"] = (proto == p).astype("int8")

    y = data["label"].fillna("").astype(str)
    return df, y


# ---------------------------------------------------------------------------
# 3. Muestreo estratificado con tope por clase
# ---------------------------------------------------------------------------

def stratified_capped_sample(X: pd.DataFrame, y: pd.Series, sample_size: int):
    """
    Muestreo estratificado con TOPE por clase: las clases minoritarias se
    incluyen completas y las mayoritarias se recortan, evitando que `background`
    domine. Reproducible con random_state=42.
    """
    classes = y.value_counts()
    n_classes = len(classes)
    cap = max(MIN_CLASS_SAMPLES, sample_size // max(1, n_classes))

    keep_idx = []
    dropped = []
    for cls, count in classes.items():
        idx = y.index[y == cls]
        if count < MIN_CLASS_SAMPLES:
            dropped.append((cls, int(count)))
            continue
        take = min(int(count), cap)
        sampled = pd.Series(idx).sample(n=take, random_state=RANDOM_STATE).tolist()
        keep_idx.extend(sampled)

    if dropped:
        print(f"[muestra] Clases descartadas por escasez (< {MIN_CLASS_SAMPLES}): {dropped}")

    keep_idx = pd.Index(keep_idx)
    Xs = X.loc[keep_idx].reset_index(drop=True)
    ys = y.loc[keep_idx].reset_index(drop=True)
    print(f"[muestra] Tope por clase = {cap}; muestra final = {len(Xs):,} trazas, {ys.nunique()} clases")
    print("[muestra] Distribución:\n" + ys.value_counts().to_string())
    return Xs, ys


# ---------------------------------------------------------------------------
# 4. Entrenamiento y evaluación
# ---------------------------------------------------------------------------

def get_models():
    """Devuelve (nombre, modelo, requiere_escalado, tope_entrenamiento)."""
    return [
        ("LogisticRegression",
         LogisticRegression(max_iter=1000, random_state=RANDOM_STATE, n_jobs=-1),
         True, None),
        ("KNN",
         KNeighborsClassifier(n_neighbors=5, n_jobs=-1),
         True, KNN_MAX_TRAIN),
        ("SVM",
         SVC(kernel="rbf", random_state=RANDOM_STATE),
         True, SVM_MAX_TRAIN),
        ("RandomForest",
         RandomForestClassifier(n_estimators=200, random_state=RANDOM_STATE, n_jobs=-1),
         False, None),
        ("MLPClassifier",
         MLPClassifier(hidden_layer_sizes=(64, 32), max_iter=300, random_state=RANDOM_STATE),
         True, None),
    ]


def maybe_subsample_train(X_tr, y_tr, max_train, name):
    """Reduce la muestra de entrenamiento de un modelo lento, avisando."""
    if max_train is None or len(X_tr) <= max_train:
        return X_tr, y_tr
    print(f"  [aviso] {name}: train {len(X_tr):,} > {max_train:,} -> submuestreo estratificado para evitar lentitud.")
    X_small, _, y_small, _ = train_test_split(
        X_tr, y_tr, train_size=max_train, stratify=y_tr, random_state=RANDOM_STATE)
    return X_small, y_small


def evaluate(name, model, needs_scale, max_train,
             X_tr_raw, X_te_raw, X_tr_scaled, X_te_scaled, y_tr, y_te,
             labels):
    """Entrena y evalúa un modelo. Devuelve (fila_global, filas_por_clase, matriz)."""
    X_tr = X_tr_scaled if needs_scale else X_tr_raw
    X_te = X_te_scaled if needs_scale else X_te_raw

    Xs, ys = maybe_subsample_train(X_tr, y_tr, max_train, name)

    t0 = time.time()
    model.fit(Xs, ys)
    train_time = time.time() - t0
    y_pred = model.predict(X_te)

    acc = accuracy_score(y_te, y_pred)
    pm, rm, fm, _ = precision_recall_fscore_support(y_te, y_pred, average="macro", zero_division=0)
    pw, rw, fw, _ = precision_recall_fscore_support(y_te, y_pred, average="weighted", zero_division=0)

    print(f"  {name:<20} acc={acc:.3f} f1_macro={fm:.3f} f1_weighted={fw:.3f} "
          f"(train {len(Xs):,}, {train_time:.1f}s)")

    global_row = {
        "model": name, "n_train": len(Xs), "n_test": len(y_te),
        "accuracy": round(acc, 4),
        "precision_macro": round(pm, 4), "recall_macro": round(rm, 4), "f1_macro": round(fm, 4),
        "precision_weighted": round(pw, 4), "recall_weighted": round(rw, 4), "f1_weighted": round(fw, 4),
        "train_time_s": round(train_time, 2),
        "note": "train submuestreado" if (max_train and len(Xs) < len(X_tr)) else "",
    }

    report = classification_report(y_te, y_pred, output_dict=True, zero_division=0)
    class_rows = []
    for cls in labels:
        if cls in report:
            r = report[cls]
            class_rows.append({
                "model": name, "class": cls,
                "precision": round(r["precision"], 4), "recall": round(r["recall"], 4),
                "f1": round(r["f1-score"], 4), "support": int(r["support"]),
            })

    cm = confusion_matrix(y_te, y_pred, labels=labels)
    return global_row, class_rows, cm


# ---------------------------------------------------------------------------
# 5. Programa principal
# ---------------------------------------------------------------------------

def main():
    parser = argparse.ArgumentParser(description="Baseline ML clásico vs clasificador contextual v3")
    parser.add_argument("--sample-size", type=int, default=DEFAULT_SAMPLE_SIZE,
                        help="Tamaño objetivo de la muestra (ej. 100000, 300000, 500000)")
    parser.add_argument("--test-size", type=float, default=TEST_SIZE)
    parser.add_argument("--input", type=str, default=None,
                        help="Ruta opcional a una muestra/fichero CSV ya preparado")
    args = parser.parse_args()

    print("===== COMPARACIÓN ML CLÁSICO (baseline) =====")
    print(f"random_state={RANDOM_STATE} | sample_size={args.sample_size} | test_size={args.test_size}\n")

    # --- carga y features ---
    data = load_traces(args.input, args.sample_size)
    X, y = build_features(data)
    del data  # liberar memoria

    X, y = stratified_capped_sample(X, y, args.sample_size)
    labels = sorted(y.unique())

    # --- split estratificado reproducible ---
    X_train, X_test, y_train, y_test = train_test_split(
        X, y, test_size=args.test_size, stratify=y, random_state=RANDOM_STATE)
    print(f"\n[split] train={len(X_train):,} test={len(X_test):,}\n")

    # --- escalado (para KNN/SVM/MLP/LogReg; RF usa sin escalar) ---
    scaler = StandardScaler()
    X_train_scaled = scaler.fit_transform(X_train)
    X_test_scaled = scaler.transform(X_test)
    X_train_raw = X_train.to_numpy()
    X_test_raw = X_test.to_numpy()

    # --- entrenar y evaluar cada modelo ---
    print("[modelos] Entrenando...")
    global_rows, all_class_rows, confusions = [], [], {}
    for name, model, needs_scale, max_train in get_models():
        try:
            g, c, cm = evaluate(
                name, model, needs_scale, max_train,
                X_train_raw, X_test_raw, X_train_scaled, X_test_scaled,
                y_train, y_test, labels)
            global_rows.append(g)
            all_class_rows.extend(c)
            confusions[name] = cm
        except Exception as exc:  # un modelo falla -> se avisa y se continúa
            print(f"  [ERROR] {name} falló y se omite: {exc}")

    # --- guardar resultados (sin sobrescribir datos grandes existentes) ---
    RESULTS_FILE.parent.mkdir(parents=True, exist_ok=True)
    results_df = pd.DataFrame(global_rows).sort_values("f1_macro", ascending=False)
    results_df.to_csv(RESULTS_FILE, index=False, encoding="utf-8")
    pd.DataFrame(all_class_rows).to_csv(SUMMARY_FILE, index=False, encoding="utf-8")

    # --- resumen por consola ---
    print("\n===== RESULTADOS GLOBALES (orden por f1_macro) =====")
    print(results_df[["model", "accuracy", "f1_macro", "f1_weighted", "train_time_s", "note"]].to_string(index=False))

    print("\n===== F1 POR FAMILIA DE ATAQUE =====")
    cls_df = pd.DataFrame(all_class_rows)
    if not cls_df.empty:
        fam = cls_df[cls_df["class"].isin(ATTACK_FAMILIES)]
        pivot = fam.pivot_table(index="class", columns="model", values="f1", aggfunc="first")
        print(pivot.to_string())

    print(f"\nResultados globales: {RESULTS_FILE}")
    print(f"Métricas por clase:  {SUMMARY_FILE}")
    print("\nNOTA: comparación PREDICTIVA. La propuesta principal sigue siendo el "
          "clasificador contextual v3 (interpretable y conectado con hipótesis LLM).")


if __name__ == "__main__":
    main()

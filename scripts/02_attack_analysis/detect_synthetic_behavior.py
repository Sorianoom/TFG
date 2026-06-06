"""
Script: detect_synthetic_behavior.py

Descripción:
Analiza ventanas temporales ya extraídas y aplica un modelo heurístico
para detectar patrones de DoS, UDP Scan y NerisBotnet.

El detector no clasifica por etiqueta, sino por comportamiento:
- DoS: concentración 1→1 + TCP + src_port secuencial + baja duración
- UDP Scan: 1 origen + muchos destinos/puertos + UDP + dst_port secuencial
- NerisBotnet: coordinación distribuida muchos→1 hacia puertos C2

Salida:
- data/attack_analysis/behavior_detection_results.csv

Uso:
python scripts/02_attack_analysis/detect_synthetic_behavior.py
"""

import csv
from pathlib import Path
from collections import Counter, defaultdict
from statistics import mean, variance

BASE_DIR = Path("data/attack_analysis")

WINDOW_PATHS = [
    BASE_DIR / "dos",
    BASE_DIR / "anomaly-udpscan",
    BASE_DIR / "nerisbotnet",
    BASE_DIR / "normal",
]

OUTPUT_FILE = BASE_DIR / "behavior_detection_results.csv"
EXPECTED_COLUMNS = 13

C2_PORTS = {6667, 4506}


def safe_int(value: str, default: int = 0) -> int:
    try:
        return int(value)
    except Exception:
        return default


def safe_float(value: str, default: float = 0.0) -> float:
    try:
        return float(value)
    except Exception:
        return default


def safe_variance(values: list[float | int]) -> float:
    if len(values) <= 1:
        return 0.0
    return variance(values)


def is_mostly_sequential(values: list[int], min_ratio: float = 0.65) -> bool:
    """
    Detecta si una lista de puertos sigue una progresión mayoritariamente secuencial.
    Acepta saltos de +1 o +2 porque en el dataset aparecen ambos casos.
    """
    values = sorted(set(v for v in values if v > 0))

    if len(values) < 5:
        return False

    diffs = [b - a for a, b in zip(values, values[1:])]

    if not diffs:
        return False

    valid_diffs = [d for d in diffs if d in (1, 2)]

    return len(valid_diffs) / len(diffs) >= min_ratio


def read_window(file_path: Path) -> list[dict]:
    rows = []

    with open(file_path, "r", encoding="utf-8", errors="ignore", newline="") as f:
        reader = csv.reader(f)

        for row in reader:
            if len(row) != EXPECTED_COLUMNS:
                continue

            rows.append(
                {
                    "timestamp": row[0],
                    "duration": safe_float(row[1]),
                    "src_ip": row[2],
                    "dst_ip": row[3],
                    "src_port": safe_int(row[4]),
                    "dst_port": safe_int(row[5]),
                    "protocol": row[6],
                    "state": row[7],
                    "src_tos": row[8],
                    "dst_tos": row[9],
                    "packets": safe_int(row[10]),
                    "bytes": safe_int(row[11]),
                    "label": row[12].strip(),
                }
            )

    return rows


def basic_metrics(rows: list[dict]) -> dict:
    total = len(rows)

    labels = [r["label"] for r in rows]
    protocols = [r["protocol"] for r in rows]
    src_ips = [r["src_ip"] for r in rows]
    dst_ips = [r["dst_ip"] for r in rows]
    src_ports = [r["src_port"] for r in rows]
    dst_ports = [r["dst_port"] for r in rows]
    durations = [r["duration"] for r in rows]
    packets = [r["packets"] for r in rows]
    bytes_values = [r["bytes"] for r in rows]
    timestamps = [r["timestamp"] for r in rows]

    dominant_label, dominant_label_count = Counter(labels).most_common(1)[0]
    dominant_protocol, _ = Counter(protocols).most_common(1)[0]
    dominant_src_ip, dominant_src_count = Counter(src_ips).most_common(1)[0]
    dominant_dst_ip, dominant_dst_count = Counter(dst_ips).most_common(1)[0]
    dominant_src_port, _ = Counter(src_ports).most_common(1)[0]
    dominant_dst_port, dominant_dst_port_count = Counter(dst_ports).most_common(1)[0]
    dominant_timestamp, dominant_timestamp_count = Counter(timestamps).most_common(1)[0]

    label_counts = Counter(labels)
    attack_labels = {
        label: count
        for label, count in label_counts.items()
        if label != "background"
    }

    return {
        "total_flows": total,
        "real_label": dominant_label,
        "dominant_label_count": dominant_label_count,
        "attack_labels_found": str(dict(attack_labels)),
        "dominant_protocol": dominant_protocol,
        "dominant_src_ip": dominant_src_ip,
        "dominant_dst_ip": dominant_dst_ip,
        "dominant_src_port": dominant_src_port,
        "dominant_dst_port": dominant_dst_port,
        "unique_src_ips": len(set(src_ips)),
        "unique_dst_ips": len(set(dst_ips)),
        "unique_src_ports": len(set(src_ports)),
        "unique_dst_ports": len(set(dst_ports)),
        "avg_duration": round(mean(durations), 6),
        "avg_packets": round(mean(packets), 3),
        "avg_bytes": round(mean(bytes_values), 3),
        "bytes_variance": round(safe_variance(bytes_values), 3),
        "duration_variance": round(safe_variance(durations), 6),
        "zero_duration_ratio": round(sum(1 for d in durations if d <= 0.001) / total, 3),
        "low_packet_ratio": round(sum(1 for p in packets if p <= 3) / total, 3),
        "same_timestamp_ratio": round(dominant_timestamp_count / total, 3),
        "dominant_src_ratio": round(dominant_src_count / total, 3),
        "dominant_dst_ratio": round(dominant_dst_count / total, 3),
        "dominant_dst_port_ratio": round(dominant_dst_port_count / total, 3),
    }


def detect_dos(rows: list[dict]) -> tuple[bool, str, dict]:
    """
    DoS:
    - TCP
    - duración ~0
    - pocos paquetes
    - mismo src_ip → mismo dst_ip:dst_port
    - src_port secuencial
    - baja varianza
    """
    groups = defaultdict(list)

    for r in rows:
        if r["protocol"] != "TCP":
            continue

        if r["duration"] > 0.001:
            continue

        if r["packets"] > 3:
            continue

        key = (r["src_ip"], r["dst_ip"], r["dst_port"])
        groups[key].append(r)

    best_key = None
    best_group = []

    for key, group in groups.items():
        if len(group) > len(best_group):
            best_key = key
            best_group = group

    if not best_group or best_key is None:
        return False, "sin grupo TCP concentrado", {}

    group_size = len(best_group)

    src_ports = [r["src_port"] for r in best_group]
    durations = [r["duration"] for r in best_group]
    packets = [r["packets"] for r in best_group]
    bytes_values = [r["bytes"] for r in best_group]
    timestamps = [r["timestamp"] for r in best_group]

    src_port_sequential = is_mostly_sequential(src_ports)
    bytes_var = safe_variance(bytes_values)

    zero_duration_ratio = sum(1 for d in durations if d <= 0.001) / group_size
    low_packet_ratio = sum(1 for p in packets if p <= 3) / group_size
    same_timestamp_ratio = Counter(timestamps).most_common(1)[0][1] / group_size

    detected = (
        group_size >= 20
        and src_port_sequential
        and zero_duration_ratio >= 0.90
        and low_packet_ratio >= 0.90
        and same_timestamp_ratio >= 0.50
        and bytes_var < 10_000
    )

    detail = {
        "dos_group_size": group_size,
        "dos_src_ip": best_key[0],
        "dos_dst_ip": best_key[1],
        "dos_dst_port": best_key[2],
        "dos_src_port_sequential": src_port_sequential,
        "dos_zero_duration_ratio": round(zero_duration_ratio, 3),
        "dos_low_packet_ratio": round(low_packet_ratio, 3),
        "dos_same_timestamp_ratio": round(same_timestamp_ratio, 3),
        "dos_bytes_variance": round(bytes_var, 3),
    }

    reason = (
        f"grupo TCP {best_key} con {group_size} flujos; "
        f"src_seq={src_port_sequential}, "
        f"zero_ratio={zero_duration_ratio:.2f}, "
        f"low_pkt={low_packet_ratio:.2f}, "
        f"same_ts={same_timestamp_ratio:.2f}, "
        f"bytes_var={bytes_var:.2f}"
    )

    return detected, reason, detail


def detect_udp_scan(rows: list[dict]) -> tuple[bool, str, dict]:
    """
    UDP Scan:
    - UDP
    - duración ~0
    - 1 o 2 paquetes
    - mismo src_ip:src_port
    - muchos dst_ip
    - muchos dst_port
    - dst_port secuencial
    - baja varianza de bytes
    """
    groups = defaultdict(list)

    for r in rows:
        if r["protocol"] != "UDP":
            continue

        if r["duration"] > 0.001:
            continue

        if r["packets"] > 2:
            continue

        key = (r["src_ip"], r["src_port"])
        groups[key].append(r)

    best_key = None
    best_group = []

    for key, group in groups.items():
        if len(group) > len(best_group):
            best_key = key
            best_group = group

    if not best_group or best_key is None:
        return False, "sin grupo UDP dominante", {}

    dst_ports = [r["dst_port"] for r in best_group]
    dst_ips = [r["dst_ip"] for r in best_group]
    bytes_values = [r["bytes"] for r in best_group]

    unique_dst_ips = len(set(dst_ips))
    unique_dst_ports = len(set(dst_ports))
    dst_port_sequential = is_mostly_sequential(dst_ports)
    bytes_var = safe_variance(bytes_values)

    detected = (
        len(best_group) >= 30
        and unique_dst_ips >= 5
        and unique_dst_ports >= 10
        and dst_port_sequential
        and bytes_var < 100
    )

    detail = {
        "udp_scan_group_size": len(best_group),
        "udp_scan_src_ip": best_key[0],
        "udp_scan_src_port": best_key[1],
        "udp_scan_unique_dst_ips": unique_dst_ips,
        "udp_scan_unique_dst_ports": unique_dst_ports,
        "udp_scan_dst_port_sequential": dst_port_sequential,
        "udp_scan_bytes_variance": round(bytes_var, 3),
    }

    reason = (
        f"grupo UDP {best_key} con {len(best_group)} flujos; "
        f"dst_ips={unique_dst_ips}, "
        f"dst_ports={unique_dst_ports}, "
        f"dst_seq={dst_port_sequential}, "
        f"bytes_var={bytes_var:.2f}"
    )

    return detected, reason, detail


def detect_neris_botnet(rows: list[dict]) -> tuple[bool, str, dict]:
    """
    NerisBotnet:
    busca coordinación distribuida muchos→1 hacia puertos C2.

    Cambio importante:
    - Primero busca explícitamente grupos hacia puertos C2 (6667, 4506).
    - No selecciona el grupo más grande global, porque en tráfico normal puede dominar 80/443.
    """

    c2_groups = defaultdict(list)

    for r in rows:
        if r["dst_port"] not in C2_PORTS:
            continue

        key = (r["dst_ip"], r["dst_port"], r["protocol"], r["timestamp"])
        c2_groups[key].append(r)

    best_key = None
    best_group = []

    for key, group in c2_groups.items():
        unique_src_ips = len(set(r["src_ip"] for r in group))
        best_unique_src_ips = len(set(r["src_ip"] for r in best_group))

        if unique_src_ips > best_unique_src_ips:
            best_key = key
            best_group = group

    if not best_group or best_key is None:
        return False, "sin grupo C2 distribuido", {}

    dst_ip, dst_port, protocol, timestamp = best_key

    src_ips = [r["src_ip"] for r in best_group]
    packets = [r["packets"] for r in best_group]
    bytes_values = [r["bytes"] for r in best_group]
    durations = [r["duration"] for r in best_group]

    unique_src_ips = len(set(src_ips))
    group_size = len(best_group)
    avg_packets = mean(packets)
    avg_bytes = mean(bytes_values)
    bytes_var = safe_variance(bytes_values)
    avg_duration = mean(durations)

    detected = (
        unique_src_ips >= 5
        and group_size >= 5
        and bytes_var < 5_000
    )

    detail = {
        "botnet_group_size": group_size,
        "botnet_unique_src_ips": unique_src_ips,
        "botnet_dst_ip": dst_ip,
        "botnet_dst_port": dst_port,
        "botnet_protocol": protocol,
        "botnet_timestamp": timestamp,
        "botnet_avg_duration": round(avg_duration, 6),
        "botnet_avg_packets": round(avg_packets, 3),
        "botnet_avg_bytes": round(avg_bytes, 3),
        "botnet_bytes_variance": round(bytes_var, 3),
    }

    reason = (
        f"grupo C2 distribuido hacia {dst_ip}:{dst_port}/{protocol} "
        f"en {timestamp}; flujos={group_size}, src_ips={unique_src_ips}, "
        f"bytes_var={bytes_var:.2f}"
    )

    return detected, reason, detail


def analyze_window(file_path: Path) -> dict:
    rows = read_window(file_path)

    if not rows:
        return {
            "file": str(file_path),
            "real_label": "sin_datos",
            "predicted_behavior": "sin_datos",
            "reason": "sin filas válidas",
        }

    metrics = basic_metrics(rows)

    dos_detected, dos_reason, dos_detail = detect_dos(rows)
    udp_detected, udp_reason, udp_detail = detect_udp_scan(rows)
    botnet_detected, botnet_reason, botnet_detail = detect_neris_botnet(rows)

    detections = []

    if dos_detected:
        detections.append(("DoS", dos_reason, dos_detail))

    if udp_detected:
        detections.append(("UDP Scan", udp_reason, udp_detail))

    if botnet_detected:
        detections.append(("NerisBotnet", botnet_reason, botnet_detail))

    if detections:
        predicted_behavior = " + ".join(d[0] for d in detections)
        reason = " | ".join(d[1] for d in detections)
    else:
        predicted_behavior = "No clasificado"
        reason = f"DoS: {dos_reason} | UDP Scan: {udp_reason} | Botnet: {botnet_reason}"

    result = {
        "file": str(file_path),
        "predicted_behavior": predicted_behavior,
        "reason": reason,
    }

    result.update(metrics)

    for _, _, detail in detections:
        result.update(detail)

    return result


def find_csv_files() -> list[Path]:
    files = []

    for folder in WINDOW_PATHS:
        if folder.exists():
            files.extend(sorted(folder.glob("*.csv")))

    return files


def save_results(results: list[dict], output_file: Path) -> None:
    if not results:
        return

    output_file.parent.mkdir(parents=True, exist_ok=True)

    fieldnames = sorted(set().union(*(r.keys() for r in results)))

    with open(output_file, "w", encoding="utf-8", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=fieldnames)
        writer.writeheader()
        writer.writerows(results)


def main() -> None:
    files = find_csv_files()

    if not files:
        print("[ERROR] No se han encontrado ventanas CSV en data/attack_analysis/")
        return

    results = []

    print("\n===== ANÁLISIS DE VENTANAS =====\n")

    for file_path in files:
        result = analyze_window(file_path)
        results.append(result)

        print(f"Archivo: {file_path}")
        print(f"  Label real dominante: {result.get('real_label')}")
        print(f"  Etiquetas de ataque encontradas: {result.get('attack_labels_found')}")
        print(f"  Clasificación modelo: {result.get('predicted_behavior')}")
        print(f"  Motivo: {result.get('reason')}")
        print(f"  Protocolo dominante: {result.get('dominant_protocol')}")
        print(f"  IPs origen únicas: {result.get('unique_src_ips')}")
        print(f"  IPs destino únicas: {result.get('unique_dst_ips')}")
        print(f"  Puertos destino únicos: {result.get('unique_dst_ports')}")
        print(f"  Duración media: {result.get('avg_duration')}")
        print(f"  Bytes medios: {result.get('avg_bytes')}")
        print()

    save_results(results, OUTPUT_FILE)

    print("===== RESULTADO =====")
    print(f"Ventanas analizadas: {len(results)}")
    print(f"Resultados guardados en: {OUTPUT_FILE}")


if __name__ == "__main__":
    main()
from scapy.all import rdpcap, IP, TCP, UDP
import pandas as pd
import os

# Map each pcap filename to the label it represents
FILES = {
    "benign_session4.pcap": "benign",
    "benign_session1_port1883only.pcap": "benign",
    "benign_session2.pcap": "benign",
    "benign_session3.pcap": "benign",
    "attack_scan1.pcap": "scan",
    "attack_bruteforce_ssh4.pcap": "bruteforce",
    "attack_mqtt_flood1.pcap": "mqtt_flood",

}

RAW_DIR = os.path.expanduser("~/ids_project/data/raw_pcaps")
OUTPUT_CSV = os.path.expanduser("~/ids_project/data/dataset.csv")

def extract_flows(pcap_path, label):
    print(f"Reading {pcap_path} ...")
    packets = rdpcap(pcap_path)
    flows = {}

    for pkt in packets:
        if IP not in pkt:
            continue
        proto = "TCP" if TCP in pkt else ("UDP" if UDP in pkt else "OTHER")
        src = pkt[IP].src
        dst = pkt[IP].dst
        sport = pkt.sport if hasattr(pkt, "sport") else 0
        dport = pkt.dport if hasattr(pkt, "dport") else 0

        # Group by conversation, regardless of direction
        key = tuple(sorted([(src, sport), (dst, dport)])) + (proto,)

        if key not in flows:
            flows[key] = {
                "packet_count": 0,
                "total_bytes": 0,
                "start_time": float(pkt.time),
                "end_time": float(pkt.time),
                "src_ports": set(),
                "dst_ports": set(),
            }

        f = flows[key]
        f["packet_count"] += 1
        f["total_bytes"] += len(pkt)
        f["end_time"] = float(pkt.time)
        f["src_ports"].add(sport)
        f["dst_ports"].add(dport)

    rows = []
    for key, f in flows.items():
        duration = max(f["end_time"] - f["start_time"], 0.0001)  # avoid divide-by-zero
        rows.append({
            "packet_count": f["packet_count"],
            "total_bytes": f["total_bytes"],
            "duration": duration,
            "avg_packet_size": f["total_bytes"] / f["packet_count"],
            "packets_per_second": f["packet_count"] / duration,
            "unique_dst_ports": len(f["dst_ports"]),
            "label": label,
        })
    return rows

all_rows = []
for filename, label in FILES.items():
    path = os.path.join(RAW_DIR, filename)
    if os.path.exists(path):
        all_rows.extend(extract_flows(path, label))
    else:
        print(f"WARNING: {filename} not found, skipping.")

df = pd.DataFrame(all_rows)
df.to_csv(OUTPUT_CSV, index=False)
print(f"\nDone. Saved {len(df)} flow rows to {OUTPUT_CSV}")
print(df["label"].value_counts())

import pandas as pd
import json

df = pd.read_csv("~/ids_project/data/dataset.csv".replace("~", "/home/stan"))

FEATURES = ["packet_count", "total_bytes", "duration", "avg_packet_size",
            "packets_per_second", "unique_dst_ports"]

for label in df["label"].unique():
    row = df[df["label"] == label].iloc[0]
    payload = {f: float(row[f]) for f in FEATURES}
    print(f"\n--- {label} ---")
    print(json.dumps(payload))

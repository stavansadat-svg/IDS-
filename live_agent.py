from scapy.all import sniff, IP, TCP, UDP
import requests
import time

API_URL = "http://localhost:5000/predict"
INTERFACE = "enp0s8"
WINDOW_SECONDS = 5

def build_flows(packets):
    flows = {}
    for pkt in packets:
        if IP not in pkt:
            continue
        proto = "TCP" if TCP in pkt else ("UDP" if UDP in pkt else "OTHER")
        src = pkt[IP].src
        dst = pkt[IP].dst
        sport = pkt.sport if hasattr(pkt, "sport") else 0
        dport = pkt.dport if hasattr(pkt, "dport") else 0

        key = tuple(sorted([(src, sport), (dst, dport)])) + (proto,)

        if key not in flows:
            flows[key] = {
                "packet_count": 0,
                "total_bytes": 0,
                "start_time": float(pkt.time),
                "end_time": float(pkt.time),
                "dst_ports": set(),
                "src": src,
                "dst": dst,
            }

        f = flows[key]
        f["packet_count"] += 1
        f["total_bytes"] += len(pkt)
        f["end_time"] = float(pkt.time)
        f["dst_ports"].add(dport)

    results = []
    for key, f in flows.items():
        duration = max(f["end_time"] - f["start_time"], 0.0001)
        results.append({
            "src": f["src"],
            "dst": f["dst"],
            "packet_count": f["packet_count"],
            "total_bytes": f["total_bytes"],
            "duration": duration,
            "avg_packet_size": f["total_bytes"] / f["packet_count"],
            "packets_per_second": f["packet_count"] / duration,
            "unique_dst_ports": len(f["dst_ports"]),
        })
    return results

def process_batch(packets):
    flows = build_flows(packets)
    if not flows:
        return

    for flow in flows:
        payload = {k: flow[k] for k in
                   ["packet_count", "total_bytes", "duration",
                    "avg_packet_size", "packets_per_second", "unique_dst_ports"]}
        try:
            r = requests.post(API_URL, json=payload, timeout=2)
            result = r.json()
            verdict = result.get("final_verdict", "UNKNOWN")
            rf = result.get("random_forest_verdict", "?")
            conf = result.get("random_forest_confidence", 0)
            
            tag = "🚨" if verdict == "MALICIOUS" else "✅"
            print(f"{tag} {flow['src']} -> {flow['dst']} | "
                  f"pkts={flow['packet_count']} | RF={rf} ({conf}) | {verdict}")

            log_line = {
                "time": time.strftime("%H:%M:%S"),
                "src": flow['src'],
                "dst": flow['dst'],
                "packet_count": flow['packet_count'],
                "rf_verdict": rf,
                "rf_confidence": conf,
                "iso_verdict": result.get("isolation_forest_verdict", "?"),
                "final_verdict": verdict,
            }
            with open("/home/stan/ids_project/live_log.csv", "a") as f:
                f.write(",".join(str(v) for v in log_line.values()) + "\n")
        except requests.exceptions.RequestException as e:
            print(f"Could not reach API: {e}")

print(f"Live agent started. Watching {INTERFACE} in {WINDOW_SECONDS}s windows...")
print("Make sure app.py (Flask API) is running in another terminal.\n")

try:
    while True:
        packets = sniff(iface=INTERFACE, timeout=WINDOW_SECONDS)
        process_batch(packets)
except KeyboardInterrupt:
    print("\nStopping live agent.")


import random
import time
from collections import Counter, defaultdict


# data input (real or fallback)
def get_packet_data(source="mock", input_data=None):
    if source == "input" and input_data:
        return input_data

    # fallback mock (for demo / testing)
    protocols = ["TCP", "UDP", "HTTP", "DNS"]
    data = []

    for _ in range(30):
        data.append({
            "src_ip": f"192.168.1.{random.randint(1,10)}",
            "dst_ip": f"192.168.1.{random.randint(11,50)}",
            "protocol": random.choice(protocols),
            "length": random.randint(40, 1500),
            "time": time.time() + random.random()
        })

    return data


# packet table
def packet_table(data):
    return [
        {
            "No": i + 1,
            "Source": pkt["src_ip"],
            "Destination": pkt["dst_ip"],
            "Protocol": pkt["protocol"],
            "Length": pkt["length"]
        }
        for i, pkt in enumerate(data)
    ]


# protocol summary
def protocol_summary(data):
    return dict(Counter(pkt["protocol"] for pkt in data))


# protocol hierarchy
def protocol_hierarchy(data):
    summary = protocol_summary(data)
    total = sum(summary.values()) or 1

    return {
        proto: {
            "count": count,
            "percentage": round((count / total) * 100, 2)
        }
        for proto, count in summary.items()
    }


# top talkers
def top_talkers(data):
    return dict(Counter(pkt["src_ip"] for pkt in data))


# conversation summary
def conversation_summary(data):
    conv = Counter((pkt["src_ip"], pkt["dst_ip"]) for pkt in data)
    return {f"{s} -> {d}": c for (s, d), c in conv.items()}


# communication graph
def communication_graph(data):
    graph = defaultdict(list)
    for pkt in data:
        graph[pkt["src_ip"]].append(pkt["dst_ip"])
    return dict(graph)


# bandwidth usage
def bandwidth_usage(data):
    total_bytes = sum(pkt["length"] for pkt in data)
    return round(total_bytes / 1024, 2)


# session duration
def session_duration(data):
    if not data:
        return 0
    times = [pkt["time"] for pkt in data]
    return round(max(times) - min(times), 2)


# protocol filter
def filter_by_protocol(data, protocol):
    return [pkt for pkt in data if pkt["protocol"] == protocol]


# behavior detection
def detect_behavior(data):
    alerts = []
    protocols = [pkt["protocol"] for pkt in data]

    if "HTTP" in protocols:
        alerts.append("Unencrypted HTTP traffic")

    if protocols.count("DNS") > 10:
        alerts.append("High DNS activity")

    if len(set(pkt["dst_ip"] for pkt in data)) > 15:
        alerts.append("High number of unique destinations")

    if any(not pkt["dst_ip"].startswith("192.168") for pkt in data):
        alerts.append("External communication detected")

    return alerts


# scoring
def anomaly_score(alerts):
    return len(alerts)


def risk_level(score):
    if score <= 1:
        return "Low"
    elif score <= 3:
        return "Moderate"
    elif score <= 5:
        return "High"
    else:
        return "Critical"


# main function (this is what they’ll call)
def run_tshark_analysis(source="mock", input_data=None):
    data = get_packet_data(source, input_data)

    alerts = detect_behavior(data)
    score = anomaly_score(alerts)

    return {
        "packet_table": packet_table(data),
        "protocol_summary": protocol_summary(data),
        "protocol_hierarchy": protocol_hierarchy(data),
        "top_talkers": top_talkers(data),
        "conversation_summary": conversation_summary(data),
        "communication_graph": communication_graph(data),
        "bandwidth_kb": bandwidth_usage(data),
        "session_duration_sec": session_duration(data),
        "alerts": alerts,
        "anomaly_score": score,
        "risk_level": risk_level(score)
    }


# run test
if __name__ == "__main__":
    result = run_tshark_analysis()
    print(result)

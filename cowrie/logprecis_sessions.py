# Run LogPrecis on Cowrie sessions and count the fingerprints
# usage: python3 cowrie/logprecis_sessions.py <cowrie log file> [max sessions]

import sys
from collections import Counter
from transformers import pipeline
from cowrie_analysis import session_by_ip, normalise_command

log_file = sys.argv[1]
max_sessions = int(sys.argv[2]) if len(sys.argv) > 2 else 200

# Jesus's function: {ip: {"sessions": {session_id: [(timestamp, command), ...]}}}
ip_data = session_by_ip(log_file)

sessions = []
for ip, data in ip_data.items():
    for sid, cmds in data["sessions"].items():
        text = " ; ".join(normalise_command(c) for _, c in cmds)
        sessions.append(text[:1000])  # model can't take very long input

sessions = sessions[:max_sessions]
print(f"{len(ip_data)} IPs, running LogPrecis on {len(sessions)} sessions\n")

model = pipeline(
    "token-classification",
    model="SmartDataPolito/logprecis",
    aggregation_strategy="simple",
    device="cpu",
)

fingerprints = Counter()
examples = {}
for text in sessions:
    tactics = [t["entity_group"] for t in model(text)]
    fp = " -> ".join(dict.fromkeys(tactics))
    fingerprints[fp] += 1
    examples.setdefault(fp, text)

print("Most common fingerprints:")
for fp, n in fingerprints.most_common(15):
    print(f"{n:>5}  {fp}")

print("\nOne example session per fingerprint:")
for fp, n in fingerprints.most_common(5):
    print(f"\n{fp}\n  {examples[fp][:200]}")

# Spot-check LogPrecis by hand
# usage: python3 <path>/logprecis_spotcheck.py <folder with cowrie logs> [number of sessions]
#
# Makes two files in the current folder:
#   spotcheck_to_label.csv  - only the commands, fill in your own label first
#   spotcheck_answers.csv   - what LogPrecis said, open this after labelling

import csv
import sys
import random
from pathlib import Path
from transformers import pipeline
from cowrie_analysis import session_by_ip, normalise_command, merge_ip

folder = sys.argv[1]
n = int(sys.argv[2]) if len(sys.argv) > 2 else 15

ip_data = {}
for f in sorted(Path(folder).rglob("cowrie*.json*")):
    merge_ip(ip_data, session_by_ip(f))

# unique command texts only, so 189 identical bot sessions count once
unique = {}
for data in ip_data.values():
    for sid, cmds in data["sessions"].items():
        text = " ; ".join(normalise_command(c) for _, c in cmds)[:1000]
        unique.setdefault(text, sid)

texts = list(unique)
random.seed(1)
sample = random.sample(texts, min(n, len(texts)))
print(f"{len(texts)} different sessions, picked {len(sample)}")

model = pipeline(
    "token-classification",
    model="SmartDataPolito/logprecis",
    aggregation_strategy="simple",
    device="cpu",
)

with open("spotcheck_to_label.csv", "w", newline="") as f1, open("spotcheck_answers.csv", "w", newline="") as f2:
    w1, w2 = csv.writer(f1), csv.writer(f2)
    w1.writerow(["nr", "commands", "my_label"])
    w2.writerow(["nr", "commands", "logprecis", "lowest_score"])
    for i, text in enumerate(sample, 1):
        tags = model(text)
        fp = " -> ".join(dict.fromkeys(t["entity_group"] for t in tags))
        low = min((t["score"] for t in tags), default=0)
        w1.writerow([i, text, ""])
        w2.writerow([i, text, fp, f"{low:.2f}"])

print("Done: spotcheck_to_label.csv and spotcheck_answers.csv")

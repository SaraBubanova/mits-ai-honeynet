"""Step: turn the PCAP flow tables into verdicts.

Input:  <results>/pcap/results/merged_enriched_port_{22,80}.csv, merged_csv_port_{23,10110}.csv
        (falls back to merged_csv_port_N.csv when there is no enriched file)
Output: <results>/verdicts/pcap.json          list of verdicts, see schemas/verdict.schema.json
        <results>/verdicts/pcap_prompt.txt    exactly what was (or would be) sent to the model

PRELIMINARY. Without an LLM configured (see llm.py) the verdicts are stats only:
model "none", label "unreviewed", severity "info", confidence 0. They exist so the steps
after this one have real data to read. With an LLM, the model writes the verdicts from
the same per-IP stats.
"""
import json
import logging
from datetime import datetime, timezone

import pandas as pd

from .. import llm
from ..config import MissingInput

NAME = "pcap_verdict"
log = logging.getLogger("honeynet")

PORTS = [22, 23, 80, 10110]
TOP_IPS = 20  # per-IP verdicts are written for the busiest source IPs only

SYSTEM = (
    "You are a security analyst reviewing traffic captured by a honeynet. "
    "You get per-source-IP statistics from the PCAP pipeline. Reply with ONLY a JSON list. "
    "One object per IP worth reporting, with keys: entity_id (the IP), label (short), "
    "verdict (benign|suspicious|malicious), severity (info|low|medium|high|critical), "
    "confidence (0 to 1), summary (2-4 sentences), evidence (list of strings), "
    "recommended_actions (list of strings). Base everything ONLY on the data given."
)


def _iso(ms):
    return datetime.fromtimestamp(float(ms) / 1000, timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def load_flows(results):
    frames = []
    for port in PORTS:
        for name in (f"merged_enriched_port_{port}.csv", f"merged_csv_port_{port}.csv"):
            path = results / name
            if path.exists():
                df = pd.read_csv(path, low_memory=False)
                if len(df):
                    frames.append(df)
                break
    return pd.concat(frames, ignore_index=True) if frames else None


def ip_stats(flows):
    """One dict per source IP, busiest first."""
    out = []
    for ip, g in flows.groupby("src_ip"):
        s = {
            "ip": ip,
            "flows": int(len(g)),
            "ports": {str(p): int(n) for p, n in g["dst_port"].value_counts().items()},
            "dst_ips": int(g["dst_ip"].nunique()),
            "first_seen": _iso(g["bidirectional_first_seen_ms"].min()),
            "last_seen": _iso(g["bidirectional_last_seen_ms"].max()),
            "packets": int(g["bidirectional_packets"].sum()) if "bidirectional_packets" in g else None,
        }
        if "auth_success" in g:
            s["ssh_auth"] = {str(k): int(v) for k, v in g["auth_success"].value_counts().items()}
        if "auth_attempts" in g:
            s["ssh_auth_attempts_total"] = int(pd.to_numeric(g["auth_attempts"], errors="coerce").fillna(0).sum())
        if "clients" in g:
            s["ssh_clients"] = [str(c) for c in g["clients"].dropna().value_counts().head(3).index]
        if "user_agent" in g:
            s["http_user_agents"] = [str(u) for u in g["user_agent"].dropna().value_counts().head(3).index]
        out.append(s)
    out.sort(key=lambda s: s["flows"], reverse=True)
    return out[:TOP_IPS]


def stats_only_verdict(s):
    evidence = [f"{s['flows']} flows to {s['dst_ips']} destination IP(s)",
                "destination ports: " + ", ".join(f"{p} ({n})" for p, n in s["ports"].items())]
    if s.get("ssh_auth_attempts_total"):
        evidence.append(f"{s['ssh_auth_attempts_total']} SSH auth attempts, outcomes {s.get('ssh_auth')}")
    if s.get("ssh_clients"):
        evidence.append("SSH clients: " + ", ".join(s["ssh_clients"]))
    if s.get("http_user_agents"):
        evidence.append("HTTP user agents: " + ", ".join(s["http_user_agents"]))
    return {
        "source": "pcap", "model": "none", "entity_type": "ip", "entity_id": s["ip"],
        "label": "unreviewed", "severity": "info", "confidence": 0.0,
        "summary": f"{s['flows']} flows from this IP between {s['first_seen']} and {s['last_seen']}. "
                   "No model has looked at it yet.",
        "evidence": evidence, "first_seen": s["first_seen"], "last_seen": s["last_seen"],
        "event_count": s["flows"],
    }


def llm_verdicts(stats, step):
    """Ask the model, then fill in the fixed fields ourselves so they can't be wrong."""
    reply = llm.chat(step, SYSTEM, json.dumps(stats, indent=1))
    reply = reply.strip().removeprefix("```json").removeprefix("```").removesuffix("```").strip()
    by_ip = {s["ip"]: s for s in stats}
    verdicts = []
    for v in json.loads(reply):
        s = by_ip.get(v.get("entity_id"))
        if s is None:
            log.warning("model returned a verdict for unknown IP %r, dropped", v.get("entity_id"))
            continue
        v.update({"source": "pcap", "model": llm.model_for(step), "entity_type": "ip",
                  "first_seen": s["first_seen"], "last_seen": s["last_seen"], "event_count": s["flows"]})
        verdicts.append(v)
    return verdicts


def run(cfg):
    results = cfg.results_dir / "pcap" / "results"
    flows = load_flows(results) if results.is_dir() else None
    if flows is None:
        raise MissingInput(f"no flow tables in {results}. Run pcap_flows first.")

    stats = ip_stats(flows)
    out_dir = cfg.results_dir / "verdicts"
    out_dir.mkdir(parents=True, exist_ok=True)
    (out_dir / "pcap_prompt.txt").write_text(SYSTEM + "\n\n" + json.dumps(stats, indent=1), encoding="utf-8")

    if llm.configured(NAME):
        verdicts = llm_verdicts(stats, NAME)
    else:
        log.warning("no LLM configured (LLM_BASE_URL / LLM_API_KEY / LLM_MODEL in .env): "
                    "writing stats-only verdicts, marked unreviewed")
        verdicts = [stats_only_verdict(s) for s in stats]

    path = out_dir / "pcap.json"
    path.write_text(json.dumps(verdicts, indent=2), encoding="utf-8")
    log.info("wrote %d verdicts to %s", len(verdicts), path)

import os
import json
from pathlib import Path
import pandas as pd
from dotenv import load_dotenv, find_dotenv

load_dotenv(find_dotenv())

# ===== LLM CONFIG =====
LLM_PROVIDER = os.getenv("LLM_PROVIDER", "")  
LLM_API_KEY  = os.getenv("LLM_API_KEY", "")   
LLM_MODEL    = os.getenv("LLM_MODEL", "")     
LLM_BASE_URL = os.getenv("LLM_BASE_URL", "") 

# ===== INPUT CONFIG =====
# Run this script from the pcap/ folder after the pipeline has run:
#   python pcap_analysis.py && python http_enrichment.py && python ssh_enrichment.py
RESULTS_DIR = Path("results")
PORTS = [22, 23, 80, 10110]
#FIXME: Adjust these values later based on the LLM and its maximum context size. 
MAX_ROWS_PER_FILE = 50     
MAX_LOG_ENTRIES = 100       
MAX_FILES_PER_SECTION = 20  

# TODO: Change the output format here based on the next step after the LLM Verdict
PROMPT_OUTPUT = RESULTS_DIR / "llm_verdict_prompt.txt"
VERDICT_OUTPUT = RESULTS_DIR / "llm_verdict.txt"

# TODO: Adjust prompt acoording to the (new)requiements.
VERDICT_INSTRUCTIONS = """You are a security analyst reviewing traffic captured by a honeynet.
Below are the outputs of the PCAP analysis pipeline (NFStream flow statistics, HTTP and SSH
enrichment, and Zeek logs). Based ONLY on this data, produce a verdict with the following format:

VERDICT: <benign | suspicious | malicious>
CONFIDENCE: <low | medium | high>
SUMMARY: <what happened in this traffic, 2-4 sentences>
KEY EVIDENCE: <bullet list of the most important indicators: source IPs, URIs, hosts, SSH auth
attempts, suspicious user agents, ports, etc.>
RECOMMENDED ACTIONS: <bullet list>
"""


def summarize_csv(path, max_rows=MAX_ROWS_PER_FILE):
  try:
    df = pd.read_csv(path, low_memory=False)
  except Exception as e:
    print(f"Could not read {path.name}: {e}")
    return {"file": str(path.relative_to(RESULTS_DIR)), "error": str(e)}

  df = df.where(pd.notna(df), None)

  summary = {
    "file": str(path.relative_to(RESULTS_DIR)),
    "rows": int(len(df)),
    "columns": int(len(df.columns)),
  }

  if "src_ip" in df.columns:
    summary["top_src_ips"] = df["src_ip"].value_counts().head(10).to_dict()
  if "dst_ip" in df.columns:
    summary["top_dst_ips"] = df["dst_ip"].value_counts().head(10).to_dict()
  if "bidirectional_first_seen_ms" in df.columns:
    summary["first_seen_ms"] = float(df["bidirectional_first_seen_ms"].min())
    if "bidirectional_last_seen_ms" in df.columns:
      summary["last_seen_ms"] = float(df["bidirectional_last_seen_ms"].max())

  summary["sample_rows"] = df.head(max_rows).to_dict(orient="records")
  return summary


def parse_zeek_log(path, max_entries=MAX_LOG_ENTRIES):
  fields = None
  rows = []

  with open(path) as f:
    for line in f:
      line = line.rstrip("\n")

      if line.startswith("#fields"):
        fields = line.split("\t")[1:]
        continue

      if line.startswith("#") or fields is None:
        continue

      rows.append(dict(zip(fields, line.split("\t"))))

      if len(rows) >= max_entries:
        break

  return {
    "file": str(path.relative_to(RESULTS_DIR)),
    "entries_read": len(rows),
    "sample": rows,
  }


def collect_section(files, parser, max_files=MAX_FILES_PER_SECTION):
  files = sorted(files)
  if len(files) > max_files:
    print(f"  Capping at {max_files} files ({len(files)} found, rest skipped)")
    files = files[:max_files]
  return [parser(f) for f in files]


def collect_inputs():
  # Gather everything the pipeline produced under results/.
  # Per-chunk raw flow CSVs are skipped on purpose: the merged_csv_port_*.csv files
  # already contain all of their rows.
  context = {}

  if not RESULTS_DIR.exists():
    print(f"No {RESULTS_DIR}/ folder found. Run the PCAP pipeline first "
          "(pcap_analysis.py, http_enrichment.py, ssh_enrichment.py).")
    return context

  print("Collecting pcap_analysis outputs (merged NFStream flow CSVs per port)...")
  flow_files = [f for port in PORTS for f in RESULTS_DIR.glob(f"merged_csv_port_{port}.csv")]
  context["pcap_analysis_flows"] = collect_section(flow_files, summarize_csv)
  print(f"  {len(context['pcap_analysis_flows'])} file(s)")

  print("Collecting http_enrichment outputs (port 80 enriched CSVs)...")
  http_files = list(RESULTS_DIR.glob("port_80/*_enriched.csv")) + list(RESULTS_DIR.glob("merged_enriched_port_80.csv"))
  context["http_enrichment"] = collect_section(http_files, summarize_csv)
  print(f"  {len(context['http_enrichment'])} file(s)")

  print("Collecting ssh_enrichment outputs (port 22 enriched CSVs)...")
  ssh_files = list(RESULTS_DIR.glob("port_22/*_enriched.csv")) + list(RESULTS_DIR.glob("merged_enriched_port_22.csv"))
  context["ssh_enrichment"] = collect_section(ssh_files, summarize_csv)
  print(f"  {len(context['ssh_enrichment'])} file(s)")

  print("Collecting zeek logs (*.log under results/)...")
  log_files = list(RESULTS_DIR.rglob("*.log"))
  context["zeek_logs"] = collect_section(log_files, parse_zeek_log)
  print(f"  {len(context['zeek_logs'])} file(s)")

  return context


def build_prompt(context):
  sections = [VERDICT_INSTRUCTIONS, "=== PCAP PIPELINE OUTPUTS ==="]

  for section_name, items in context.items():
    sections.append(f"\n--- {section_name} ---")
    if not items:
      sections.append("(no data)")
    else:
      sections.append(json.dumps(items, indent=2, default=str))

  return "\n".join(sections)


def call_llm(prompt):
  #TODO: IMPLEMENT HERE THE LLM CALL. Examples are mentioned below. 
  
  # Plug the chosen LLM in here. The prompt is fully assembled at this point.
  # Examples (install the matching package first, e.g. pip install openai):
  #
  # OpenAI-compatible (also works with many proxies via LLM_BASE_URL):
  #   from openai import OpenAI
  #   client = OpenAI(api_key=LLM_API_KEY, base_url=LLM_BASE_URL or None)
  #   resp = client.chat.completions.create(model=LLM_MODEL, messages=[{"role": "user", "content": prompt}])
  #   return resp.choices[0].message.content
  #
  # Anthropic:
  #   import anthropic
  #   client = anthropic.Anthropic(api_key=LLM_API_KEY)
  #   resp = client.messages.create(model=LLM_MODEL, max_tokens=4096, messages=[{"role": "user", "content": prompt}])
  #   return resp.content[0].text
  #
  # Ollama (local, no API key needed):
  #   import ollama
  #   resp = ollama.chat(model=LLM_MODEL, messages=[{"role": "user", "content": prompt}])
  #   return resp["message"]["content"]

  if not LLM_PROVIDER or not LLM_MODEL:
    print("No LLM configured yet. Set LLM_PROVIDER / LLM_MODEL / LLM_API_KEY "
          "at the top of this file or via environment variables / .env.")
    return None

  raise NotImplementedError(
    f"LLM_PROVIDER '{LLM_PROVIDER}' is not wired up in call_llm() yet. "
    "See the commented examples in call_llm() and add a branch for your provider."
  )


def main():
  context = collect_inputs()

  prompt = build_prompt(context)

  RESULTS_DIR.mkdir(parents=True, exist_ok=True)
  PROMPT_OUTPUT.write_text(prompt, encoding="utf-8")
  print(f"\nAssembled prompt ({len(prompt):,} chars) and saved to {PROMPT_OUTPUT}")

  verdict = call_llm(prompt)

  if verdict is None:
    print("No verdict produced (LLM not configured). The assembled prompt is ready "
          f"at {PROMPT_OUTPUT} — paste it into any LLM to test.")
    return

  VERDICT_OUTPUT.write_text(verdict, encoding="utf-8")
  print(f"Verdict saved to {VERDICT_OUTPUT}\n")
  print(verdict)


if __name__ == "__main__":
  main()

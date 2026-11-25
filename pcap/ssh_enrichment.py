import shutil
import subprocess
import tempfile
from concurrent.futures import ProcessPoolExecutor, as_completed
from pathlib import Path

import pandas as pd

SPLIT_DIR = Path("preprocessed_pcaps")
RESULTS_DIR = Path("results") / "port_22"
MAX_WORKERS = 3

def repair_pcap_with_editcap(pcap_path, tmp_dir):
  fixed_pcap = tmp_dir / f"{pcap_path.stem}_fixed.pcap"

  try:
    subprocess.run(
      [
        "editcap", 
       str(pcap_path),
       str(fixed_pcap)
      ],
      capture_output=True,
      check=True
    )
  except FileNotFoundError:
    print("Editcap not found. Install Wireshark")
    return None
  except subprocess.CalledProcessError as e:
    print(f"Editcap could not repair {pcap_path.name}: {e.stderr.decode(errors='replace')}")
    return None

  if fixed_pcap.exists():
    return fixed_pcap

  return None


def run_zeek(pcap_path, tmp_dir):
  ssh_log_out = RESULTS_DIR / f"{pcap_path.stem}_ssh.log"

  try:
    subprocess.run(
      [
        "zeek",
        "-r", str(pcap_path),
        "local",
        f"Log::default_logdir={tmp_dir}"
      ],
      capture_output=True,
      check=True
    )

  except subprocess.CalledProcessError as e:
    stderr = e.stderr.decode(errors="replace")

    if "truncated dump file" not in stderr:
      print(f"Zeek failed on {pcap_path.name}: {stderr}")
      return None

    print(f"PCAP is truncated, trying editcap repair: {pcap_path.name}")

    fixed_pcap = repair_pcap_with_editcap(pcap_path, tmp_dir)

    if fixed_pcap is None:
      print(f"Could not repair truncated PCAP: {pcap_path.name}")
      return None

    try:
      subprocess.run(
        [
          "zeek",
          "-r", str(fixed_pcap),
          "local",
          f"Log::default_logdir={tmp_dir}"
        ],
        capture_output=True,
        check=True
      )
    except subprocess.CalledProcessError as e2:
      print(f"Zeek still failed after editcap repair on {pcap_path.name}: {e2.stderr.decode(errors='replace')}")
      return None

  ssh_log = tmp_dir / "ssh.log"

  if not ssh_log.exists():
    return None

  shutil.copy(ssh_log, ssh_log_out)
  return ssh_log


def parse_zeek_ssh(ssh_log):
  fields = None
  rows = []

  with open(ssh_log) as f:
    for line in f:
      line = line.rstrip("\n")

      if line.startswith("#fields"):
        fields = line.split("\t")[1:]
        continue

      if line.startswith("#") or fields is None:
        continue

      values = line.split("\t")
      rows.append(dict(zip(fields, values)))

  df = pd.DataFrame(rows)

  if df.empty:
    return df

  df.replace("-", pd.NA, inplace=True)
  df.replace("(empty)", pd.NA, inplace=True)

  df["ts"] = pd.to_numeric(df["ts"], errors="coerce")
  df["id.orig_p"] = pd.to_numeric(df["id.orig_p"], errors="coerce")
  df["id.resp_p"] = pd.to_numeric(df["id.resp_p"], errors="coerce")
  df["ts_ms"] = df["ts"] * 1000 # Matching to NFStream
  return df


def classify_auth(x):
  vals = x.dropna().astype(str)

  if (vals == "T").any():
    return "success"

  if (vals == "F").any():
    return "failed"

  return "unknown"


def clean_unique_list(x):
  return list(dict.fromkeys(v for v in x.dropna() if v not in ["-", "(empty)"]))


def enrich_chunk(flow_csv):

  # For each flow_csv under the port 22 folder, find its matching PCAP file.
  pcap_path = next(SPLIT_DIR.rglob(f"{flow_csv.stem}.pcap"), None)

  if pcap_path is None:
    print(f"No pcap found for {flow_csv.name}")
    return

  out_path = RESULTS_DIR / f"{flow_csv.stem}_enriched.csv"

  # Skip processing if the final enriched CSV already exists.
  if out_path.exists():
    print(f"Skipping already exists: {out_path.name}")
    return

  df_flow = pd.read_csv(flow_csv, low_memory=False)

  ssh_log_out = RESULTS_DIR / f"{flow_csv.stem}_ssh.log"

  # Skip Zeek if ssh.log already exists for this file.
  if ssh_log_out.exists():
    df_ssh = parse_zeek_ssh(ssh_log_out)
  else:
    with tempfile.TemporaryDirectory() as tmp:
      tmp_dir = Path(tmp)
      ssh_log = run_zeek(pcap_path, tmp_dir)

      if ssh_log is None:
        print(f"No ssh.log for {pcap_path.name}")
        df_flow.to_csv(out_path, index=False)
        return

      df_ssh = parse_zeek_ssh(ssh_log)

  if df_ssh.empty:
    print(f"No SSH traffic in {pcap_path.name}")
    df_flow.to_csv(out_path, index=False)
    return

  results = []

  for _, row in df_ssh.iterrows():
    # Match Zeek SSH rows to NFStream flows using the same style as the port 80 script.
    match = df_flow[
      (df_flow["src_ip"] == row["id.orig_h"]) &
      (df_flow["src_port"] == row["id.orig_p"]) &
      (df_flow["dst_ip"] == row["id.resp_h"]) &
      (df_flow["dst_port"] == row["id.resp_p"]) &
      (df_flow["bidirectional_first_seen_ms"] <= row["ts_ms"]) &
      (df_flow["bidirectional_last_seen_ms"] >= row["ts_ms"])
    ]

    if not match.empty:
      results.append({
        "flow_id": int(match.iloc[0]["id"]),
        "auth_success": row.get("auth_success"),
        "auth_attempts": row.get("auth_attempts"),
        "version": row.get("version"),
        "client": row.get("client"),
        "server": row.get("server"),
        "cipher_alg": row.get("cipher_alg"),
        "mac_alg": row.get("mac_alg"),
        "compression_alg": row.get("compression_alg"),
        "kex_alg": row.get("kex_alg"),
        "host_key_alg": row.get("host_key_alg"),
        "host_key": row.get("host_key"),
      })

  if not results:
    print(f"No matches for {pcap_path.name}")
    df_flow.to_csv(out_path, index=False)
    return

  df_results = pd.DataFrame(results)

  # Group by flow_id because one flow may contain more than one SSH log entry.
  agg = df_results.groupby("flow_id").agg(
    auth_success=("auth_success", classify_auth),
    auth_attempts=("auth_attempts", lambda x: pd.to_numeric(x, errors="coerce").max()),
    ssh_versions=("version", clean_unique_list),
    clients=("client", clean_unique_list),
    servers=("server", clean_unique_list),
    cipher_algs=("cipher_alg", clean_unique_list),
    mac_algs=("mac_alg", clean_unique_list),
    compression_algs=("compression_alg", clean_unique_list),
    kex_algs=("kex_alg", clean_unique_list),
    host_key_algs=("host_key_alg", clean_unique_list),
    host_keys=("host_key", clean_unique_list),
    ssh_record_count=("version", "count"),
  ).reset_index()

  enriched = df_flow.merge(agg, left_on="id", right_on="flow_id", how="left")
  
  enriched.drop(columns="flow_id", inplace=True)
  enriched["ssh_record_count"] = enriched["ssh_record_count"].fillna(0).astype(int)
  enriched.to_csv(out_path, index=False)
  print(f"Saved {out_path.name}")
  return

# Same as in pcap_analysis
def merge_and_sort_enriched():
  enriched_files = sorted(RESULTS_DIR.glob("*_enriched.csv"))

  if not enriched_files:
    print("No enriched CSVs found")
    return

  # Merge and Sort ended up using Pandas for cross compatibility
  try:
    dfs = []
    for f in enriched_files:
      try:
        dfs.append(pd.read_csv(f, low_memory=False))
      except Exception as e:
        print(f"Could not read {f.name}: {e}")

    if not dfs:
      print("No readable enriched CSVs found")
      return

    merged = pd.concat(dfs, ignore_index=True)
    merged.sort_values("bidirectional_first_seen_ms", inplace=True)

    merged_file = Path("results") / "merged_enriched_port_22.csv"
    sorted_file = Path("results") / "sorted_enriched_port_22.csv"

    merged.to_csv(merged_file, index=False)
    merged.to_csv(sorted_file, index=False)

    print(f"Merged saved to {merged_file}")
    print(f"Sorted saved to {sorted_file}")

  except Exception as e:
    print(f"Error merging CSVs: {e}")


if __name__ == "__main__":
  RESULTS_DIR.mkdir(parents=True, exist_ok=True)

  flow_csvs = [f for f in sorted(RESULTS_DIR.glob("*.csv")) if "_enriched" not in f.name]

  print(f"Found {len(flow_csvs)} flow CSVs to process\n")

  # Similsr to pcap_analysis and http_enrichment
  with ProcessPoolExecutor(max_workers=MAX_WORKERS) as executor:
    futures = {executor.submit(enrich_chunk, flow_csv): flow_csv for flow_csv in flow_csvs}

    completed = 0
    failed = []

    for future in as_completed(futures):
      completed += 1
      try:
        error = future.result()
        if error:
          failed.append(error)
      except Exception as e:
        failed.append(str(e))

      if completed % 10 == 0 or completed == len(flow_csvs):
        print(f"Progress: {completed}/{len(flow_csvs)}")

  if failed:
    print("\nFailed:")
    for error in failed:
      print(error)
  else:
    print("\nAll done.")

  merge_and_sort_enriched()
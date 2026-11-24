from nfstream import NFStreamer
from pathlib import Path
import pandas as pd
import subprocess
import shutil
from concurrent.futures import ProcessPoolExecutor, as_completed

PORTS = [22, 23, 80, 10110]
MAX_PCAP_SIZE_GB = 1
SPLIT_DIR = Path("preprocessed_pcaps")
MAX_WORKERS = 3

def get_clean_stem(file_path):
  parts = file_path.name.split(".pcap")
  stem = parts[0]
  suffix = parts[1].lstrip(".")  # "1741303167", or "" if plain .pcap (Added to handle pcap files with paths such as: "log.pcap.43235343")
  return f"{stem}_{suffix}" if suffix else stem

def split_pcap(file_path, chunk_dir):
  clean_stem = Path (get_clean_stem(file_path))

  try:
    subprocess.run([
      "tcpdump",
      "-r", str(file_path),
      "-w", str(chunk_dir / clean_stem) + ".pcap",
      "-C", str(int(MAX_PCAP_SIZE_GB * 1024)),
    ], capture_output=True, check=True)

    i = 0
    for chunk_file in sorted(chunk_dir.glob(f"{clean_stem}*.pcap*")):
      chunk_file.rename(chunk_dir / f"{clean_stem}_chunk{i:02d}.pcap")
      i += 1

    print(f"Split {file_path.name} into {i} chunks")

  except subprocess.CalledProcessError as e:
    print(f"tcpdump split failed: {e.stderr.decode()}")

  except FileNotFoundError:
    print("tcpdump not found")


def split_all_pcaps(pcap_dir):
  if SPLIT_DIR.exists():
    shutil.rmtree(SPLIT_DIR)
  SPLIT_DIR.mkdir(parents=True, exist_ok=True)

  pcap_dir = Path(pcap_dir)
  pcap_files = sorted(f for f in pcap_dir.rglob("*") if f.is_file() and ".pcap" in f.name)
  print(f"Checking {len(pcap_files)} PCAP files in case splitting is needed...\n")

  for pcap_file in pcap_files:
    clean_stem = get_clean_stem(pcap_file)
    
    size_gb = pcap_file.stat().st_size / 1024 ** 3
    print(f"{pcap_file.name} ({size_gb:.2f}GB)")

    relative_path = pcap_file.parent.relative_to(pcap_dir)
    chunk_dir = SPLIT_DIR / relative_path / clean_stem
    chunk_dir.mkdir(parents=True, exist_ok=True)

    if size_gb > MAX_PCAP_SIZE_GB:
      print("Splitting needed")
      split_pcap(pcap_file, chunk_dir)

    else:
      print("No splitting needed")
      (chunk_dir / f"{clean_stem}.pcap").symlink_to(pcap_file.resolve())

  print("\nSplitting complete")

def process_chunk(chunk_path):
  errors = []
  for port in PORTS:
    output_file = Path("results") / f"port_{port}" / f"{chunk_path.stem}.csv"

    # No recomputing if file already exists.
    if output_file.exists():
      print(f"Skipping {output_file} (already exists)")
      continue
    try:
      streamer = NFStreamer(
        source=str(chunk_path),
        bpf_filter=f"tcp port {port}",
        n_meters=0,
        statistical_analysis=True,
        accounting_mode=0, # 0: Link layer, 1: IP layer, 2: Transport layer, 3: Payload
        splt_analysis=5, # Could be useful for further reseach
      )
      streamer.to_csv(str(output_file))
      print(f"Saved to {output_file}")
    except Exception as e:
      print(f"Error {chunk_path.name} port {port}: {e}")
      errors.append(f"{chunk_path.name} port {port}: {e}")
  return errors


def process_pcap_folder(max_workers=MAX_WORKERS):

  # Create output directories for each port before spawning workers
  for port in PORTS:
    (Path("results") / f"port_{port}").mkdir(parents=True, exist_ok=True)

  chunks = sorted(SPLIT_DIR.rglob("*.pcap"))
  print(f"\nProcessing {len(chunks)} chunks across {max_workers} workers\n")

  # Use ProcessPoolExecutor to process tasks in parallel until completed
  with ProcessPoolExecutor(max_workers=max_workers) as executor:
    failed = []
    completed = 0
    # Map each chunk to a future and keep track of which chunk corresponds to which future
    futures = {executor.submit(process_chunk, chunk): chunk for chunk in chunks}

    for future in as_completed(futures):
      completed += 1
      chunk = futures[future]
      try:
        # Append error messages if any were returned by process_chunk
        errors = future.result()
        if errors:
          failed.append((chunk, errors))
      except Exception as e:
        # Catch any exceptions that occurred during processing for this chunk by the worker
        print(f"Worker exception in {chunk.name}: {e}")
        failed.append((chunk, [str(e)]))

      if completed % 10 == 0 or completed == len(chunks):
        print(f"\nProgress: {completed}/{len(chunks)} completed tasks\n")

  if failed:
    print(f"List of Failed chunks:")
    for chunk, errors in failed:
      print(f"{chunk.name}: {errors}")
  else:
    print("\nAll chunks processed successfully.")


def merge_and_sort_csvs(port): 
  csv_files = [f for f in (Path("results") / f"port_{port}").glob("*.csv") if "_enriched" not in f.name]

  if not csv_files:
    print(f"No CSVs found for port {port}")
    return

  merged_file = Path("results") / f"merged_csv_port_{port}.csv"
  sorted_file = Path("results") / f"sorted_csv_port_{port}.csv"
  
  # Merge and Sort ended up using Pandas for cross compatibility
  try:
    dfs = []
    for f in csv_files:
      try:
        dfs.append(pd.read_csv(f))
      except Exception as e:
        print(f"Could not read {f.name}: {e}")

    if not dfs:
      print(f"No readable CSVs found for port {port}")
      return

    merged = pd.concat(dfs, ignore_index=True)
    merged.sort_values("bidirectional_first_seen_ms", inplace=True)
    merged.to_csv(merged_file, index=False)
    print(f"Merged CSV ({port}) saved to {merged_file} — {len(merged)} flows")
    merged.to_csv(sorted_file, index=False)
    print(f"Sorted CSV ({port}) saved to {sorted_file}")

  except Exception as e:
    print(f"Error merging CSVs for port {port}: {e}")

def merge_and_sort_all():
  print("\nMerging and sorting CSVs per port\n")
  for port in PORTS:
    merge_and_sort_csvs(port)

if __name__ == "__main__":
  Path("results").mkdir(parents=True, exist_ok=True)
  # Local Folder vs External Volume
  # split_all_pcaps("samples")
  split_all_pcaps("/Volumes/New Volume")
  process_pcap_folder()
  merge_and_sort_all()
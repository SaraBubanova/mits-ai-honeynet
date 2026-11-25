"""Step: add SSH and HTTP details to the flow CSVs using Zeek (Jesus's enrichment scripts).

Input:  <results>/pcap/results/port_22/*.csv and port_80/*.csv   (written by pcap_flows)
        <results>/pcap/preprocessed_pcaps/                       (the chunks those flows came from)
Output: <results>/pcap/results/port_<N>/*_enriched.csv
        <results>/pcap/results/sorted_enriched_port_22.csv and sorted_enriched_port_80.csv

Needs zeek installed. editcap (Wireshark) is used to repair truncated pcaps if present.
Like pcap_flows, this runs Jesus's code from inside <results>/pcap/ because his paths are relative.
"""
import os
import shutil
import sys
from concurrent.futures import ProcessPoolExecutor, as_completed

from ..config import REPO_ROOT, MissingInput

NAME = "pcap_enrich"


def _enrich_port(mod, label):
    """Same loop as the __main__ block of ssh_enrichment.py / http_enrichment.py."""
    mod.RESULTS_DIR.mkdir(parents=True, exist_ok=True)
    flow_csvs = [f for f in sorted(mod.RESULTS_DIR.glob("*.csv")) if "_enriched" not in f.name]
    print(f"\n[{label}] Found {len(flow_csvs)} flow CSVs to enrich")
    if not flow_csvs:
        return

    failed = []
    with ProcessPoolExecutor(max_workers=mod.MAX_WORKERS) as executor:
        futures = {executor.submit(mod.enrich_chunk, f): f for f in flow_csvs}
        for done, future in enumerate(as_completed(futures), 1):
            try:
                error = future.result()
                if error:
                    failed.append(error)
            except Exception as e:
                failed.append(f"{futures[future].name}: {e}")
            if done % 10 == 0 or done == len(flow_csvs):
                print(f"[{label}] Progress: {done}/{len(flow_csvs)}")

    if failed:
        print(f"[{label}] Failed:")
        for error in failed:
            print(f"  {error}")
    mod.merge_and_sort_enriched()


def run(cfg):
    work_dir = (cfg.results_dir / "pcap").resolve()
    if not (work_dir / "preprocessed_pcaps").is_dir():
        raise MissingInput(f"no flow data in {work_dir}. Run pcap_flows first.")
    if shutil.which("zeek") is None:
        raise MissingInput("zeek is not installed (brew install zeek)")
    if shutil.which("editcap") is None:
        print("note: editcap not found, truncated pcaps cannot be repaired (install Wireshark)")

    sys.path.insert(0, str(REPO_ROOT / "pcap"))
    import http_enrichment
    import ssh_enrichment

    old_cwd = os.getcwd()
    os.chdir(work_dir)
    try:
        _enrich_port(ssh_enrichment, "ssh, port 22")
        _enrich_port(http_enrichment, "http, port 80")
    finally:
        os.chdir(old_cwd)

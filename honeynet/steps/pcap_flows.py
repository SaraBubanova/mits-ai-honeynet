"""Step: turn the per-day pcaps into network-flow CSVs (Jesus's pcap_analysis.py).

Input:  <results>/pcaps_by_day/*.pcap   (written by pcap_split)
Output: <results>/pcap/results/port_<N>/*.csv         one CSV per chunk and port
        <results>/pcap/results/sorted_csv_port_<N>.csv   everything merged, per port

Jesus's functions use relative paths ("results", "preprocessed_pcaps"), so this step
runs them from inside <results>/pcap/. His worker processes inherit that folder.
"""
import os
import shutil
import sys

from ..config import REPO_ROOT, MissingInput

NAME = "pcap_flows"


def run(cfg):
    day_dir = (cfg.results_dir / "pcaps_by_day").resolve()
    if not day_dir.is_dir() or not any(day_dir.glob("*.pcap")):
        raise MissingInput(f"no day files in {day_dir}. Run pcap_split first.")
    if shutil.which("tcpdump") is None:
        raise MissingInput("tcpdump is not installed (only needed for day files over 1 GB)")

    work_dir = (cfg.results_dir / "pcap").resolve()
    work_dir.mkdir(parents=True, exist_ok=True)

    sys.path.insert(0, str(REPO_ROOT / "pcap"))
    import pcap_analysis as pa

    old_cwd = os.getcwd()
    os.chdir(work_dir)
    try:
        pa.split_all_pcaps(day_dir)   # cuts day files over 1 GB into chunks
        pa.process_pcap_folder()      # NFStream, ports 22/23/80/10110
        pa.merge_and_sort_all()       # one sorted CSV per port
    finally:
        os.chdir(old_cwd)

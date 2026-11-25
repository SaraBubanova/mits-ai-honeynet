"""Step: split the raw PCAP captures into one file per calendar day (UTC).

Input:  --pcap-dir
Output: <results>/pcaps_by_day/YYYY-MM-DD.pcap   (rebuilt on every run)
"""
import shutil
import sys

from ..config import REPO_ROOT

NAME = "pcap_split"


def run(cfg):
    pcap_dir = cfg.require("pcap_dir", "--pcap-dir")

    # The splitter lives next to Jesus's scripts in pcap/, which is not a package.
    sys.path.insert(0, str(REPO_ROOT / "pcap"))
    from pcap_splitter_script.split_pcaps_by_day import split_by_day

    out_dir = cfg.results_dir / "pcaps_by_day"
    if out_dir.exists():
        shutil.rmtree(out_dir)
    split_by_day([str(pcap_dir)], str(out_dir))

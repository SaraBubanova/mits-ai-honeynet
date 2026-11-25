"""Terminal commands.

    python -m honeynet run suricata      one source, all its steps
    python -m honeynet run all           everything, then summary and report
    python -m honeynet step <name>       one step only, for debugging

Input folders are given as options, e.g.
    python -m honeynet run all --pcap-dir /Volumes/Drive --cowrie-dir logs/cowrie --suricata-dir logs/eve

A step is a module in honeynet/steps/ with a run(cfg) function. A step is skipped
with a warning if it has no run() yet, raises NotImplementedError, or needs an input
folder that was not given. Any other error stops the run.
"""
import argparse
import importlib
import logging
import sys
from pathlib import Path

from .config import DEFAULT_RESULTS_DIR, MissingInput, RunConfig

log = logging.getLogger("honeynet")

# Order matters: later steps read what earlier ones wrote.
SOURCES = {
    "suricata": ["suricata_verdict"],
    "cowrie": ["cowrie_classifier", "cowrie_verdict"],
    "pcap": ["pcap_split", "pcap_verdict"],
}
AFTER_SOURCES = ["summary", "visualiser", "pdf"]
ALL_STEPS = [s for steps in SOURCES.values() for s in steps] + AFTER_SOURCES


def run_step(name, cfg):
    """Run one step. Returns 'ran' or 'skipped'."""
    module = importlib.import_module(f"honeynet.steps.{name}")
    run = getattr(module, "run", None)
    if run is None:
        log.warning("SKIPPED %s: not implemented yet", name)
        return "skipped"
    try:
        run(cfg)
    except NotImplementedError:
        log.warning("SKIPPED %s: not implemented yet", name)
        return "skipped"
    except MissingInput as e:
        log.warning("SKIPPED %s: %s", name, e)
        return "skipped"
    return "ran"


def run_steps(names, cfg):
    results = {}
    for i, name in enumerate(names, 1):
        log.info("=== [%d/%d] %s ===", i, len(names), name)
        try:
            results[name] = run_step(name, cfg)
        except Exception:
            log.exception("FAILED %s, stopping", name)
            return results, False
    ran = [n for n, r in results.items() if r == "ran"]
    skipped = [n for n, r in results.items() if r == "skipped"]
    log.info("Done: %d ran, %d skipped%s", len(ran), len(skipped),
             f" ({', '.join(skipped)})" if skipped else "")
    return results, True


def main(argv=None):
    logging.basicConfig(level=logging.INFO, format="%(levelname)s: %(message)s", stream=sys.stdout)
    ap = argparse.ArgumentParser(prog="honeynet")
    inputs = argparse.ArgumentParser(add_help=False)
    inputs.add_argument("--pcap-dir", type=Path, help="folder with raw .pcap captures")
    inputs.add_argument("--cowrie-dir", type=Path, help="folder with cowrie*.json* logs")
    inputs.add_argument("--suricata-dir", type=Path, help="folder with eve*.json* logs")
    inputs.add_argument("--results-dir", type=Path, default=DEFAULT_RESULTS_DIR, help="where outputs are written")
    sub = ap.add_subparsers(dest="command", required=True)
    p_run = sub.add_parser("run", parents=[inputs], help="run a source's steps, or everything")
    p_run.add_argument("target", choices=[*SOURCES, "all"])
    p_step = sub.add_parser("step", parents=[inputs], help="run one step")
    p_step.add_argument("name", choices=ALL_STEPS)
    args = ap.parse_args(argv)

    if args.command == "step":
        names = [args.name]
    elif args.target == "all":
        names = ALL_STEPS
    else:
        names = SOURCES[args.target]

    cfg = RunConfig(pcap_dir=args.pcap_dir, cowrie_dir=args.cowrie_dir,
                    suricata_dir=args.suricata_dir, results_dir=args.results_dir)
    _, ok = run_steps(names, cfg)
    sys.exit(0 if ok else 1)

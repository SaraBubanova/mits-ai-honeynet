"""Settings shared by all steps: where inputs come from and where results go."""
from dataclasses import dataclass
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
DEFAULT_RESULTS_DIR = Path(__file__).resolve().parent / "results"  # git-ignored by the */results rule


class MissingInput(Exception):
    """A step needs an input the user did not give. The step is skipped with a warning."""


@dataclass
class RunConfig:
    pcap_dir: Path | None = None       # folder with raw .pcap captures
    cowrie_dir: Path | None = None     # folder with cowrie*.json* logs
    suricata_dir: Path | None = None   # folder with eve*.json* logs
    results_dir: Path = DEFAULT_RESULTS_DIR

    def require(self, field, flag):
        """Return an input folder, or raise MissingInput naming the option that sets it."""
        value = getattr(self, field)
        if value is None:
            raise MissingInput(f"no folder given, set {flag}")
        if not Path(value).is_dir():
            raise MissingInput(f"{flag} folder does not exist: {value}")
        return Path(value)

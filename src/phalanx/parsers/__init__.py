from __future__ import annotations

from datetime import UTC, datetime


def _now_iso() -> str:
    """Return current UTC timestamp as ISO string."""
    return datetime.now(tz=UTC).isoformat()


from .aircrack_parser import AircrackParser  # noqa: F401, E402
from .amass_parser import AmassParser  # noqa: F401, E402
from .bettercap_parser import BettercapParser  # noqa: F401, E402
from .burpsuite_parser import BurpsuiteParser  # noqa: F401, E402
from .ettercap_parser import EttercapParser  # noqa: F401, E402
from .ffuf_parser import FfufParser  # noqa: F401, E402
from .gobuster_parser import GobusterParser  # noqa: F401, E402
from .hashcat_parser import HashcatParser  # noqa: F401, E402
from .hydra_parser import HydraParser  # noqa: F401, E402
from .impacket_parser import ImpacketParser  # noqa: F401, E402
from .john_parser import JohnParser  # noqa: F401, E402
from .masscan_parser import MasscanParser  # noqa: F401, E402
from .metasploit_parser import MetasploitParser  # noqa: F401, E402
from .nikto_parser import NiktoParser  # noqa: F401, E402
from .nmap_parser import NmapParser  # noqa: F401, E402
from .nuclei_parser import NucleiParser  # noqa: F401, E402
from .shodan_parser import ShodanParser  # noqa: F401, E402
from .sqlmap_parser import SqlmapParser  # noqa: F401, E402
from .subfinder_parser import SubfinderParser  # noqa: F401, E402
from .wpscan_parser import WpscanParser  # noqa: F401, E402
from .zaproxy_parser import ZaproxyParser  # noqa: F401, E402

__all__ = [
    "_now_iso",
    "AircrackParser",
    "AmassParser",
    "BettercapParser",
    "BurpsuiteParser",
    "EttercapParser",
    "FfufParser",
    "GobusterParser",
    "HashcatParser",
    "HydraParser",
    "ImpacketParser",
    "JohnParser",
    "MasscanParser",
    "MetasploitParser",
    "NiktoParser",
    "NmapParser",
    "NucleiParser",
    "ShodanParser",
    "SqlmapParser",
    "SubfinderParser",
    "WpscanParser",
    "ZaproxyParser",
]

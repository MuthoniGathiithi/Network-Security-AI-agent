"""
Network Security AI Agent Package

Public classes are imported lazily (PEP 562), so `import src` or importing
one submodule doesn't pull in scapy, scikit-learn and every other module.
"""

import importlib
from typing import TYPE_CHECKING, Any

__version__ = "1.0.0"
__author__ = "Muthoni Gathiithi"
__license__ = "MIT"

# Public name -> submodule that defines it
_LAZY_EXPORTS = {
    "SOCAgent": "src.orchestrator",
    "DetectionAgent": "src.detection_agent",
    "FlowFeatures": "src.detection_agent",
    "ResponseAgent": "src.response_agent",
    "PacketCapture": "src.packet_capture",
    "PcapReadError": "src.packet_capture",
    "ThreatLevel": "src.threat",
}

__all__ = list(_LAZY_EXPORTS)

if TYPE_CHECKING:
    from src.orchestrator import SOCAgent
    from src.detection_agent import DetectionAgent, FlowFeatures
    from src.response_agent import ResponseAgent
    from src.packet_capture import PacketCapture, PcapReadError
    from src.threat import ThreatLevel


def __getattr__(name: str) -> Any:
    module_name = _LAZY_EXPORTS.get(name)
    if module_name is None:
        raise AttributeError(f"module {__name__!r} has no attribute {name!r}")
    value = getattr(importlib.import_module(module_name), name)
    globals()[name] = value  # cache so later lookups skip __getattr__
    return value


def __dir__():
    return sorted(list(globals()) + __all__)

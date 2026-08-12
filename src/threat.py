"""
Shared threat severity levels.

Kept in its own lightweight module so every component (detection, response,
API, dashboard) can use it without importing ML or packet libraries.
"""

import logging
from enum import Enum
from typing import Any

logger = logging.getLogger(__name__)


class ThreatLevel(str, Enum):
    """
    Severity of a detection, ordered LOW < MEDIUM < HIGH < CRITICAL.

    Subclasses str, so members compare equal to their names
    (ThreatLevel.HIGH == "HIGH") and serialize to JSON as plain strings.
    """

    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"

    @property
    def rank(self) -> int:
        """Numeric severity: LOW=0 ... CRITICAL=3."""
        return _ORDER.index(self)

    @property
    def color(self) -> str:
        """Hex color for alerts and dashboards."""
        return _COLORS[self]

    @classmethod
    def parse(cls, value: Any, default: "ThreatLevel" = None) -> "ThreatLevel":
        """
        Convert a string (any case) or ThreatLevel to a ThreatLevel.

        Args:
            value: Value to convert, e.g. "critical" or ThreatLevel.HIGH
            default: Returned for missing or unknown values; if None,
                unknown values raise instead

        Returns:
            The matching ThreatLevel

        Raises:
            ValueError: If the value is unknown and no default is given
        """
        if isinstance(value, cls):
            return value
        try:
            return cls(str(value).strip().upper())
        except ValueError:
            if default is None:
                raise ValueError(
                    f"Unknown threat level {value!r}; expected one of "
                    f"{[level.value for level in cls]}"
                ) from None
            if value is not None:
                logger.warning(f"Unknown threat level {value!r}; using {default.value}")
            return default

    def __str__(self) -> str:
        # Plain "HIGH" in f-strings and logs, not "ThreatLevel.HIGH"
        return self.value

    # str comparison would order alphabetically (CRITICAL < HIGH < LOW),
    # so compare by severity instead
    def __lt__(self, other: Any) -> bool:
        return self.rank < ThreatLevel.parse(other).rank

    def __le__(self, other: Any) -> bool:
        return self.rank <= ThreatLevel.parse(other).rank

    def __gt__(self, other: Any) -> bool:
        return self.rank > ThreatLevel.parse(other).rank

    def __ge__(self, other: Any) -> bool:
        return self.rank >= ThreatLevel.parse(other).rank

    # Defining comparison methods resets __hash__; keep str hashing so
    # members still work as dict keys alongside their string names
    __hash__ = str.__hash__


_ORDER = [ThreatLevel.LOW, ThreatLevel.MEDIUM, ThreatLevel.HIGH, ThreatLevel.CRITICAL]

_COLORS = {
    ThreatLevel.LOW: "#36a64f",
    ThreatLevel.MEDIUM: "#ff9900",
    ThreatLevel.HIGH: "#ff6600",
    ThreatLevel.CRITICAL: "#cc0000",
}

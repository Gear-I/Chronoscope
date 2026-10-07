"""Parser discovery: built-in parsers plus the ``chronoscope.parsers`` entry-point group."""

from __future__ import annotations

from dataclasses import dataclass, field
from importlib.metadata import entry_points

from chronoscope.parsers.base import ParseContext, Parser
from chronoscope.parsers.bodyfile import BodyfileParser
from chronoscope.parsers.browsers import ChromiumHistoryParser, FirefoxHistoryParser
from chronoscope.parsers.evtx import EvtxParser
from chronoscope.parsers.filesystem import FilesystemParser

__all__ = ["ParseContext", "Parser", "Registry", "discover", "ENTRY_POINT_GROUP"]

ENTRY_POINT_GROUP = "chronoscope.parsers"
BUILTIN: tuple[type[Parser], ...] = (
    FilesystemParser,
    BodyfileParser,
    ChromiumHistoryParser,
    FirefoxHistoryParser,
    EvtxParser,
)


@dataclass
class Registry:
    parsers: dict[str, Parser] = field(default_factory=dict)
    unavailable: dict[str, str] = field(default_factory=dict)
    origins: dict[str, str] = field(default_factory=dict)

    def register(self, cls: type[Parser], origin: str) -> None:
        name = getattr(cls, "name", None)
        if not name:
            self.unavailable[f"<{origin}>"] = "parser class has no name"
            return
        if name in self.parsers or name in self.unavailable:
            self.unavailable[f"{name} ({origin})"] = "name already registered; ignored"
            return
        reason = cls.unavailable_reason()
        if reason:
            self.unavailable[name] = reason
        else:
            self.parsers[name] = cls()
        self.origins[name] = origin


def discover(include_plugins: bool = True) -> Registry:
    registry = Registry()
    for cls in BUILTIN:
        registry.register(cls, "builtin")
    if include_plugins:
        for ep in entry_points(group=ENTRY_POINT_GROUP):
            try:
                cls = ep.load()
            except Exception as exc:
                registry.unavailable[ep.name] = f"failed to load {ep.value}: {exc}"
                continue
            if not (isinstance(cls, type) and issubclass(cls, Parser)):
                registry.unavailable[ep.name] = f"{ep.value} is not a Parser subclass"
                continue
            registry.register(cls, ep.value)
    return registry

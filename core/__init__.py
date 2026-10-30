__all__ = ["NemesisScanner", "Reporter", "VERSION", "RecentTargetStore"]


def __getattr__(name):
	if name == "Reporter":
		from .reporting import Reporter
		return Reporter
	if name == "RecentTargetStore":
		from .history import RecentTargetStore
		return RecentTargetStore
	if name in {"NemesisScanner", "VERSION"}:
		from .core import NemesisScanner, VERSION
		return {"NemesisScanner": NemesisScanner, "VERSION": VERSION}[name]
	raise AttributeError(f"module {__name__!r} has no attribute {name!r}")
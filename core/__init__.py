__all__ = ["NemesisScanner", "Reporter", "VERSION"]


def __getattr__(name):
	if name == "Reporter":
		from .reporting import Reporter

		return Reporter
	if name in {"NemesisScanner", "VERSION"}:
		from .core import NemesisScanner, VERSION

		return {"NemesisScanner": NemesisScanner, "VERSION": VERSION}[name]
	raise AttributeError(f"module {__name__!r} has no attribute {name!r}")
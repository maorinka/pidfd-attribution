"""Compatibility import for the import-safe, parameterized fixture verifier."""
if __name__ == "__main__":
    raise SystemExit("Support library only; use the backend's ./run.sh commands")

from .collector_records import (Event, Frame, Source, WireActor, WireHeader,
                                WorkloadVerifier, callee, events, stack, text_events)

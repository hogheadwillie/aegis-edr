"""Agent orchestration: runs monitors, feeds the engine, dispatches alerts."""

from __future__ import annotations

import socket
import time
from pathlib import Path
from typing import Iterable, List, Optional, Set

from .alerts import Alert, AlertSink
from .detection.engine import DetectionEngine
from .monitors import fim, network, process
from .response.actions import Responder


class Agent:
    """The host agent. One-shot scans or a continuous watch loop."""

    def __init__(self, engine: DetectionEngine, sink: AlertSink,
                 responder: Optional[Responder] = None) -> None:
        self.engine = engine
        self.sink = sink
        self.responder = responder
        self._rules_by_id = {r.id: r for r in engine.rules}
        self._seen: Set[str] = set()  # dedup within a watch session

    # -- one-shot scans ----------------------------------------------------

    def scan_processes(self) -> List[Alert]:
        return self._dispatch(self.engine.evaluate_all(process.iter_process_events()))

    def scan_network(self) -> List[Alert]:
        return self._dispatch(self.engine.evaluate_all(network.iter_network_events()))

    def scan_files(self, root: Path | str, baseline_path: Path | str) -> List[Alert]:
        baseline = fim.load_baseline(baseline_path)
        events = fim.diff_baseline(baseline, root)
        return self._dispatch(self.engine.evaluate_all(events))

    def full_scan(self) -> List[Alert]:
        return self.scan_processes() + self.scan_network()

    # -- continuous watch ---------------------------------------------------

    def watch(self, interval: float = 5.0, cycles: Optional[int] = None) -> None:
        """Poll process + network sensors until interrupted (or `cycles` times)."""
        n = 0
        try:
            while cycles is None or n < cycles:
                self.scan_processes()
                self.scan_network()
                n += 1
                time.sleep(interval)
        except KeyboardInterrupt:
            pass

    # -- internals ----------------------------------------------------------

    def _dispatch(self, alerts: Iterable[Alert]) -> List[Alert]:
        fresh: List[Alert] = []
        for alert in alerts:
            key = alert.dedup_key()
            if key in self._seen:
                continue
            self._seen.add(key)
            self.sink.emit(alert)
            if self.responder is not None:
                # Containment runs after the alert is safely logged.
                self.responder.handle_alert(alert, self._rules_by_id)
            fresh.append(alert)
        return fresh


def hostname() -> str:
    return socket.gethostname()

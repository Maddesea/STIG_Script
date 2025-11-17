"""Global state management and shutdown coordination."""

from __future__ import annotations
from typing import Optional, List, Callable
from pathlib import Path
from contextlib import suppress
import threading
import signal
import atexit
import sys
import gc


class GlobalState:
    """
    Process-wide shutdown coordinator and resource manager (Singleton).

    Responsibilities:
    - Signal handling (SIGINT, SIGTERM) for graceful shutdown
    - Temporary file tracking and cleanup
    - Registration of cleanup callbacks
    - Thread-safe shutdown coordination

    Usage:
        GLOBAL = GlobalState()  # First call creates instance
        GLOBAL.add_temp(tmp_file)  # Track for cleanup
        GLOBAL.add_cleanup(lambda: close_connection())  # Register callback

    Cleanup is automatic on exit via atexit, but can be manually triggered
    with GLOBAL.cleanup(). Thread-safe via RLock.

    Thread Safety:
        All public methods are thread-safe via internal RLock. Safe to call
        from multiple threads or signal handlers.
    """

    _instance: Optional["GlobalState"] = None
    _lock = threading.RLock()

    def __new__(cls) -> "GlobalState":
        if cls._instance is None:
            with cls._lock:
                if cls._instance is None:
                    cls._instance = super().__new__(cls)
                    cls._instance._init()
        return cls._instance

    def _init(self) -> None:
        self.shutdown = threading.Event()
        self.temps: List[Path] = []
        self.cleanups: List[Callable[[], None]] = []
        atexit.register(self.cleanup)
        self._setup_signals()

    def _setup_signals(self) -> None:
        def handler(sig, frame):
            print(f"\n[SIGNAL {sig}] Shutting down gracefully...", file=sys.stderr)
            self.shutdown.set()
            self.cleanup()
            sys.exit(0)

        for sig in (signal.SIGINT, signal.SIGTERM):
            with suppress(Exception):
                signal.signal(sig, handler)

    def add_temp(self, path: Path) -> None:
        with self._lock:
            self.temps.append(path)

    def add_cleanup(self, func: Callable[[], None]) -> None:
        """Add a cleanup function to be called on shutdown."""
        with self._lock:
            self.cleanups.append(func)

    def cleanup(self) -> None:
        with self._lock:
            if self.shutdown.is_set():
                return
            self.shutdown.set()

            for func in reversed(self.cleanups):
                with suppress(Exception):
                    func()

            for temp in self.temps:
                with suppress(Exception):
                    if temp and temp.exists():
                        temp.unlink()

            self.temps.clear()
            self.cleanups.clear()
            gc.collect()


# Module-level singleton instance
GLOBAL_STATE = GlobalState()

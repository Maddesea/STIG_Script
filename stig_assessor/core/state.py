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
    _singleton_lock = threading.RLock()

    def __new__(cls, *args, **kwargs):
        with cls._singleton_lock:
            if cls._instance is None:
                cls._instance = super().__new__(cls)
                cls._instance._initialized = False
            return cls._instance

    def __init__(self, register_signals: bool = True) -> None:
        if getattr(self, "_initialized", False):
            return
        self._lock = threading.RLock()
        self.shutdown = threading.Event()
        self.temps: List[Path] = []
        self.cleanups: List[Callable[[], None]] = []
        if register_signals:
            atexit.register(self.cleanup)
            self._setup_signals()
        self._initialized = True

    def __enter__(self) -> "GlobalState":
        return self

    def __exit__(self, exc_type, exc_val, exc_tb) -> None:
        self.cleanup()

    def _setup_signals(self) -> None:
        """Register application signal handlers for graceful shutdown operations."""

        def handler(sig, frame):
            print(f"\n[SIGNAL {sig}] Shutting down gracefully...", file=sys.stderr)
            self.shutdown.set()
            self.cleanup()
            sys.exit(0)

        for sig in (signal.SIGINT, signal.SIGTERM):
            with suppress(OSError, ValueError):
                signal.signal(sig, handler)

    def add_temp(self, path: Path) -> None:
        """Register a temporary path for automated deletion during system exit."""
        with self._lock:
            self.temps.append(path)

    def add_cleanup(self, func: Callable[[], None]) -> None:
        """Add a cleanup function to be called on shutdown."""
        with self._lock:
            self.cleanups.append(func)

    def cleanup(self) -> None:
        """Execute all registered cleanup callbacks and remove temporary files."""
        with self._lock:
            if getattr(self, "_is_cleaning", False):
                return
            self._is_cleaning = True

            try:
                for func in reversed(self.cleanups):
                    with suppress(Exception):
                        # User callbacks are unpredictable — keep broad catch
                        func()

                for temp in self.temps:
                    with suppress(OSError):
                        if temp and temp.exists():
                            temp.unlink()

                self.temps.clear()
                self.cleanups.clear()
                gc.collect()
            finally:
                self._is_cleaning = False

    def remove_temp(self, path: Path) -> None:
        """Remove a specific path from the tracked temporaries list."""
        with self._lock:
            try:
                self.temps.remove(path)
            except ValueError:
                pass


# Module-level singleton
GLOBAL_STATE = GlobalState(register_signals=False)

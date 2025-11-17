"""Tests for GlobalState singleton."""

import unittest
from pathlib import Path
import tempfile
from stig_assessor.core.state import GlobalState


class TestGlobalState(unittest.TestCase):
    """Test GlobalState singleton."""

    def test_singleton(self):
        """Verify singleton behavior."""
        state1 = GlobalState()
        state2 = GlobalState()
        self.assertIs(state1, state2)

    def test_temp_tracking(self):
        """Test temporary file tracking."""
        state = GlobalState()
        # Create a temporary file
        tmp = Path(tempfile.mktemp())
        tmp.touch()

        # Add to tracking
        state.add_temp(tmp)
        self.assertIn(tmp, state.temps)

        # Cleanup
        tmp.unlink()

    def test_cleanup_callback(self):
        """Test cleanup callback registration."""
        state = GlobalState()
        called = []

        def callback():
            called.append(True)

        state.add_cleanup(callback)
        self.assertIn(callback, state.cleanups)


if __name__ == "__main__":
    unittest.main()

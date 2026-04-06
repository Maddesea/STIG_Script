"""Unit tests for the CLI logic."""

import unittest
import sys
from unittest.mock import patch

import stig_assessor.ui.cli as cli

class TestCLI(unittest.TestCase):
    
    @patch('stig_assessor.ui.cli.LOG')
    def test_cli_no_args(self, mock_log):
        with patch.object(sys, 'argv', ['stig_assessor']):
            code = cli.main()
            self.assertEqual(code, 0)
    
    def test_cli_show_drift_no_db(self):
        # Gracefully handle show drift with unset db
        with patch.object(sys, 'argv', ['stig_assessor', '--show-drift', 'TEST-SERVER-01']):
            code = cli.main()
            self.assertEqual(code, 1)

if __name__ == "__main__":
    unittest.main()

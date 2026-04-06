from stig_assessor.ui.cli import main as cli_main
import tempfile
from pathlib import Path

MINIMAL_XCCDF = """<?xml version="1.0" encoding="UTF-8"?>
<Benchmark xmlns="http://checklists.nist.gov/xccdf/1.2" id="TEST_STIG">
    <title>E2E STIG</title>
    <version>1</version>
    <Group id="V-999999">
        <title>Test Vuln</title>
        <Rule id="SV-999999r1_rule" severity="medium">
            <version>TEST-001</version>
            <title>Test Rule Title</title>
        </Rule>
    </Group>
</Benchmark>"""

test_dir = Path(tempfile.mkdtemp())
xccdf_path = test_dir / "test_benchmark.xml"
xccdf_path.write_text(MINIMAL_XCCDF, encoding="utf-8")

args = ["--create", "--xccdf", str(xccdf_path), "--asset", "SMART_TEST"]
print("Calling cli_main...")
cli_main(args)
print("Success!")

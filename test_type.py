from stig_assessor.io.file_ops import FO
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

p = Path(tempfile.gettempdir()) / 'test.xml'
p.write_text(MINIMAL_XCCDF)
tree = FO.parse_xml(str(p))
print(type(tree))
print(type(tree).__name__)

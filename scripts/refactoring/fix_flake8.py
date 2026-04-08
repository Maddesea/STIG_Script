import re


def replace_in_file(path, old, new):
    with open(path, "r") as f:
        content = f.read()
    with open(path, "w") as f:
        f.write(content.replace(old, new))


# history/__init__.py
replace_in_file(
    "stig_assessor/history/__init__.py",
    'from .models import Hist\nfrom .manager import HistMgr\n\n__all__ = ["Hist", "HistMgr"]\n\nfrom .models import Hist\nfrom .manager import HistMgr',
    'from .models import Hist\nfrom .manager import HistMgr\n\n__all__ = ["Hist", "HistMgr"]',
)

# history/manager.py
replace_in_file(
    "stig_assessor/history/manager.py", "from contextlib import suppress\n", ""
)
replace_in_file("stig_assessor/history/models.py", "from typing import Union\n", "")

# processor/processor.py
# Remove unused imports
with open("stig_assessor/processor/processor.py", "r") as f:
    text = f.read()
for imp in ["collections", "copy", "json", "os", "re", "shutil", "tempfile", "time"]:
    text = re.sub(f"^import {imp}\n", "", text, flags=re.MULTILINE)
text = re.sub(
    r"from datetime import datetime\n.*from datetime import datetime",
    "from datetime import datetime",
    text,
    flags=re.DOTALL,
)
text = re.sub(
    r"import xml.etree.ElementTree as ET\n.*import xml.etree.ElementTree as ET",
    "import xml.etree.ElementTree as ET",
    text,
    flags=re.DOTALL,
)
text = text.replace('f"No history entries added"', '"No history entries added"')
with open("stig_assessor/processor/processor.py", "w") as f:
    f.write(text)

# remediation/extractor.py
replace_in_file(
    "stig_assessor/remediation/extractor.py",
    "        from stig_assessor.exceptions import ParseError\n        raise ParseError",
    "        raise ParseError",
)
with open("stig_assessor/remediation/extractor.py", "r") as f:
    text = f.read()
if "from stig_assessor.exceptions import ParseError" not in text:
    text = text.replace(
        "from stig_assessor.exceptions import ValidationError",
        "from stig_assessor.exceptions import ValidationError, ParseError",
    )
text = text.replace('f"Found {len(match)} command blocks"', '"Found command blocks"')
with open("stig_assessor/remediation/extractor.py", "w") as f:
    f.write(text)

# validation/validator.py
with open("stig_assessor/validation/validator.py", "r") as f:
    text = f.read()
if "from stig_assessor.exceptions import ParseError" not in text:
    text = text.replace(
        "from stig_assessor.exceptions import ValidationError",
        "from stig_assessor.exceptions import ValidationError, ParseError",
    )
with open("stig_assessor/validation/validator.py", "w") as f:
    f.write(text)

# ui/cli.py
replace_in_file(
    "stig_assessor/ui/cli.py", 'f"STIG Assessor CLI ("', '"STIG Assessor CLI ("'
)
replace_in_file(
    "stig_assessor/ui/cli.py",
    'f"  No actionable fixes extracted."',
    '"  No actionable fixes extracted."',
)

# ui/gui.py
with open("stig_assessor/ui/gui.py", "r") as f:
    text = f.read()
text = re.sub(r"fixes = \[\].*?fixes\.append\(fix\)", "pass", text, flags=re.DOTALL)
with open("stig_assessor/ui/gui.py", "w") as f:
    f.write(text)

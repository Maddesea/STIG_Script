import re
from pathlib import Path

# Fix wizard.py
p = Path('stig_assessor/ui/wizard.py')
text = p.read_text(encoding='utf-8')
text = text.replace('f"  Note: Evidence logs will be mapped to \'evidence/\' directory when scripts run."', '"  Note: Evidence logs will be mapped to \'evidence/\' directory when scripts run."')
text = text.replace('f"Report generated successfully."', '"Report generated successfully."')
p.write_text(text, encoding='utf-8')

# Fix tabs/extract.py
p = Path('stig_assessor/ui/gui/tabs/extract.py')
text = p.read_text(encoding='utf-8')
text = re.sub(r'stats = extractor\.stats_summary\(\)\n\s*', '', text)
text = re.sub(r'plat_parts = \[\]\n\s*if \"windows\" in platforms:.*\n\s*plat_parts\.append\(\"Windows\"\)\n\s*if \"linux\" in platforms:.*\n\s*plat_parts\.append\(\"Linux\"\)\n\s*', '', text)
text = text.replace('f"Playbooks Exported"', '"Playbooks Exported"')
p.write_text(text, encoding='utf-8')

# Fix tabs/analytics.py
p = Path('stig_assessor/ui/gui/tabs/analytics.py')
text = p.read_text(encoding='utf-8')
text = text.replace('f"No checklist data available"', '"No checklist data available"')
p.write_text(text, encoding='utf-8')

# Fix tabs/editor.py
p = Path('stig_assessor/ui/gui/tabs/editor.py')
text = p.read_text(encoding='utf-8')
text = re.sub(r'\s*wildcard = list\([^\)]+\)\s*\n', '\n', text)
p.write_text(text, encoding='utf-8')

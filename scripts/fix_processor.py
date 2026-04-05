import re

with open("stig_assessor/processor/processor.py", "r") as f:
    text = f.read()

# Replace Path validation exception
text = re.sub(
    r"except Exception as exc:\s*raise ValidationError\(f\"Path validation failed:(.*?)\"\) from exc",
    r"except (ValidationError, OSError, ValueError, TypeError) as exc:\n            raise ValidationError(f\"Path validation failed:\g<1>\") from exc",
    text
)

# Replace parse exceptions
text = re.sub(
    r"except Exception as exc:\s*raise ParseError\(f\"Failed to parse(.*?)\"\) from exc",
    r"except (ParseError, OSError, ValueError) as exc:\n            raise ParseError(f\"Failed to parse\g<1>\") from exc",
    text
)

# Replace "Could not parse" exceptions in _ingest_history
text = re.sub(
    r"except Exception as exc:\s*LOG\.w\(f\"Unexpected error parsing history from(.*?)\"\)\s*return",
    r"except (OSError, RuntimeError) as exc:\n            LOG.w(f\"Unexpected error parsing history from\g<1>\")\n            return",
    text
)

with open("stig_assessor/processor/processor.py", "w") as f:
    f.write(text)


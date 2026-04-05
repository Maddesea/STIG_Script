import re

with open("stig_assessor/validation/validator.py", "r") as f:
    text = f.read()

text = text.replace("except Exception as exc:\n            return False, [f\"Unable to parse XML", "except (ParseError, OSError, ValueError) as exc:\n            return False, [f\"Unable to parse XML")
text = text.replace("except Exception as exc:\n            return False, [f\"Unable to parse CKLB JSON", "except (ParseError, OSError, ValueError) as exc:\n            return False, [f\"Unable to parse CKLB JSON")
with open("stig_assessor/validation/validator.py", "w") as f:
    f.write(text)

with open("stig_assessor/templates/boilerplate.py", "r") as f:
    text = f.read()

text = text.replace("except Exception as e:\n            LOG.e(f\"Failed to load boilerplate: {e}\")", "except (OSError, ValueError, TypeError) as e:\n            LOG.e(f\"Failed to load boilerplate: {e}\")")
text = text.replace("except Exception as e:\n            raise FileError(f\"Failed to save boilerplate: {e}\")", "except (OSError, ValueError, TypeError) as e:\n            raise FileError(f\"Failed to save boilerplate: {e}\")")
with open("stig_assessor/templates/boilerplate.py", "w") as f:
    f.write(text)

with open("stig_assessor/core/__init__.py", "r") as f:
    text = f.read()

text = text.replace("except Exception as e:\n    import sys", "except (RuntimeError, OSError, ValueError) as e:\n    import sys")
with open("stig_assessor/core/__init__.py", "w") as f:
    f.write(text)

with open("stig_assessor/core/logging.py", "r") as f:
    text = f.read()

text = text.replace("except Exception as fallback_exc:", "except (TypeError, AttributeError, OSError, ValueError) as fallback_exc:")
with open("stig_assessor/core/logging.py", "w") as f:
    f.write(text)

import re
import sys

def process_file(filepath):
    with open(filepath, 'r') as f:
        content = f.read()

    # Generic replace of 'except Exception:' or 'except Exception as e:' 
    # based on context or just marking them as TODO. Actually we can do it smarter
    # but the safest is to change them to `except (Exception, OSError) as e:` which is 
    # not functionally changing much but quiets linter? No, the goal is narrowing down.
    pass

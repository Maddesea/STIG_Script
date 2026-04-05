import ast
import os

def check_file(filepath):
    with open(filepath, 'r') as f:
        try:
            tree = ast.parse(f.read(), filename=filepath)
        except SyntaxError:
            return

    for node in ast.walk(tree):
        if isinstance(node, ast.ExceptHandler):
            if node.type is None:
                print(f"{filepath}:{node.lineno} Bare except:")
            elif isinstance(node.type, ast.Name) and node.type.id == 'Exception':
                print(f"{filepath}:{node.lineno} Broad exception handling: except Exception")

for root, _, files in os.walk('stig_assessor'):
    if 'ui' in root: continue
    for f in files:
        if f.endswith('.py'):
            check_file(os.path.join(root, f))

import ast
import os


def check_file(filepath):
    with open(filepath, "r") as f:
        try:
            tree = ast.parse(f.read(), filename=filepath)
        except SyntaxError as e:
            print(f"{filepath}:{e.lineno} SyntaxError: {e.msg}")
            return

    for node in ast.walk(tree):
        if isinstance(node, ast.ExceptHandler):
            if node.type is None:
                print(f"{filepath}:{node.lineno} Bare except:")
            elif isinstance(node.type, ast.Name) and node.type.id == "Exception":
                print(
                    f"{filepath}:{node.lineno} Broad exception handling: except Exception"
                )
        elif isinstance(node, ast.Call):
            if isinstance(node.func, ast.Name):
                if node.func.id in ("eval", "exec"):
                    print(f"{filepath}:{node.lineno} Security: Use of {node.func.id}")
            elif isinstance(node.func, ast.Attribute):
                if (
                    node.func.attr == "system"
                    and isinstance(node.func.value, ast.Name)
                    and node.func.value.id == "os"
                ):
                    print(f"{filepath}:{node.lineno} Security: Use of os.system")


for root, _, files in os.walk("stig_assessor"):
    for f in files:
        if f.endswith(".py"):
            check_file(os.path.join(root, f))

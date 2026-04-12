import os


def run_cleanup():
    target = os.path.join(os.path.dirname(__file__), "ui", "gui", "core.py")

    if not os.path.exists(target):
        print(f"Error: {target} not found.")
        return

    with open(target, "r", encoding="utf-8") as f:
        lines = f.readlines()

    start_idx = -1
    end_idx = -1

    for i, line in enumerate(lines):
        if line.strip() == "def _tab_merge(self, frame):":
            start_idx = i
        if (
            line.strip()
            == "# ------------------------------------------------------------ menu actions"
        ):
            end_idx = i

    if start_idx != -1 and end_idx != -1 and start_idx < end_idx:
        new_lines = lines[:start_idx] + ["\n"] + lines[end_idx:]
        with open(target, "w", encoding="utf-8") as f:
            f.writelines(new_lines)
        print(
            f"Cleanup Successful: Removed {end_idx - start_idx} lines of legacy dead code."
        )
    else:
        print(
            "Error: Could not identify structural markers in core.py. The file may have already been cleaned or modified."
        )


if __name__ == "__main__":
    run_cleanup()

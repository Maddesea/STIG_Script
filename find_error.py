import subprocess

def check_ps(code):
    with open('test_temp.ps1', 'w', encoding='utf-8') as f:
        f.write(code)
    res = subprocess.run(['powershell', '-ExecutionPolicy', 'Bypass', '-File', 'test_temp.ps1'], capture_output=True, text=True)
    return res.returncode == 0, res.stderr

with open('test_fixes/out2.ps1', 'r', encoding='utf-8') as f:
    lines = f.readlines()

for i in range(len(lines)):
    test_code = "".join(lines[:i+1])
    # Add dummy closing braces to make it valid if it was cut off
    test_code += "\n}\n" * 10
    ok, err = check_ps(test_code)
    if "Unexpected token" in err:
        print(f"Error starts at line {i+1}: {lines[i].strip()}")
        print(err)
        break
else:
    print("No unexpected token found when adding braces?")

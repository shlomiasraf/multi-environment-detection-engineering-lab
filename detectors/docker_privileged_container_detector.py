import subprocess

result = subprocess.run(
    ["journalctl"],
    capture_output=True,
    text=True
)

logs = result.stdout.split("\n")

for line in logs:
    if "docker" in line and "run" in line and "--privileged" in line:

        print(" ALERT: Privileged container execution detected")
        print(line)


import subprocess

result = subprocess.run(
    ["journalctl"],
    capture_output=True,
    text=True
)

logs = result.stdout.split("\n")

for line in logs:

    if "docker exec" in line and "-it" in line:

        print(" ALERT: Interactive container access detected")

        parts = line.split()

        container_name = parts[-2]

        print(f"Container: {container_name}")


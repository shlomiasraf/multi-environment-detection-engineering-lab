cat attack_chain_time_detector.py 
from datetime import datetime

log_file = "/var/log/auth.log"

invalid_attempts = []
success_logins = []
sudo_events = []
user_creations = []


def parse_time(line):
    return datetime.strptime(line[:15], "%b %d %H:%M:%S")


with open(log_file, "r") as f:
    for line in f:
        line = line.strip()

        if "sudo:" in line and "grep" in line:
            continue

        if "Invalid user" in line and "sudo:" not in line:
            parts = line.split()
            ip = parts[9]
            invalid_attempts.append((parse_time(line), ip))

        elif "Accepted publickey" in line:
            parts = line.split()
            ip = parts[10]
            success_logins.append((parse_time(line), ip))

        elif "sudo:" in line:
            sudo_events.append(parse_time(line))

        elif "new user:" in line:
            user_creations.append(parse_time(line))


TIME_WINDOW = 300

alerted_ips = set()
for invalid_time, ip in invalid_attempts:

    for success_time, success_ip in success_logins:

        if ip != success_ip:
            continue

        if (success_time - invalid_time).seconds > TIME_WINDOW:
            continue

        for sudo_time in sudo_events:

            if (sudo_time - success_time).seconds > TIME_WINDOW:
                continue

            for create_time in user_creations:

                if (create_time - sudo_time).seconds > TIME_WINDOW:
                    continue
                if ip not in alerted_ips:
                    print("ALERT: Full attack chain detected")
                    print(f"Suspicious IP: {ip}")
                    alerted_ips.add(ip)

log_file = "/var/log/auth.log"

ip_counts = {}

with open(log_file, "r") as f:
    for line in f:
        if "Invalid user" in line and "sudo" not in line:
            parts = line.split()
            ip = parts[9] 

            if ip not in ip_counts:
                ip_counts[ip] = 1
            else:
                ip_counts[ip] += 1

for ip, count in ip_counts.items():
    if count >= 3:
        print(f" ALERT: {ip} has {count} failed attempts")
    else:
        print(f"{ip} has {count} attempts")

log_file = "/var/log/auth.log"

events = {
    "invalid_user": [],
    "login_success": [],
    "sudo": [],
    "new_user": []
}

with open(log_file, "r") as f:
    for line in f:
        line = line.strip()

        if "Invalid user" in line:
            events["invalid_user"].append(line)

        elif "Accepted publickey" in line:
            events["login_success"].append(line)

        elif "sudo:" in line and "grep" not in line:
            events["sudo"].append(line)

        elif "new user:" in line:
            events["new_user"].append(line)


print("invalid_user:", len(events["invalid_user"]))
print("login_success:", len(events["login_success"]))
print("sudo:", len(events["sudo"]))
print("new_user:", len(events["new_user"]))


if (
    len(events["invalid_user"]) > 0 and
    len(events["login_success"]) > 0 and
    len(events["sudo"]) > 0 and
    len(events["new_user"]) > 0
):
    print("\n ALERT: Attack chain detected!")
else:
    print("\nNo full attack chain detected.")

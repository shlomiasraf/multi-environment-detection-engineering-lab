import json

def detect_k8s_suspicious_activity(logfile):

    with open(logfile) as f:

        for line in f:

            try:
                event = json.loads(line)

                verb = event.get("verb")
                resource = event.get("objectRef", {}).get("resource")
                subresource = event.get("objectRef", {}).get("subresource")
                user = event.get("user", {}).get("username")
                user_agent = event.get("userAgent")

                if verb == "create" and resource == "pods":
                    print("ALERT: Pod creation detected")
                    print("User:", user)
                    print("UserAgent:", user_agent)
                    print()

                if subresource == "exec":
                    print("ALERT: Exec into pod detected")
                    print("User:", user)
                    print("UserAgent:", user_agent)
                    print()

            except:
                continue


detect_k8s_suspicious_activity(
    "/var/lib/rancher/k3s/audit/audit.log"
)


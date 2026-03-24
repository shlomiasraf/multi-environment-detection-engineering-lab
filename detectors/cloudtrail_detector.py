import subprocess
import json


def get_events(region):

    result = subprocess.run(
        [
            "aws",
            "cloudtrail",
            "lookup-events",
            "--max-results",
            "50",
            "--region",
            region,
        ],
        capture_output=True,
        text=True,
    )

    return json.loads(result.stdout)


regions = ["eu-central-1", "us-east-1"]


for region in regions:

    events = get_events(region)

    for event in events["Events"]:

        event_name = event["EventName"]

        if event_name == "RunInstances":
            print(f" ALERT: EC2 instance creation detected in {region}")

        if event_name == "ConsoleLogin":

            print(f" ALERT: Console login detected in {region}")

            cloudtrail_event = json.loads(event["CloudTrailEvent"])

            user_type = cloudtrail_event["userIdentity"]["type"]

            if user_type == "Root":
                print(" HIGH ALERT: Root login detected")

            mfa_used = cloudtrail_event["additionalEventData"]["MFAUsed"]

            if mfa_used == "No":
                print(" WARNING: Login without MFA detected")

        if event_name == "CreateAccessKey":
            print(f" ALERT: Access key created in {region}")

            cloudtrail_event = json.loads(event["CloudTrailEvent"])

            user_identity = cloudtrail_event["userIdentity"]["type"]

            print(f" Access key created by: {user_identity}")


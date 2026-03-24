# Multi-Environment Detection Engineering Lab

## Overview

This project demonstrates detection engineering techniques across multiple environments:

- Linux
- Docker
- Kubernetes
- AWS CloudTrail

The goal of this lab is to simulate realistic attacker behavior and implement detection logic based on security telemetry collected from different infrastructure layers.

The detectors correlate:

- authentication activity
- privilege escalation attempts
- container access
- Kubernetes actions
- cloud control-plane events

This project reflects hands-on experience with:

- Linux security logs
- Docker runtime activity
- Kubernetes audit logs
- AWS CloudTrail telemetry
- Python-based detection logic
- Attack chain correlation

---

## Detection Coverage

### Linux — SSH Attack Chain Detection

Detects a realistic attacker sequence:


Invalid login attempts
→ Successful login
→ sudo privilege escalation
→ New user creation


Files:

detectors/simple_detector.py
detectors/attack_chain_detector.py
detectors/attack_chain_time_detector.py


Telemetry source:


/var/log/auth.log


---

### Docker — Suspicious Container Activity Detection

Detects:

- interactive container shell access
- privileged container execution

Files:


detectors/docker_detector.py
detectors/docker_privileged_container_detector.py


Telemetry source:


journalctl

---

### AWS — CloudTrail Detection

Detects:

- EC2 instance creation
- Console login
- Root account access
- Login without MFA
- Access key creation

File:


detectors/cloudtrail_detector.py


Telemetry source:


AWS CloudTrail

---

### Kubernetes — Audit Log Detection

Detects:

- pod creation events
- exec access into running containers

File:


detectors/k8s_detector.py


Telemetry source:


/var/lib/rancher/k3s/audit/audit.log


---

## Sample Logs

Example telemetry datasets are included:


sample_logs/auth_sample.log
sample_logs/docker_sample.log
sample_logs/k8s_audit_sample.log
sample_logs/cloudtrail_sample.json


These allow running detectors locally without requiring cloud infrastructure.

---

## Skills Demonstrated

This lab demonstrates practical detection engineering skills:

- log parsing
- attack sequence correlation
- privilege escalation detection
- container runtime monitoring
- Kubernetes audit analysis
- cloud control-plane monitoring
- Python security automation

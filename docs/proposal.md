# Project Proposal

## Project title

Detecting Suspicious Network Activity in an Isolated Laboratory Using Suricata IDS

## Team members

- Ali MD Mehrab
- Aryan Singh
- Arsenault Isaac
- Diya Avasthi
- Frederick Dodzi Mensah

## Problem statement

Organizations face network threats such as reconnaissance, unauthorized connection attempts, high-volume traffic, malicious communication, and unauthorized access. If network activity is not continuously monitored, suspicious behavior may remain undetected until system availability, data, or services are affected.

This project will investigate how a network-based intrusion detection system can detect and document suspicious activity in a controlled laboratory network. Suricata will monitor traffic, generate alerts, collect evidence, and support evaluation using normal and authorized suspicious traffic.

## Objectives

The project will:

- Build an isolated virtual network containing a monitored server, test client, authorized testing client, and IDS sensor.
- Configure Suricata in detection mode without automatic blocking.
- Establish a baseline of normal network activity.
- Detect selected suspicious behaviors such as port scanning, repeated SSH connection attempts, and high-rate HTTP requests.
- Record source address, destination address, ports, protocol, timestamp, alert type, and severity.
- Compare network alerts with server-side logs.
- Evaluate detection rate, false-positive rate, alert-generation time, and resource usage.
- Document IDS limitations, including encrypted traffic, threshold tuning, and missed or unknown attacks.

## System environment

The laboratory will use three virtual machines connected to a private isolated network:

| Machine | Hostname | IP address | Role |
|---|---|---:|---|
| IDS sensor | ids-sensor | 192.168.56.10 | Runs Suricata and records alerts |
| Test client | test-client | 192.168.56.20 | Generates normal and authorized test traffic |
| Monitored server | lab-server | 192.168.56.30 | Runs Apache HTTP and OpenSSH services |

The project will use private virtual-network addresses. No external, public, university, or unauthorized systems will be scanned or tested.

## Detection approach

The project will use signature-based and threshold-based detection rules.

Signature-based rules will identify selected network characteristics, such as TCP connection attempts to SSH or HTTP requests to the monitored server.

Threshold-based rules will identify repeated activity within a defined time period, such as multiple TCP SYN packets during a port scan or many HTTP requests within a short interval.

The system will initially run in IDS mode so that the team can observe, record, and evaluate traffic without automatically blocking it.

## Planned experiments

The team will conduct the following controlled experiments:

1. Normal-traffic baseline using ping, HTTP requests, and permitted SSH activity.
2. Authorized local port-scan detection against the monitored server.
3. Repeated failed SSH-login observation using server authentication logs.
4. Controlled high-rate HTTP-request detection.
5. Optional dummy-file transfer observation.
6. Optional slow-scan test to examine threshold limitations.
7. Optional safe offline packet-capture replay.

All experiments will use dummy systems and private laboratory addresses.

## Evaluation

The IDS will be evaluated using:

- True positives.
- False positives.
- False negatives.
- Detection rate.
- False-positive rate.
- Alert-generation time.
- CPU and memory usage.
- Completeness of alert information.
- Correlation between network alerts and server logs.
- Ability to distinguish normal activity from suspicious activity.

## Expected outcomes

The project is expected to show that Suricata can improve visibility into network activity by identifying selected suspicious patterns and recording useful evidence for investigation.

The project will also demonstrate that IDS effectiveness depends on rule quality, sensor visibility, threshold values, and traffic characteristics. Encrypted traffic, unknown threats, slow activity, incomplete network visibility, and excessive alerts may limit detection capability.

## Ethical and safety considerations

All testing will occur inside an isolated virtual laboratory network owned and controlled by the project team. The team will not scan, attack, or monitor external networks, university systems, public addresses, or devices without explicit authorization.

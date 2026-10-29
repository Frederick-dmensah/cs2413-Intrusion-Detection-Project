# cs2413-Intrusion-Detection-Project
CS 2413 Group-Two Project: Detecting suspicious network activity using Suricata IDS in an isolated virtual laboratory.
# Java Intrusion Detection System (IDS)

## 1. Project Overview

The Java Intrusion Detection System (IDS) is a network security monitoring application designed to identify suspicious activity from recorded network traffic.

The application reads network events from CSV files, analyzes them using three detection algorithms, generates security alerts, and presents the results through a command-line interface and web dashboard.

The project is developed using Java 21 and runs on Ubuntu Linux under Windows Subsystem for Linux (WSL 2).

## 2. Project Objectives

- Detect repeated failed login attempts that may indicate brute-force attacks.
- Identify possible port-scanning activity.
- Detect unusually large network traffic events.
- Generate structured security alerts.
- Save security alerts to a CSV file.
- Display network security statistics in a web dashboard.
- Allow users to analyze different sample datasets.
- Verify detection functionality through automated tests.

## 3. Technologies Used

- **Programming language:** Java 21
- **Operating system:** Ubuntu 24.04 (WSL 2)
- **Development environment:** Visual Studio Code
- **Web server:** Java built-in HTTP server
- **Frontend:** HTML, CSS, JavaScript
- **Data format:** CSV
- **Configuration:** Java properties file

No external Java web framework is required.

## 4. Project Structure

```text
IntrusionDetection/
├── src/
│   ├── NetworkEvent.java
│   ├── TrafficReader.java
│   ├── IDSConfig.java
│   ├── SecurityAlert.java
│   ├── BruteForceDetector.java
│   ├── PortScanDetector.java
│   ├── TrafficVolumeDetector.java
│   ├── AlertLogger.java
│   ├── SecurityReport.java
│   ├── IDSAnalyzer.java
│   ├── Main.java
│   ├── IDSMenu.java
│   ├── IDSServer.java
│   └── IDSTest.java
├── data/
│   ├── network_events.csv
│   ├── normal_events.csv
│   └── realistic_events.csv
├── config/
│   └── ids.properties
├── web/
│   ├── index.html
│   ├── style.css
│   └── script.js
├── output/
│   └── security_alerts.csv
└── README.md
```

The `output/` directory also contains compiled Java class files after compilation.

## 5. Detection Algorithms

### 5.1 Brute-Force Detection

The brute-force detector identifies repeated failed login attempts associated with a source and destination IP address.

Default configuration:

- Failed login threshold: 3
- Time window: 60 seconds

An alert is generated when the configured number of failed login attempts occurs within the specified time window.

### 5.2 Port-Scan Detection

The port-scan detector identifies connections to multiple unique destination ports within a short period.

Default configuration:

- Unique destination port threshold: 4
- Time window: 60 seconds

Repeated connections to the same port do not increase the unique-port count.

### 5.3 High-Traffic Detection

The traffic-volume detector identifies individual network events with unusually large byte counts.

Default configuration:

- Byte threshold: 10,000 bytes

An alert is generated when an event meets or exceeds the configured threshold.

## 6. Configuration

Detection thresholds are stored in:

`config/ids.properties`

```properties
bruteforce.threshold=3
bruteforce.windowSeconds=60

portscan.threshold=4
portscan.windowSeconds=60

traffic.bytesThreshold=10000
```

These settings can be modified to test different detection thresholds.

## 7. Compilation and Execution

### Requirements

- Ubuntu Linux or another compatible environment
- Java Development Kit (JDK) 21
- A terminal
- A web browser for the dashboard

### Compile the project

From the project directory:

```bash
javac -d output src/*.java
```

### Run the command-line IDS

```bash
java -cp output Main data/realistic_events.csv
```

### Run the interactive menu

```bash
java -cp output IDSMenu
```

### Run automated tests

```bash
java -cp output IDSTest
```

### Start the web server

```bash
java -cp output IDSServer
```

The server uses port 8080.

Open the dashboard in a browser at the address of the running server.

For a local Ubuntu browser:

`http://127.0.0.1:8080/`

When using Windows with WSL 2, obtain the Ubuntu IP address using:

```bash
hostname -I
```

Then open:

`http://UBUNTU_IP:8080/`

Replace `UBUNTU_IP` with the actual address reported by Ubuntu.

The WSL IP address may change after restarting the environment.

## 8. Web Dashboard

The dashboard displays:

- Total network events
- Total security alerts
- High-severity alerts
- Medium-severity alerts
- Brute-force attacks
- Port scans
- High-traffic alerts
- A table of detected security alerts

Each alert contains a timestamp, severity, attack type, source IP address, destination IP address, and description.

Alerts are displayed chronologically.

### Dataset Selection

The dashboard supports three datasets:

| Dataset | Network Events | Security Alerts |
|---|---:|---:|
| Normal Traffic | 5 | 0 |
| Malicious Traffic | 9 | 3 |
| Realistic Traffic | 16 | 4 |

Changing the selected dataset updates the dashboard statistics and alert table.

### Web API Endpoints

The Java server provides:

`/api/alerts`

Returns detected security alerts in JSON format.

`/api/summary`

Returns network event counts and alert statistics in JSON format.

Both endpoints support a `dataset` query parameter with the values `normal`, `malicious`, or `realistic`.

Example:

```text
/api/summary?dataset=normal
/api/alerts?dataset=realistic
```

## 9. Security Alert Logging

The command-line application saves detected security alerts to:

`output/security_alerts.csv`

The CSV file includes:

- Timestamp
- Severity
- Attack type
- Source IP
- Destination IP
- Description

This file can be used for reviewing detected activity and preserving the results of an analysis.

## 10. Automated Testing

The project includes 12 automated tests covering:

1. Brute-force detection
2. Higher brute-force threshold
3. Port-scan detection
4. Higher port-scan threshold
5. High-traffic detection
6. Higher traffic threshold
7. Failed login attempts outside the detection window
8. Repeated destination ports
9. Out-of-order network events
10. Duplicate brute-force alert suppression
11. Traffic exactly at the configured threshold
12. Brute-force detection at the exact time boundary

### Verified Test Results

```text
========== TEST RESULTS ==========
Passed: 12
Failed: 0
==================================
```

All 12 automated tests passed during the final regression test.

The API responses and dashboard statistics were also checked using normal, malicious, and realistic traffic datasets.

## 11. System Limitations

This IDS is an educational, rule-based security monitoring prototype.

- It analyzes recorded CSV network events rather than capturing live network packets.
- It detects three predefined categories of suspicious activity.
- Its accuracy depends on the supplied event data and configured thresholds.
- Detection alerts indicate suspicious patterns; they do not independently prove that an attack occurred.
- The web server is intended for local development and demonstration, not deployment on an untrusted public network.
- The system does not automatically block network connections or attackers.

## 12. Future Improvements

Potential future enhancements include:

- Live network packet capture
- Real-time traffic monitoring
- Additional intrusion detection rules
- Historical alert storage using a database
- Charts showing security trends
- Dashboard authentication
- Alert notifications
- More comprehensive testing with larger datasets

## 13. Conclusion

The Java Intrusion Detection System demonstrates how rule-based detection can identify suspicious network activity using configurable thresholds and time windows.

The project combines Java programming, file processing, network security concepts, automated testing, CSV logging, HTTP APIs, and web development into one functional application.

The completed prototype successfully analyzes three sample datasets and presents the detection results through both command-line and browser interfaces.

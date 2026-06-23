# Log Analyzer – Suspicious Activity Detector

A Python-based cybersecurity tool that analyzes authentication and web server logs to identify suspicious behavior and potential security threats. The analyzer parses log entries, detects common attack patterns, and generates detailed alerts with supporting evidence.

## Features

* Detects brute-force login attacks
* Identifies potential port scanning activity
* Flags privilege escalation attempts
* Detects after-hours login activity
* Finds directory traversal attacks
* Monitors access to sensitive resources
* Severity-based alert classification
* JSON report export support
* Built-in demo dataset for testing

## Threats Detected

### Brute Force Attacks

Detects repeated failed login attempts from the same IP address.

### Port Scans

Identifies hosts probing multiple ports in a short period.

### Privilege Escalation

Flags commands executed with elevated privileges, especially root access.

### After-Hours Logins

Highlights successful logins occurring during unusual hours.

### Path Traversal

Detects attempts to access restricted files using traversal techniques.

### Suspicious Resource Access

Monitors requests to sensitive locations such as:

* `/admin`
* `/.env`
* `/.git`
* `/phpmyadmin`
* `/etc/passwd`

## Installation

```bash
git clone https://github.com/yourusername/log-analyzer.git
cd log-analyzer
```

## Usage

Analyze a log file:

```bash
python log_analyzer.py auth.log
```

Export results as JSON:

```bash
python log_analyzer.py auth.log --json report.json
```

Run the built-in demo:

```bash
python log_analyzer.py
```

## Example Output

```text
[1] 🔴 HIGH — Brute Force
IP: 10.0.0.5
6 failed login attempts detected

[2] 🔴 HIGH — Privilege Escalation
User: admin
Command executed as root
```

## Technologies Used

* Python 3
* Regular Expressions
* Dataclasses
* JSON Export
* Log Parsing
* Security Event Detection

## Educational Purpose

This project demonstrates practical cybersecurity concepts including log analysis, threat detection, security monitoring, attack pattern recognition, and incident investigation.

## License

MIT License

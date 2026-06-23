"""
Log Analyzer — Suspicious Activity Detector
Parses auth/web server logs and flags anomalies: brute force, port scans,
privilege escalation, and unusual access patterns.
"""

import re
import sys
import json
from collections import defaultdict
from dataclasses import dataclass, field
from datetime import datetime
from typing import List, Dict, Optional
from pathlib import Path


# ── Thresholds ────────────────────────────────────────────────────────────────

BRUTE_FORCE_THRESHOLD = 5       # failed logins from one IP within window
SCAN_THRESHOLD = 10             # distinct ports from one IP
RAPID_REQUEST_THRESHOLD = 50    # requests from one IP in < 60s window
AFTER_HOURS_START = 22          # 10 PM
AFTER_HOURS_END = 6             # 6 AM


# ── Data structures ───────────────────────────────────────────────────────────

@dataclass
class LogEntry:
    raw: str
    timestamp: Optional[datetime] = None
    ip: Optional[str] = None
    user: Optional[str] = None
    action: Optional[str] = None
    status: Optional[str] = None
    port: Optional[int] = None
    extra: str = ""


@dataclass
class Alert:
    severity: str       # HIGH / MEDIUM / LOW
    category: str
    ip: Optional[str]
    user: Optional[str]
    message: str
    evidence: List[str] = field(default_factory=list)


# ── Parsers ───────────────────────────────────────────────────────────────────

# SSH auth log:  Jan 15 03:22:11 server sshd[1234]: Failed password for root from 192.168.1.5 port 22 ssh2
SSH_PATTERN = re.compile(
    r"(\w{3}\s+\d+\s+\d+:\d+:\d+)\s+\S+\s+sshd\[\d+\]:\s+"
    r"(Failed|Accepted|Invalid)\s+\S+\s+for\s+(\S+)\s+from\s+([\d.]+)\s+port\s+(\d+)"
)

# Apache/Nginx access log:  192.168.1.5 - - [15/Jan/2024:03:22:11 +0000] "GET /admin HTTP/1.1" 200 1234
WEB_PATTERN = re.compile(
    r'([\d.]+)\s+-\s+-\s+\[(.+?)\]\s+"(\w+)\s+(\S+)\s+HTTP/[\d.]+"\s+(\d+)\s+(\d+)'
)

# sudo log:  Jan 15 03:22:11 server sudo: jvu : TTY=pts/0 ; PWD=/home/jvu ; USER=root ; COMMAND=/bin/bash
SUDO_PATTERN = re.compile(
    r"(\w{3}\s+\d+\s+\d+:\d+:\d+)\s+\S+\s+sudo:\s+(\S+)\s+:.*?USER=(\S+)\s+;\s+COMMAND=(.+)"
)


def parse_timestamp(s: str) -> Optional[datetime]:
    for fmt in ("%b %d %H:%M:%S", "%d/%b/%Y:%H:%M:%S %z"):
        try:
            return datetime.strptime(s.strip(), fmt)
        except ValueError:
            continue
    return None


def parse_line(line: str) -> Optional[LogEntry]:
    line = line.strip()
    if not line:
        return None

    m = SSH_PATTERN.search(line)
    if m:
        ts, result, user, ip, port = m.groups()
        return LogEntry(
            raw=line,
            timestamp=parse_timestamp(ts),
            ip=ip, user=user,
            action=result.lower(),
            port=int(port)
        )

    m = WEB_PATTERN.search(line)
    if m:
        ip, ts, method, path, status, _ = m.groups()
        return LogEntry(
            raw=line,
            timestamp=parse_timestamp(ts),
            ip=ip,
            action=f"{method} {path}",
            status=status,
            extra=path
        )

    m = SUDO_PATTERN.search(line)
    if m:
        ts, user, target_user, command = m.groups()
        return LogEntry(
            raw=line,
            timestamp=parse_timestamp(ts),
            user=user,
            action="sudo",
            extra=f"USER={target_user} CMD={command.strip()}"
        )

    return None


# ── Detection engines ─────────────────────────────────────────────────────────

def detect_brute_force(entries: List[LogEntry]) -> List[Alert]:
    alerts = []
    failures: Dict[str, List[LogEntry]] = defaultdict(list)

    for e in entries:
        if e.action == "failed" and e.ip:
            failures[e.ip].append(e)

    for ip, events in failures.items():
        if len(events) >= BRUTE_FORCE_THRESHOLD:
            users = list({e.user for e in events if e.user})
            alerts.append(Alert(
                severity="HIGH",
                category="Brute Force",
                ip=ip,
                user=None,
                message=f"{len(events)} failed login attempts from {ip}",
                evidence=[
                    f"Targeted users: {', '.join(users[:5])}",
                    f"First attempt: {events[0].raw[:80]}",
                    f"Last attempt:  {events[-1].raw[:80]}"
                ]
            ))
    return alerts


def detect_port_scan(entries: List[LogEntry]) -> List[Alert]:
    alerts = []
    ports_by_ip: Dict[str, set] = defaultdict(set)

    for e in entries:
        if e.ip and e.port:
            ports_by_ip[e.ip].add(e.port)

    for ip, ports in ports_by_ip.items():
        if len(ports) >= SCAN_THRESHOLD:
            alerts.append(Alert(
                severity="HIGH",
                category="Port Scan",
                ip=ip,
                user=None,
                message=f"{ip} probed {len(ports)} distinct ports",
                evidence=[f"Ports: {sorted(ports)[:15]}"]
            ))
    return alerts


def detect_after_hours(entries: List[LogEntry]) -> List[Alert]:
    alerts = []
    seen = set()

    for e in entries:
        if e.action == "accepted" and e.timestamp and e.ip:
            h = e.timestamp.hour
            if h >= AFTER_HOURS_START or h < AFTER_HOURS_END:
                key = (e.ip, e.user, e.timestamp.date() if e.timestamp else None)
                if key not in seen:
                    seen.add(key)
                    alerts.append(Alert(
                        severity="MEDIUM",
                        category="After-Hours Login",
                        ip=e.ip,
                        user=e.user,
                        message=f"Successful login at {e.timestamp.strftime('%H:%M')} from {e.ip}",
                        evidence=[e.raw[:100]]
                    ))
    return alerts


def detect_privilege_escalation(entries: List[LogEntry]) -> List[Alert]:
    alerts = []
    for e in entries:
        if e.action == "sudo" and "USER=root" in e.extra:
            cmd = e.extra.split("CMD=")[-1] if "CMD=" in e.extra else ""
            severity = "HIGH" if any(s in cmd for s in ["/bin/bash", "/bin/sh", "chmod", "visudo", "passwd"]) else "MEDIUM"
            alerts.append(Alert(
                severity=severity,
                category="Privilege Escalation",
                ip=None,
                user=e.user,
                message=f"User '{e.user}' ran command as root",
                evidence=[f"Command: {cmd[:80]}"]
            ))
    return alerts


def detect_suspicious_paths(entries: List[LogEntry]) -> List[Alert]:
    alerts = []
    bad_paths = ["/admin", "/wp-admin", "/.env", "/etc/passwd", "/.git", "/phpmyadmin", "/shell", "/cmd"]
    traversal = re.compile(r"\.\./|%2e%2e", re.IGNORECASE)

    for e in entries:
        if e.action and e.status and e.extra:
            path = e.extra.lower()
            if traversal.search(path):
                alerts.append(Alert(
                    severity="HIGH",
                    category="Path Traversal",
                    ip=e.ip, user=None,
                    message=f"Directory traversal attempt: {e.extra[:60]}",
                    evidence=[e.raw[:100]]
                ))
            elif any(bad in path for bad in bad_paths):
                alerts.append(Alert(
                    severity="MEDIUM",
                    category="Suspicious Path",
                    ip=e.ip, user=None,
                    message=f"Access to sensitive path: {e.extra[:60]}",
                    evidence=[e.raw[:100]]
                ))
    return alerts


# ── Reporter ──────────────────────────────────────────────────────────────────

SEVERITY_ICON = {"HIGH": "🔴", "MEDIUM": "🟡", "LOW": "🟢"}
SEVERITY_ORDER = {"HIGH": 0, "MEDIUM": 1, "LOW": 2}


def print_report(alerts: List[Alert], total_lines: int) -> None:
    alerts.sort(key=lambda a: SEVERITY_ORDER.get(a.severity, 3))

    high = sum(1 for a in alerts if a.severity == "HIGH")
    med  = sum(1 for a in alerts if a.severity == "MEDIUM")
    low  = sum(1 for a in alerts if a.severity == "LOW")

    print(f"\n{'='*60}")
    print(f"  LOG ANALYSIS REPORT")
    print(f"{'='*60}")
    print(f"  Lines parsed : {total_lines}")
    print(f"  Alerts found : {len(alerts)}  "
          f"(🔴 {high} HIGH  🟡 {med} MEDIUM  🟢 {low} LOW)")
    print(f"{'='*60}\n")

    if not alerts:
        print("  ✓ No suspicious activity detected.\n")
        return

    for i, a in enumerate(alerts, 1):
        icon = SEVERITY_ICON.get(a.severity, "⚪")
        print(f"  [{i}] {icon} {a.severity} — {a.category}")
        if a.ip:
            print(f"      IP   : {a.ip}")
        if a.user:
            print(f"      User : {a.user}")
        print(f"      {a.message}")
        for ev in a.evidence:
            print(f"      ↳ {ev}")
        print()


def export_json(alerts: List[Alert], path: str) -> None:
    data = [{
        "severity": a.severity,
        "category": a.category,
        "ip": a.ip,
        "user": a.user,
        "message": a.message,
        "evidence": a.evidence
    } for a in alerts]
    with open(path, "w") as f:
        json.dump(data, f, indent=2)
    print(f"  Report saved to: {path}")


# ── Main ──────────────────────────────────────────────────────────────────────

SAMPLE_LOG = """
Jan 15 03:12:01 server sshd[1001]: Failed password for root from 10.0.0.5 port 22 ssh2
Jan 15 03:12:04 server sshd[1002]: Failed password for root from 10.0.0.5 port 22 ssh2
Jan 15 03:12:07 server sshd[1003]: Failed password for admin from 10.0.0.5 port 22 ssh2
Jan 15 03:12:10 server sshd[1004]: Failed password for jvu from 10.0.0.5 port 22 ssh2
Jan 15 03:12:13 server sshd[1005]: Failed password for test from 10.0.0.5 port 22 ssh2
Jan 15 03:12:16 server sshd[1006]: Failed password for pi from 10.0.0.5 port 22 ssh2
Jan 15 23:45:01 server sshd[2001]: Accepted password for jvu from 203.0.113.42 port 22 ssh2
Jan 15 03:22:11 server sshd[2002]: Accepted password for deploy from 10.0.0.9 port 33891 ssh2
Jan 15 09:00:01 server sudo: jvu : TTY=pts/0 ; PWD=/home/jvu ; USER=root ; COMMAND=/bin/bash
Jan 15 09:01:05 server sudo: deploy : TTY=pts/1 ; PWD=/opt ; USER=root ; COMMAND=/usr/bin/apt update
10.0.0.7 - - [15/Jan/2024:14:22:01 +0000] "GET /admin HTTP/1.1" 403 512
10.0.0.7 - - [15/Jan/2024:14:22:02 +0000] "GET /.env HTTP/1.1" 404 0
10.0.0.8 - - [15/Jan/2024:14:23:01 +0000] "GET /../../etc/passwd HTTP/1.1" 400 0
Jan 15 10:00:01 server sshd[3001]: Invalid user scanner from 10.0.0.6 port 22 ssh2
Jan 15 10:00:02 server sshd[3002]: Invalid user scanner from 10.0.0.6 port 23 ssh2
Jan 15 10:00:03 server sshd[3003]: Invalid user scanner from 10.0.0.6 port 80 ssh2
Jan 15 10:00:04 server sshd[3004]: Invalid user scanner from 10.0.0.6 port 443 ssh2
Jan 15 10:00:05 server sshd[3005]: Invalid user scanner from 10.0.0.6 port 3306 ssh2
Jan 15 10:00:06 server sshd[3006]: Invalid user scanner from 10.0.0.6 port 5432 ssh2
Jan 15 10:00:07 server sshd[3007]: Invalid user scanner from 10.0.0.6 port 6379 ssh2
Jan 15 10:00:08 server sshd[3008]: Invalid user scanner from 10.0.0.6 port 27017 ssh2
Jan 15 10:00:09 server sshd[3009]: Invalid user scanner from 10.0.0.6 port 8080 ssh2
Jan 15 10:00:10 server sshd[3010]: Invalid user scanner from 10.0.0.6 port 8443 ssh2
Jan 15 10:00:11 server sshd[3011]: Invalid user scanner from 10.0.0.6 port 9200 ssh2
""".strip()


def main():
    if len(sys.argv) > 1:
        log_file = Path(sys.argv[1])
        if not log_file.exists():
            print(f"Error: file not found: {log_file}")
            sys.exit(1)
        lines = log_file.read_text().splitlines()
        print(f"  Analyzing: {log_file}")
    else:
        print("  Running demo with sample log data.")
        print("  Usage: python log_analyzer.py <logfile> [--json output.json]\n")
        lines = SAMPLE_LOG.splitlines()

    entries = [e for line in lines if (e := parse_line(line)) is not None]

    all_alerts = (
        detect_brute_force(entries) +
        detect_port_scan(entries) +
        detect_after_hours(entries) +
        detect_privilege_escalation(entries) +
        detect_suspicious_paths(entries)
    )

    print_report(all_alerts, len(lines))

    if "--json" in sys.argv:
        idx = sys.argv.index("--json")
        out = sys.argv[idx + 1] if idx + 1 < len(sys.argv) else "report.json"
        export_json(all_alerts, out)


if __name__ == "__main__":
    main()

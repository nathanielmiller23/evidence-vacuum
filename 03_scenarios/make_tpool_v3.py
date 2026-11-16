"""v3 TRAINING pool extension: T061–T300 (never used for evaluation; S2 uses different archetypes and org).

    python 03_scenarios/make_tpool_v3.py      # writes tpool/configs/T061..T300 *.yaml + *.meta.json

6 new fictional orgs x the same 10 archetypes as v2 x 4 variants = 240 scenarios.
Variety along the gap axes (the thing the reviewer must learn):
  va: consequential gap, randomized window start/end (40-60 min) and activity shift
  vb: consequential gap, a different randomized window/shift
  vc: NON-consequential gap on an unrelated host
  vd: NON-consequential gap on an unrelated sensor (decisive sensors intact)
Labels follow the same PROTOCOL §1.4 rule. Every cell is later validated by check_decisive.py
(token present in C1, absent in C2 for consequential; present in C2 for non-consequential); failing cells are excluded.
Fix vs v2: rogue_admin's consequential gap also covers the DC (account creation is logged there).
"""
import json
import random
from copy import deepcopy

import yaml

from make_tpool import OUT, context, environment, stories

ORG_SPECS = [
    # key, name, domain, netbios, day, mail, net, ext_cidr, attacker, users(4), app, vendor, share
    ("pinecrest", "Pinecrest Family Clinic", "pinecrest.local", "PINECREST", "2026-09-08", "pinecrestclinic.org", "10.51",
     "198.51.100.16/28", "203.0.113.17",
     [("ana.ruiz", "accountant"), ("tom.weber", "analyst"), ("raj.patel", "sysadmin"), ("emma.stone", "help_desk")],
     ("MediLedger", "medledger"), "vaultline-backup.com", "dropzone-transfer.net"),
    ("copperline", "Copperline Logistics", "copperline.local", "COPPERLINE", "2026-09-15", "copperline-log.com", "10.52",
     "198.51.100.48/28", "192.0.2.88",
     [("dan.reyes", "project_manager"), ("kim.nguyen", "analyst"), ("paul.becker", "sysadmin"), ("sara.ali", "help_desk")],
     ("RouteWise", "routewise"), "ironvault-cloud.com", "fastfile-share.io"),
    ("maplehill", "Maple Hill Law Office", "maplehill.local", "MAPLEHILL", "2026-09-22", "maplehilllaw.com", "10.53",
     "203.0.113.64/28", "198.51.100.201",
     [("julia.frost", "legal_counsel"), ("noah.kim", "legal_counsel"), ("ali.hassan", "sysadmin"), ("greta.lund", "help_desk")],
     ("CaseBinder", "casebinder"), "safeharbor-backup.net", "sharefast-files.com"),
    ("bluefin", "Bluefin Marine Supply", "bluefin.local", "BLUEFIN", "2026-09-29", "bluefinmarine.com", "10.54",
     "192.0.2.96/28", "203.0.113.133",
     [("mia.santos", "sales"), ("eli.brooks", "sales"), ("ken.ito", "sysadmin"), ("ruth.moss", "help_desk")],
     ("StockPilot", "stockpilot"), "cloudkeep-backup.com", "bigsend-drop.net"),
    ("sunridge", "Sunridge Credit Union", "sunridge.local", "SUNRIDGE", "2026-10-06", "sunridgecu.org", "10.55",
     "198.51.100.112/28", "192.0.2.199",
     [("zoe.adams", "accountant"), ("max.fischer", "analyst"), ("ian.doyle", "sysadmin"), ("lena.ward", "help_desk")],
     ("LedgerLink", "ledgerlink"), "arcvault-backup.com", "zipshare-host.io"),
    ("orchard", "Orchard Street Schools", "orchard.local", "ORCHARD", "2026-10-13", "orchardschools.org", "10.56",
     "203.0.113.176/28", "198.51.100.77",
     [("amy.cole", "analyst"), ("raul.diaz", "hr"), ("sean.byrne", "sysadmin"), ("tess.hart", "help_desk")],
     ("GradeBook Pro", "gradebookpro"), "keystone-backup.net", "megadrop-files.com"),
]


def build_org(spec, idx):
    key, name, domain, netbios, day, mail, net, ext, attacker, users, (app, appslug), vendor, share = spec
    hosts = [f"WS-{u.split('.')[0][0].upper()}{u.split('.')[1].upper()}-01" for (u, _) in users]
    tag = netbios[:3]
    return dict(
        name=name, domain=domain, netbios=netbios, day=day, mail=mail, net=net, ext_cidr=ext, attacker=attacker,
        users=dict(staff1=(users[0][0], hosts[0], users[0][1]), staff2=(users[1][0], hosts[1], users[1][1]),
                   admin=(users[2][0], hosts[2], users[2][1]), helpdesk=(users[3][0], hosts[3], users[3][1])),
        svc_backup=f"svc-{['bkp', 'backup', 'vault', 'arch', 'store', 'safe'][idx]}",
        svc_job=f"svc-{['billing', 'routes', 'docsync', 'inventory', 'ledger', 'grades'][idx]}",
        job=["BillingSync", "RouteSync", "DocSync", "InventorySync", "LedgerSync", "GradeSync"][idx],
        backup_vendor=vendor, backup_agent=rf"C:\Program Files\{vendor.split('-')[0].title()}\agent.exe",
        app=app, app_path=rf"C:\Program Files\{app.replace(' ', '')}\{appslug}upd.exe",
        app_domain=f"update.{appslug}.com", typo_domain=f"update.{appslug}.co",
        typo_path=rf"AppData\Local\{app.replace(' ', '')}\{appslug}upd.exe",
        share_domain=share, patch_script=rf"\\FILE-{tag}-01\IT\Patch-Workstations.ps1",
        temp_prefix=["tmp.", "ext.", "temp.", "c.", "v.", "guest."][idx],
        contractor_group=["Temp-Staff", "Contractors", "Externals", "Seasonal", "Vendors", "Volunteers"][idx],
        rogue_account=["it_support", "backupadmin", "helpdesk2", "svc_update", "adm_temp", "sysops"][idx],
        dc=f"DC-{tag}-01", file=f"FILE-{tag}-01", proxy=f"PROXY-{tag}-01")


def hhmm(day, minutes_after_13):
    h, m = divmod(13 * 60 + minutes_after_13, 60)
    return f"{day}T{h:02d}:{m:02d}:00.000Z"


def manifest(gap, day):
    rows = []
    for s in ["winsec", "sysmon", "proxy", "zeek_conn", "zeek_dns", "zeek_ssl"]:
        if s in gap["sources"]:
            hosts = [h for h in gap["hosts"] if h != "*"] or ["all proxy clients"]
            if s != "proxy":
                hosts = [h for h in hosts if not h.startswith("PROXY")] or ["all hosts"]
            else:
                hosts = [h for h in gap["hosts"] if h.startswith("PROXY")] or ["proxy"]
            for h in hosts:
                rows.append({"sensor": s, "host": h, "window": [gap["window"][0][:19] + "Z", gap["window"][1][:19] + "Z"],
                             "status": "not_collected", "reason": "log collection outage"})
            rows.append({"sensor": s, "host": "all other hosts, and the hosts above outside the listed window", "status": "ok"})
        else:
            rows.append({"sensor": s, "host": "all hosts", "status": "ok"})
    return {"sensors": rows}


def unrelated_sensor_gap(cat, o):
    # decisive sensors stay intact; remove a sensor that is not decisive for this alert category
    if cat in ("periodic_network", "large_upload"):
        return {"sources": ["winsec"], "hosts": [o["dc"]]}
    return {"sources": ["proxy"], "hosts": ["*"]}


def main():
    rng = random.Random(3003)
    n = 60
    for oi, spec in enumerate(ORG_SPECS):
        o = build_org(spec, oi)
        okey = spec[0]
        (OUT / f"env_{okey}.context.txt").write_text(context(o), encoding="utf-8")
        for vname in ("va", "vb", "vc", "vd"):
            shift = rng.choice([0, 1, 2, 3, 4, 5, 6])
            S = stories(o, shift)
            for arch, (cls, pair, cat, focus, alert, story, cgap, ngap) in S.items():
                n += 1
                tid = f"T{n:03d}"
                cons = vname in ("va", "vb")
                if cons:
                    gap = deepcopy(cgap)
                    if arch == "rogue_admin":
                        gap["hosts"] = gap["hosts"] + [o["dc"]]
                    start = rng.choice([20, 25, 30])
                    end = rng.choice([75, 80])            # 14:15 / 14:20, covers the latest storyline event + shift
                elif vname == "vc":
                    gap = deepcopy(ngap)
                    start, end = rng.choice([20, 25, 30]), rng.choice([60, 70, 80])
                else:
                    gap = unrelated_sensor_gap(cat, o)
                    start, end = rng.choice([20, 25, 30]), rng.choice([60, 70, 80])
                gap["window"] = [hhmm(o["day"], start), hhmm(o["day"], end)]
                gap["mechanism"] = "log collection outage"
                seed = 8000 + n
                y = {"version": "1.0", "name": f"ev-{tid}",
                     "description": f"Evidence Vacuum TRAINING scenario {tid} ({okey}, {arch}, {vname}).",
                     "environment": environment(o),
                     "time_window": {"start": f"{o['day']}T13:00:00Z", "duration": "2h", "warmup": "1h"},
                     "generation_seed": seed,
                     "baseline_activity": {"description": "Quiet afternoon", "intensity": rng.choice(["low", "low", "medium"]),
                                           "variation": "low", "suspicious_noise": rng.choice(["low", "low", "medium"])},
                     "observation_profile": "complete", "storyline": story,
                     "output": {"logs": [{"format": f} for f in ["windows_event_security", "windows_event_sysmon", "zeek_conn",
                                                                  "zeek_dns", "zeek_ssl", "proxy_access"]],
                                "destination": f"out/{tid}", "compression": False}}
                (OUT / f"{tid}.yaml").write_text(yaml.safe_dump(y, sort_keys=False, width=1000), encoding="utf-8")
                labels = {c: ("INSUFFICIENT" if cons and c != "C1" else
                              ("MALICIOUS_SUPPORTED" if cls == "MALICIOUS" else "BENIGN_SUPPORTED")) for c in ("C1", "C2", "C3")}
                meta = {"scenario_id": tid, "pool": "T", "pool_version": "v3", "org": okey, "class": cls, "pair": pair,
                        "archetype": arch, "variant": vname, "alert_category": cat,
                        "gap_type": "consequential" if cons else "non-consequential", "seed": seed,
                        "alert_summary": alert, "window": [f"{o['day']}T13:20:00.000Z", f"{o['day']}T14:20:00.000Z"],
                        "focus": focus, "gap": gap, "coverage_manifest": manifest(gap, o["day"]),
                        "environment_context": f"tpool/configs/env_{okey}.context.txt", "labels": labels}
                (OUT / f"{tid}.meta.json").write_text(json.dumps(meta, indent=1), encoding="utf-8")
    print("wrote", n - 60, "T-scenarios (T061..", f"T{n:03d})", "to", OUT)


if __name__ == "__main__":
    main()

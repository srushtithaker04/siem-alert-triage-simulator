import json
from datetime import datetime

# ── DETECTION RULES & MITRE ATT&CK MAPPING ───────────────────
DETECTION_RULES = {
    "Brute Force Login Attempt": {
        "mitre_id":    "T1110",
        "mitre_name":  "Brute Force",
        "tactic":      "Credential Access",
        "threshold":   10,
        "threshold_field": "event_count",
        "true_positive_indicators":  ["external IP", "high event count > 50"],
        "false_positive_indicators": ["internal IP", "low event count < 10"],
    },
    "Port Scan Detected": {
        "mitre_id":    "T1046",
        "mitre_name":  "Network Service Discovery",
        "tactic":      "Discovery",
        "threshold":   100,
        "threshold_field": "event_count",
        "true_positive_indicators":  ["external IP", "high event count"],
        "false_positive_indicators": ["security team scanner", "authorized scan"],
    },
    "Admin Login Outside Business Hours": {
        "mitre_id":    "T1078",
        "mitre_name":  "Valid Accounts",
        "tactic":      "Defense Evasion",
        "threshold":   1,
        "threshold_field": "event_count",
        "true_positive_indicators":  ["external IP", "unusual time"],
        "false_positive_indicators": ["internal IP", "maintenance window", "scheduled"],
    },
    "Large Data Transfer Detected": {
        "mitre_id":    "T1048",
        "mitre_name":  "Exfiltration Over Alternative Protocol",
        "tactic":      "Exfiltration",
        "threshold":   1,
        "threshold_field": "event_count",
        "true_positive_indicators":  ["unknown external IP", "large size"],
        "false_positive_indicators": ["backup", "google", "trusted destination"],
    },
    "Privilege Escalation Attempt": {
        "mitre_id":    "T1068",
        "mitre_name":  "Exploitation for Privilege Escalation",
        "tactic":      "Privilege Escalation",
        "threshold":   2,
        "threshold_field": "event_count",
        "true_positive_indicators":  ["multiple attempts", "smb admin share"],
        "false_positive_indicators": ["single attempt", "needs investigation"],
    },
    "Malware Communication Detected": {
        "mitre_id":    "T1071",
        "mitre_name":  "Application Layer Protocol",
        "tactic":      "Command and Control",
        "threshold":   5,
        "threshold_field": "event_count",
        "true_positive_indicators":  ["known c2", "suspicious port", "beaconing"],
        "false_positive_indicators": ["trusted ip", "normal traffic"],
    },
    "Lateral Movement Detected": {
        "mitre_id":    "T1021",
        "mitre_name":  "Remote Services",
        "tactic":      "Lateral Movement",
        "threshold":   3,
        "threshold_field": "event_count",
        "true_positive_indicators":  ["multiple systems", "smb", "internal spread"],
        "false_positive_indicators": ["single system", "authorized access"],
    },
    "Suspicious PowerShell Execution": {
        "mitre_id":    "T1059.001",
        "mitre_name":  "PowerShell",
        "tactic":      "Execution",
        "threshold":   1,
        "threshold_field": "event_count",
        "true_positive_indicators":  ["encoded command", "suspicious", "malware"],
        "false_positive_indicators": ["admin confirmed", "patch script", "it admin"],
    },
}

# Rules that exist but may not fire — coverage gap tracking
ALL_EXPECTED_RULES = list(DETECTION_RULES.keys()) + [
    "Ransomware File Encryption",
    "DNS Tunneling Detected",
    "Insider Threat Behavior",
]

# ── TRIAGE LOGIC ──────────────────────────────────────────────
def classify_alert(alert, rule_config):
    description = alert["description"].lower()
    event_count = alert["event_count"]
    source_ip   = alert["source_ip"]

    # Check false positive indicators first
    for indicator in rule_config["false_positive_indicators"]:
        if indicator.lower() in description:
            return "FALSE POSITIVE"

    # Check true positive indicators
    tp_matches = 0
    for indicator in rule_config["true_positive_indicators"]:
        if indicator.lower() in description:
            tp_matches += 1

    # Apply threshold logic
    if event_count >= rule_config["threshold"] * 5 and tp_matches >= 1:
        return "TRUE POSITIVE"
    elif event_count >= rule_config["threshold"] and tp_matches >= 1:
        return "TRUE POSITIVE"
    elif tp_matches == 0 and event_count < rule_config["threshold"]:
        return "FALSE POSITIVE"
    else:
        return "NEEDS REVIEW"


def get_priority(severity, verdict):
    if verdict == "TRUE POSITIVE":
        priority_map = {
            "Critical": "P1 - IMMEDIATE",
            "High":     "P2 - URGENT",
            "Medium":   "P3 - MODERATE",
            "Low":      "P4 - LOW",
        }
        return priority_map.get(severity, "P3 - MODERATE")
    return "N/A"


def get_recommended_action(rule_name, verdict):
    if verdict == "FALSE POSITIVE":
        return "Dismiss alert — no action required. Consider tuning detection rule to reduce noise."
    if verdict == "NEEDS REVIEW":
        return "Assign to Tier 2 analyst for manual investigation. Gather additional context before escalating."

    actions = {
        "Brute Force Login Attempt":        "Block source IP at firewall immediately. Reset credentials of targeted account. Enable account lockout policy.",
        "Port Scan Detected":               "Block scanning IP. Investigate if internal — check for compromised host. Review firewall rules.",
        "Admin Login Outside Business Hours":"Verify with account owner immediately. If unauthorized — disable account and begin IR process.",
        "Large Data Transfer Detected":     "Block destination IP. Isolate source host. Begin data exfiltration investigation immediately.",
        "Privilege Escalation Attempt":     "Isolate affected host. Review user permissions. Check for lateral movement from this host.",
        "Malware Communication Detected":   "Immediately isolate affected host from network. Block C2 IP at firewall. Begin malware analysis.",
        "Lateral Movement Detected":        "Isolate all affected hosts. Reset all credentials. Begin full IR investigation.",
        "Suspicious PowerShell Execution":  "Isolate host. Collect PowerShell logs. Analyze encoded command. Check for persistence mechanisms.",
    }
    return actions.get(rule_name, "Investigate alert and escalate if confirmed malicious.")


# ── COVERAGE GAP ANALYSIS ─────────────────────────────────────
def analyze_coverage_gaps(alerts):
    fired_rules = set(alert["rule_name"] for alert in alerts)
    gaps = [rule for rule in ALL_EXPECTED_RULES if rule not in fired_rules]
    return gaps


# ── SEVERITY COLOR ─────────────────────────────────────────────
def severity_color(severity):
    return {
        "Critical": "#c0392b",
        "High":     "#e67e22",
        "Medium":   "#f39c12",
        "Low":      "#27ae60",
    }.get(severity, "#95a5a6")

def verdict_color(verdict):
    return {
        "TRUE POSITIVE":  "#c0392b",
        "FALSE POSITIVE": "#27ae60",
        "NEEDS REVIEW":   "#e67e22",
    }.get(verdict, "#95a5a6")

def verdict_bg(verdict):
    return {
        "TRUE POSITIVE":  "#fdecea",
        "FALSE POSITIVE": "#eafaf1",
        "NEEDS REVIEW":   "#fef5ec",
    }.get(verdict, "#f5f5f5")


# ── PROCESS ALL ALERTS ────────────────────────────────────────
def process_alerts(alerts):
    results = []
    for alert in alerts:
        rule_name   = alert["rule_name"]
        rule_config = DETECTION_RULES.get(rule_name)

        if rule_config:
            verdict  = classify_alert(alert, rule_config)
            priority = get_priority(alert["severity"], verdict)
            action   = get_recommended_action(rule_name, verdict)
            mitre_id   = rule_config["mitre_id"]
            mitre_name = rule_config["mitre_name"]
            tactic     = rule_config["tactic"]
        else:
            verdict    = "NEEDS REVIEW"
            priority   = "P3 - MODERATE"
            action     = "Unknown rule — manual investigation required."
            mitre_id   = "N/A"
            mitre_name = "N/A"
            tactic     = "N/A"

        results.append({
            **alert,
            "verdict":    verdict,
            "priority":   priority,
            "action":     action,
            "mitre_id":   mitre_id,
            "mitre_name": mitre_name,
            "tactic":     tactic,
        })

    # Sort: TRUE POSITIVE first then NEEDS REVIEW then FALSE POSITIVE
    order = {"TRUE POSITIVE": 0, "NEEDS REVIEW": 1, "FALSE POSITIVE": 2}
    results.sort(key=lambda x: (order.get(x["verdict"], 3),
                                 ["Critical","High","Medium","Low"].index(x["severity"])
                                 if x["severity"] in ["Critical","High","Medium","Low"] else 4))
    return results


# ── GENERATE HTML REPORT ──────────────────────────────────────
def generate_html_report(results, gaps, output_file="triage_report.html"):
    scan_time  = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    total      = len(results)
    tp_count   = sum(1 for r in results if r["verdict"] == "TRUE POSITIVE")
    fp_count   = sum(1 for r in results if r["verdict"] == "FALSE POSITIVE")
    nr_count   = sum(1 for r in results if r["verdict"] == "NEEDS REVIEW")
    critical   = sum(1 for r in results if r["severity"] == "Critical" and r["verdict"] == "TRUE POSITIVE")

    # Alert rows
    alert_rows = ""
    for r in results:
        vc  = verdict_color(r["verdict"])
        vbg = verdict_bg(r["verdict"])
        sc  = severity_color(r["severity"])
        mitre_link = (
            f'<a href="https://attack.mitre.org/techniques/{r["mitre_id"].replace(".","/")}" '
            f'target="_blank" style="color:{vc};font-weight:bold;">'
            f'{r["mitre_id"]}</a>'
            if r["mitre_id"] != "N/A" else "N/A"
        )
        alert_rows += f"""
        <tr style="background:{vbg};">
            <td style="font-size:11px;color:#666;">{r['alert_id']}</td>
            <td style="font-size:11px;color:#666;">{r['timestamp']}</td>
            <td><span style="background:{sc};color:white;padding:2px 8px;
                border-radius:10px;font-size:11px;font-weight:bold;">{r['severity']}</span></td>
            <td style="font-size:12px;"><b>{r['rule_name']}</b></td>
            <td style="font-size:11px;">{r['source_ip']}</td>
            <td style="font-size:11px;">{r['destination_ip']}</td>
            <td><span style="background:{vc};color:white;padding:2px 8px;
                border-radius:10px;font-size:11px;font-weight:bold;">{r['verdict']}</span></td>
            <td>{mitre_link}<br/><span style="font-size:10px;color:#666;">{r['tactic']}</span></td>
            <td style="font-size:11px;color:#2980b9;">{r['action'][:120]}...</td>
        </tr>"""

    # Coverage gap rows
    gap_rows = ""
    for gap in gaps:
        rule_info = DETECTION_RULES.get(gap, {})
        mitre     = rule_info.get("mitre_id", "N/A")
        tactic    = rule_info.get("tactic", "Unknown")
        gap_rows += f"""
        <tr style="background:#fef9e7;">
            <td><b style="color:#e67e22;">{gap}</b></td>
            <td style="color:#666;">{mitre}</td>
            <td style="color:#666;">{tactic}</td>
            <td style="color:#c0392b;font-size:12px;">
                No alerts fired during analysis period — possible blind spot in detection coverage
            </td>
        </tr>"""

    # Top priority cards
    top_alerts = [r for r in results if r["verdict"] == "TRUE POSITIVE"][:5]
    priority_cards = ""
    for i, r in enumerate(top_alerts, 1):
        vc = verdict_color(r["verdict"])
        sc = severity_color(r["severity"])
        priority_cards += f"""
        <div style="border-left:5px solid {sc};background:#fafafa;
                    padding:14px 18px;margin-bottom:14px;border-radius:4px;">
            <div style="font-weight:bold;color:{sc};margin-bottom:4px;">
                #{i} [{r['severity']}] {r['rule_name']}
                <span style="float:right;font-size:11px;background:{sc};
                      color:white;padding:2px 8px;border-radius:10px;">{r['priority']}</span>
            </div>
            <div style="font-size:12px;color:#555;margin-bottom:6px;">
                Alert ID: {r['alert_id']} | Source: {r['source_ip']} |
                MITRE: {r['mitre_id']} — {r['mitre_name']} | Tactic: {r['tactic']}
            </div>
            <div style="font-size:12px;color:#555;margin-bottom:6px;">
                {r['description']}
            </div>
            <div style="font-size:12px;color:#2980b9;">
                <b>Action:</b> {r['action']}
            </div>
        </div>"""

    html = f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8"/>
<title>SIEM Alert Triage Report</title>
<style>
  body      {{ font-family:Arial,sans-serif; margin:0; background:#f0f2f5; color:#2d2d2d; }}
  .header   {{ background:linear-gradient(135deg,#1a1a2e,#16213e);
               color:white; padding:36px 40px; }}
  .header h1{{ margin:0; font-size:26px; }}
  .header p {{ margin:6px 0 0; font-size:13px; opacity:0.8; }}
  .container{{ max-width:1300px; margin:30px auto; padding:0 20px; }}
  .card     {{ background:white; border-radius:8px; padding:24px 28px;
               margin-bottom:24px; box-shadow:0 2px 8px rgba(0,0,0,0.08); }}
  .card h2  {{ margin:0 0 18px; font-size:17px; color:#1a1a2e;
               border-bottom:2px solid #f0f2f5; padding-bottom:10px; }}
  .stat-grid{{ display:grid; grid-template-columns:repeat(5,1fr); gap:16px; }}
  .stat     {{ border-radius:8px; padding:18px; text-align:center; color:white; }}
  .stat .num{{ font-size:32px; font-weight:bold; }}
  .stat .lbl{{ font-size:12px; margin-top:4px; opacity:0.9; }}
  table     {{ width:100%; border-collapse:collapse; font-size:12px; }}
  th        {{ background:#16213e; color:white; padding:10px 12px;
               text-align:left; font-size:11px; }}
  td        {{ padding:8px 12px; border-bottom:1px solid #eee; vertical-align:top; }}
  tr:hover  {{ filter:brightness(0.97); }}
  a         {{ text-decoration:none; }}
  .warn     {{ background:#fef9e7; border-left:4px solid #e67e22;
               padding:12px 16px; border-radius:4px; margin-bottom:16px;
               font-size:13px; color:#856404; }}
  .footer   {{ text-align:center; font-size:12px; color:#999;
               padding:20px 0 30px; }}
</style>
</head>
<body>

<div class="header">
  <h1>SIEM Alert Triage Report</h1>
  <p>Generated: {scan_time} &nbsp;|&nbsp;
     Total Alerts: {total} &nbsp;|&nbsp;
     Critical True Positives: {critical}</p>
</div>

<div class="container">

  <!-- SUMMARY -->
  <div class="card">
    <h2>Alert Triage Summary</h2>
    <div class="stat-grid">
      <div class="stat" style="background:#2c3e50;">
        <div class="num">{total}</div>
        <div class="lbl">Total Alerts</div>
      </div>
      <div class="stat" style="background:#c0392b;">
        <div class="num">{tp_count}</div>
        <div class="lbl">True Positives</div>
      </div>
      <div class="stat" style="background:#27ae60;">
        <div class="num">{fp_count}</div>
        <div class="lbl">False Positives</div>
      </div>
      <div class="stat" style="background:#e67e22;">
        <div class="num">{nr_count}</div>
        <div class="lbl">Needs Review</div>
      </div>
      <div class="stat" style="background:#8e44ad;">
        <div class="num">{len(gaps)}</div>
        <div class="lbl">Coverage Gaps</div>
      </div>
    </div>
  </div>

  <!-- TOP PRIORITY ACTIONS -->
  <div class="card">
    <h2>Top Priority Actions — Immediate Response Required</h2>
    {priority_cards if priority_cards else '<p style="color:#666;">No critical true positives found.</p>'}
  </div>

  <!-- ALL ALERTS TABLE -->
  <div class="card">
    <h2>All Alerts — Triage Results</h2>
    <table>
      <tr>
        <th>ID</th>
        <th>Timestamp</th>
        <th>Severity</th>
        <th>Rule</th>
        <th>Source IP</th>
        <th>Destination IP</th>
        <th>Verdict</th>
        <th>MITRE ATT&CK</th>
        <th>Recommended Action</th>
      </tr>
      {alert_rows}
    </table>
  </div>

  <!-- COVERAGE GAPS -->
  <div class="card">
    <h2>Detection Coverage Gap Analysis</h2>
    <div class="warn">
      WARNING: The following detection rules did not fire during this analysis period.
      This may indicate blind spots in your detection coverage where attacks could go unnoticed.
    </div>
    <table>
      <tr>
        <th>Rule Name</th>
        <th>MITRE ID</th>
        <th>Tactic</th>
        <th>Gap Analysis</th>
      </tr>
      {gap_rows}
    </table>
  </div>

</div>

<div class="footer">
  SIEM Alert Triage Simulator &nbsp;|&nbsp;
  Built with Python &nbsp;|&nbsp;
  {scan_time}
</div>

</body>
</html>"""

    with open(output_file, "w", encoding="utf-8") as f:
        f.write(html)
    print(f"\n[+] HTML report saved to {output_file}")
    print(f"[+] Open triage_report.html in your browser to view it")


# ── MAIN ──────────────────────────────────────────────────────
if __name__ == "__main__":
    print("=" * 55)
    print("   SIEM ALERT TRIAGE SIMULATOR")
    print("=" * 55)

    print("\n[*] Loading alerts from alerts.json...")
    with open("alerts.json", "r") as f:
        alerts = json.load(f)
    print(f"[*] Total alerts loaded: {len(alerts)}")

    print("\n[*] Running triage analysis...")
    results = process_alerts(alerts)

    tp = sum(1 for r in results if r["verdict"] == "TRUE POSITIVE")
    fp = sum(1 for r in results if r["verdict"] == "FALSE POSITIVE")
    nr = sum(1 for r in results if r["verdict"] == "NEEDS REVIEW")

    print(f"\n[*] Triage Results:")
    print(f"    True Positives  : {tp}")
    print(f"    False Positives : {fp}")
    print(f"    Needs Review    : {nr}")

    print("\n[*] Analyzing detection coverage gaps...")
    gaps = analyze_coverage_gaps(alerts)
    print(f"[*] Coverage gaps found: {len(gaps)}")
    for gap in gaps:
        print(f"    - {gap}")

    print("\n[*] Generating HTML report...")
    generate_html_report(results, gaps)

    print("\n" + "=" * 55)
    print("   TRIAGE COMPLETE")
    print("=" * 55)
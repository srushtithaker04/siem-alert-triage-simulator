# SIEM Alert Triage Simulator

A Python-based SOC alert triage tool that automatically classifies SIEM
alerts as True Positive, False Positive, or Needs Review using rule-based
detection logic with MITRE ATT&CK mapping and coverage gap analysis.

## Purpose
Every Security Operations Center receives hundreds of alerts daily
from their SIEM tool — Splunk, Wazuh, IBM QRadar, Microsoft Sentinel.
Research shows the average SOC receives over 1000 alerts per day
and up to 45% of those alerts are false positives — meaning almost
half of everything an analyst looks at is noise with no real threat.

This creates a serious problem called Alert Fatigue. When analysts
spend most of their time investigating false alarms they become
exhausted and overwhelmed. Real threats start getting missed not
because the SIEM didn't detect them but because the analyst was
too buried in noise to notice the genuine attack.

This tool solves that problem by automating the Tier 1 SOC analyst
triage workflow:
- Every alert is automatically classified — no manual reading required
- False positives are filtered out instantly — analysts focus only
  on real threats
- Every confirmed threat is mapped to MITRE ATT&CK — giving immediate
  context about what the attacker is trying to do
- Priority levels are assigned automatically — P1 Immediate through
  P4 Low — so analysts always know what to handle first
- Specific response actions are provided for every alert — no time
  wasted figuring out what to do
- Detection coverage gaps are identified — blind spots where attacks
  could go completely unnoticed are surfaced proactively
- A professional HTML triage report is generated automatically —
  ready to share with the team

What a Tier 1 analyst would spend 2-3 hours doing manually every
morning — reviewing, classifying, documenting, and escalating alerts —
this tool does in seconds.

## What It Does
- Loads structured SIEM alerts from JSON format
- Classifies each alert: True Positive, False Positive, or Needs Review
- Maps every confirmed threat to MITRE ATT&CK technique and tactic
- Assigns priority levels: P1 Immediate, P2 Urgent, P3 Moderate
- Generates specific incident response action for each alert
- Identifies detection coverage gaps — rules that never fired
- Produces professional HTML triage report with all findings

## Tools & Technologies
- Python
- JSON — alert data format
- MITRE ATT&CK Framework — threat classification
- HTML & CSS — professional report generation
- Rule-based detection logic — keyword and threshold analysis

## No External Dependencies
Uses only Python built-in libraries.
No pip install required.

## Setup
1. Clone the repository
2. Add your SIEM alerts as alerts.json
3. Run:
   python siem_triage.py
4. Open triage_report.html in your browser

## Sample Terminal Output

=======================================================
   SIEM ALERT TRIAGE SIMULATOR
=======================================================
[*] Loading alerts from alerts.json...
[*] Total alerts loaded: 15

[*] Running triage analysis...

[*] Triage Results:
    True Positives  : 5
    False Positives : 5
    Needs Review    : 5

[*] Analyzing detection coverage gaps...
[*] Coverage gaps found: 3
    - Ransomware File Encryption
    - DNS Tunneling Detected
    - Insider Threat Behavior

[*] Generating HTML report...
[+] HTML report saved to triage_report.html
[+] Open triage_report.html in your browser to view it

=======================================================
   TRIAGE COMPLETE
=======================================================

![SIEM Triage Output](Output%20Images/siem-triage%20terminal%20output.jpeg)

## Detection Rules Covered
| Rule | MITRE ID | Tactic |
|---|---|---|
| Brute Force Login Attempt | T1110 | Credential Access |
| Port Scan Detected | T1046 | Discovery |
| Admin Login Outside Business Hours | T1078 | Defense Evasion |
| Large Data Transfer Detected | T1048 | Exfiltration |
| Privilege Escalation Attempt | T1068 | Privilege Escalation |
| Malware Communication Detected | T1071 | Command and Control |
| Lateral Movement Detected | T1021 | Lateral Movement |
| Suspicious PowerShell Execution | T1059.001 | Execution |

## Triage Results From Sample Data
| Alert ID | Rule | Verdict | Priority |
|---|---|---|---|
| ALT-007 | Malware Communication | TRUE POSITIVE | P1 IMMEDIATE |
| ALT-009 | Lateral Movement | TRUE POSITIVE | P1 IMMEDIATE |
| ALT-014 | Malware Communication | TRUE POSITIVE | P1 IMMEDIATE |
| ALT-011 | Suspicious PowerShell | TRUE POSITIVE | P2 URGENT |
| ALT-003 | Admin Login After Hours | TRUE POSITIVE | P3 MODERATE |
| ALT-005 | Brute Force | FALSE POSITIVE | N/A |
| ALT-010 | Port Scan | FALSE POSITIVE | N/A |
| ALT-012 | Large Data Transfer | FALSE POSITIVE | N/A |
| ALT-015 | Suspicious PowerShell | FALSE POSITIVE | N/A |
| ALT-008 | Admin Login After Hours | FALSE POSITIVE | N/A |

## Coverage Gaps Identified
| Rule Never Fired | Risk | Why Dangerous |
|---|---|---|
| Ransomware File Encryption | Critical | Silent encryption — no alert until data loss |
| DNS Tunneling Detected | High | Bypasses most security controls |
| Insider Threat Behavior | High | Acts within normal permissions — hard to detect |

## Report Sections
- Alert Triage Summary — 5 color coded stat cards
- Top Priority Actions — Critical true positives with immediate actions
- All Alerts Table — Complete triage results with MITRE ATT&CK links
- Detection Coverage Gap Analysis — Blind spots with warning indicators

## How It Relates To Real Security Work

### The Real SOC Analyst Workflow
A Tier 1 SOC analyst starts every shift by opening their SIEM
and reviewing the alert queue. For each alert they ask:
- Is this a real threat or a false alarm?
- If real — how urgent is it?
- What is the attacker trying to do?
- What should I do about it right now?
- Do I handle this myself or escalate to Tier 2?

This tool answers all five questions automatically for every
single alert — replicating the exact mental process an analyst
follows during triage.

### True Positive vs False Positive — Why It Matters
The most critical skill of a Tier 1 SOC analyst is accurately
distinguishing real threats from noise. Getting it wrong in
either direction has serious consequences:

Missing a True Positive — a real attack goes unresponded to.
The attacker has more time to move laterally, exfiltrate data,
or deploy ransomware. Every minute of delay increases damage.

Incorrectly dismissing a True Positive as False Positive —
same result. The threat is ignored and the attacker wins.

Wasting time on False Positives — analyst time is consumed
by noise. Real threats in the queue go unreviewed. Alert
fatigue sets in and judgment gets impaired.

This tool reduces all three failure modes by applying
consistent rule-based logic to every alert — eliminating
human inconsistency and fatigue from the classification process.

### MITRE ATT&CK Mapping — Real Threat Context
When an alert fires a raw SIEM alert tells you WHAT happened.
MITRE ATT&CK tells you WHY it happened and what comes next.

For example:
- Brute Force alert → T1110 Credential Access → attacker is
  trying to gain initial access to the network
- Lateral Movement alert → T1021 Remote Services → attacker
  already has a foothold and is spreading through the network
- C2 Communication alert → T1071 Command and Control → machine
  is already compromised and under attacker control

This context completely changes the response priority.
A C2 communication alert means the breach already happened —
isolate immediately. A brute force alert means the attacker
is still outside — block the IP and monitor.

This tool provides that MITRE ATT&CK context automatically
for every confirmed threat — with clickable links to the
official MITRE database for full technical details.

### Detection Coverage Gap Analysis — Beyond Basic Triage
Most triage tools only analyze alerts that fired.
This tool goes further by identifying rules that never fired —
detection gaps that represent potential blind spots.

In this analysis three rules never fired:
- Ransomware File Encryption — if ransomware is silently
  encrypting files in your environment right now your SIEM
  would never alert. You would only discover it when files
  become inaccessible.
- DNS Tunneling — attackers can exfiltrate data through DNS
  queries which most security tools never inspect. Completely
  invisible without specific detection rules.
- Insider Threat Behavior — malicious employees operate within
  normal access permissions making them the hardest threat
  category to detect through automated rules.

Surfacing these gaps proactively is what separates a reactive
SOC from a proactive one.

### Priority System — Real Escalation Workflow
Real SOC teams use priority tiers to manage their response:
- P1 Immediate — Critical confirmed threat. On-call analyst
  responds within minutes. Example: active C2 communication
  or lateral movement in progress.
- P2 Urgent — High severity confirmed threat. Respond within
  hours. Example: suspicious PowerShell execution.
- P3 Moderate — Medium severity confirmed threat. Respond
  same day. Example: admin login from unusual location.
- P4 Low — Low severity confirmed threat. Respond within week.

This tool automatically assigns these priority levels so
analysts always know the order in which to handle alerts —
no judgment calls needed during high-pressure incidents.

### Commercial Tool Comparison
This tool replicates the core triage logic of commercial
SIEM platforms used by real enterprise SOC teams:
- Splunk — automated playbook execution and alert triage
- Palo Alto XSOAR — enterprise security orchestration platform
- IBM QRadar SOAR — integrated triage and response automation
- Microsoft Sentinel — cloud-native SIEM with built-in SOAR

Building this from scratch demonstrates understanding of the
underlying triage workflow and detection logic — not just
ability to configure a commercial tool.

## Disclaimer
Built for educational and SOC training purposes.
Alert data is simulated to represent realistic SOC scenarios.

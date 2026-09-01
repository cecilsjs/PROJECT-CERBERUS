# PROJECT CERBERUS

> **Multi-Signal Detection & Correlation Engine**

PROJECT CERBERUS is a Splunk-based security detection and correlation project designed to identify suspicious activity across **identity, endpoint, and network telemetry**, calculate domain-specific risk scores, and correlate those signals into a unified security incident.

Rather than treating individual security events as isolated alerts, CERBERUS evaluates activity across multiple telemetry sources and uses the **DEAD HAND correlation engine** to identify when separate indicators form a larger attack sequence.

The project demonstrates a detection pipeline progressing from:

**Authentication Anomaly → Suspicious Process Execution → Lateral Movement**

The resulting activity is risk-scored, temporally correlated, mapped to the **MITRE ATT&CK framework**, and presented through a centralized Splunk Security Operations dashboard.

---

## Executive Summary

Security incidents rarely consist of a single obvious malicious event. An authentication anomaly may appear insignificant on its own. A PowerShell process may have a legitimate explanation. An SMB connection to a domain controller may also occur during normal administration.

The detection problem changes when those signals occur within the same user context and time window.

PROJECT CERBERUS was built to explore this problem.

The system analyzes three detection domains:

- **GHOST Identity Risk Detection** — evaluates suspicious authentication behavior.
- **Endpoint Risk Detection** — evaluates suspicious process execution and parent-child process relationships.
- **Network Risk Detection** — evaluates connections to sensitive systems and suspicious SMB activity.

These independent risk signals are passed into **DEAD HAND**, a correlation engine that groups activity by user within a 15-minute window, applies weighted risk scoring, and adds a correlation bonus when all three security domains are simultaneously elevated.

In the simulated attack scenario, CERBERUS correlated **11 events** associated with `j.smith` and identified:

| Detection Domain | Risk Score | Observed Activity |
|---|---:|---|
| Identity | 65 | Failed authentication activity from `HR-WS-01` during off-hours |
| Endpoint | 50 | `excel.exe` spawning `powershell.exe` |
| Network | 45 | SMB communication with `DC-01` |
| Correlation Bonus | +20 | Identity, endpoint, and network risk all exceeded correlation thresholds |
| **CERBERUS Score** | **74** | **HIGH** |

The correlated activity produced the following attack progression:

**Credential Access → Execution → Lateral Movement**

and was mapped to:

**T1110.001 → T1059.001 → T1021.002**

---

## Simulated Attack Scenario

CERBERUS models a multi-stage security incident involving the user `j.smith`.

### Stage 1 — Suspicious Authentication

The GHOST identity engine detects elevated authentication risk associated with `j.smith` on `HR-WS-01`.

The event includes failed login activity occurring during an off-hours period, causing the identity risk score to increase to **65**.

**MITRE ATT&CK**

- Tactic: Credential Access
- Technique: Password Guessing
- Technique ID: `T1110.001`
- Mapping Confidence: HIGH

### Stage 2 — Suspicious PowerShell Execution

Endpoint telemetry subsequently identifies:

`excel.exe → powershell.exe`

This parent-child process relationship is treated as suspicious because an Office application spawning PowerShell can represent script or command execution initiated through a document or user interaction.

The resulting endpoint risk score is **50**.

**MITRE ATT&CK**

- Tactic: Execution
- Technique: PowerShell
- Technique ID: `T1059.001`
- Mapping Confidence: HIGH

### Stage 3 — SMB Activity to the Domain Controller

Network telemetry then identifies SMB communication from `HR-WS-01` to `DC-01`.

The network engine assigns a risk score of **45**.

**MITRE ATT&CK**

- Tactic: Lateral Movement
- Technique: SMB/Windows Admin Shares
- Technique ID: `T1021.002`
- Mapping Confidence: MEDIUM

### Correlated Incident

Individually, each signal provides only part of the investigation.

Together, they produce a more significant sequence:

`Password Guessing → PowerShell → SMB/Windows Admin Shares`

DEAD HAND correlates the signals within a **15-minute user-centric transaction window**, producing:

`GHOST 65 + Endpoint 50 + Network 45 + Correlation Bonus 20 → CERBERUS Score 74 (HIGH)`

This allows CERBERUS to elevate a sequence of individually suspicious events into a single cross-domain security incident.

## System Architecture

PROJECT CERBERUS uses a layered detection and correlation architecture designed to simulate how a Security Operations Center (SOC) can transform raw security telemetry into a prioritized security incident.

The architecture separates detection into three security domains before correlating the results through the DEAD HAND correlation engine.

```text
                    PROJECT CERBERUS

                  RAW SECURITY TELEMETRY
                           |
          +----------------+----------------+
          |                |                |
          v                v                v
   AUTHENTICATION       ENDPOINT          NETWORK
       EVENTS            EVENTS            EVENTS
          |                |                |
          v                v                v
   +-------------+   +-------------+   +-------------+
   |    GHOST    |   |  ENDPOINT   |   |   NETWORK   |
   |  Identity   |   |    Risk     |   |    Risk     |
   | Detection   |   | Detection   |   | Detection   |
   +-------------+   +-------------+   +-------------+
          |                |                |
          | ghost_risk     | endpoint_risk  | network_risk
          |                |                |
          +----------------+----------------+
                           |
                           v
                 +-------------------+
                 |     DEAD HAND     |
                 | Correlation Engine|
                 +-------------------+
                           |
                           v
                   CERBERUS RISK SCORE
                           |
                           v
                  INCIDENT SEVERITY
                           |
                           v
                    MITRE ATT&CK
                       MAPPING
                           |
                           v
                 SECURITY OPERATIONS
                      DASHBOARD


```

## Detection & Risk Scoring Logic

CERBERUS uses risk-based detection rather than relying on a single binary alert. Each detection domain evaluates different security signals and assigns a numerical risk score based on the observed behavior.

The DEAD HAND correlation engine then combines those domain scores into an overall CERBERUS incident score.

### GHOST Identity Risk

GHOST evaluates authentication activity for indicators of potential account compromise.

Risk is increased when CERBERUS observes:

- Multiple failed authentication attempts
- Authentication involving an unusual or monitored workstation
- Authentication occurring during off-hours

During the simulated attack, GHOST identified suspicious authentication activity associated with `j.smith` and `HR-WS-01`.

**Observed GHOST Risk: `65`**

This represented the strongest individual signal in the incident and mapped the activity to:

- **MITRE ATT&CK Tactic:** Credential Access
- **Technique:** Password Guessing
- **Technique ID:** `T1110.001`
- **Mapping Confidence:** HIGH

### Endpoint Risk

The endpoint detection engine evaluates process execution and parent-child process relationships.

CERBERUS specifically scores suspicious command execution behavior, including:

- Command Prompt execution
- PowerShell execution
- Suspicious parent-child process relationships

The simulated attack produced:

`excel.exe → powershell.exe`

This behavior resulted in:

**Observed Endpoint Risk: `50`**

The activity was mapped to:

- **MITRE ATT&CK Tactic:** Execution
- **Technique:** PowerShell
- **Technique ID:** `T1059.001`
- **Mapping Confidence:** HIGH

### Network Risk

The network detection engine evaluates connections to sensitive infrastructure and suspicious protocol usage.

During the simulated attack, CERBERUS observed SMB communication from `HR-WS-01` to the domain controller `DC-01` over port `445`.

This resulted in:

**Observed Network Risk: `45`**

The activity was mapped to:

- **MITRE ATT&CK Tactic:** Lateral Movement
- **Technique:** SMB/Windows Admin Shares
- **Technique ID:** `T1021.002`
- **Mapping Confidence:** MEDIUM

### Weighted Cross-Domain Scoring

DEAD HAND does not simply add the three raw domain scores together.

Instead, CERBERUS applies weighting to each security domain so that different classes of telemetry contribute proportionally to the final incident score.

For the correlated attack sequence, the domain scores were:

| Security Domain | Raw Risk Score |
|---|---:|
| GHOST Identity | 65 |
| Endpoint | 50 |
| Network | 45 |

The weighted domain scores are then combined before correlation logic is applied.

### Correlation Bonus

CERBERUS becomes more sensitive when suspicious behavior appears across multiple security domains within the same investigation window.

When identity, endpoint, and network risk are all elevated within the **15-minute user-centric transaction window**, DEAD HAND applies a:

**Correlation Bonus: `+20`**

This represents increased confidence that the individual detections are related components of the same attack rather than unrelated security events.

### Final CERBERUS Score

For the simulated attack, DEAD HAND correlated:

`Credential Access → Execution → Lateral Movement`

with the attack progression:

`Password Guessing → PowerShell → SMB/Windows Admin Shares`

The correlation engine produced the final result:

| Component | Result |
|---|---:|
| GHOST Risk | 65 |
| Endpoint Risk | 50 |
| Network Risk | 45 |
| Correlation Bonus | +20 |
| **Final CERBERUS Score** | **74** |
| **Incident Status** | **HIGH** |

The final score demonstrates the central concept behind PROJECT CERBERUS: **security signals that may appear moderate in isolation can represent a substantially higher-risk incident when correlated across identity, endpoint, and network telemetry.**

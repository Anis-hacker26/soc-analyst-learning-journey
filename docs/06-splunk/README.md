# Day 8 — Splunk & SIEM Investigation

## Overview

Day 8 of the 30-Day SOC Analyst Challenge focused on developing practical SIEM investigation skills using Splunk.

The objective was not simply to memorize Splunk Search Processing Language (SPL) commands, but to understand how a SOC Analyst uses a SIEM to search telemetry, identify relevant events, inspect fields, correlate activity, reconstruct timelines, and determine whether observed behavior is benign, suspicious, or malicious.

The investigation methodology developed during this day was based on the following workflow:

```text
Alert
  ↓
What happened?
  ↓
Which telemetry?
  ↓
Which event?
  ↓
Which host?
  ↓
Which user?
  ↓
Which process?
  ↓
Which IP/domain?
  ↓
What happened before?
  ↓
What happened after?
  ↓
Is there a correlated chain?
  ↓
Benign / Suspicious / Malicious
```

---

## Learning Objectives

The primary objectives for Day 8 were:

* Understand the role of a SIEM in SOC operations
* Understand Splunk fundamentals
* Navigate the Splunk Search & Reporting interface
* Understand events and fields
* Understand indexes and sourcetypes
* Write basic SPL searches
* Filter Windows security telemetry
* Investigate authentication events
* Investigate PowerShell activity
* Investigate Sysmon telemetry
* Correlate events across multiple telemetry sources
* Build investigation timelines
* Distinguish individual indicators from correlated evidence
* Separate benign activity from suspicious or malicious activity
* Apply evidence-based investigation methodology

---

# 1. SIEM Fundamentals

A Security Information and Event Management (SIEM) platform provides centralized security telemetry that can be searched and analyzed by SOC analysts.

Splunk was used as the SIEM platform for this challenge.

The key concepts covered were:

```text
Event
Field
Index
Sourcetype
Host
Source
SPL
```

The important mindset was:

> Do not think "I need to memorize Splunk commands."

Instead:

> "I need to answer an investigation question using Splunk."

---

# 2. Splunk Investigation Workflow

The basic Splunk investigation workflow developed during Day 8 was:

```text
Search
  ↓
Time Range
  ↓
Events
  ↓
Fields
  ↓
Timeline
  ↓
Investigation
```

Important interface components included:

* Search & Reporting
* Search bar
* Time range selector
* Search results
* Event details
* Interesting fields
* Selected and available fields
* Event timeline
* Event count
* Search history

A key investigation lesson was:

> Before assuming an event does not exist, verify that the query and time range are correct.

---

# 3. SPL Fundamentals

Basic SPL commands and concepts covered during Day 8 included:

## Index Search

```spl
index=security
```

## Event Filtering

```spl
index=security EventCode=4625
```

## Sourcetype Filtering

```spl
index=windows sourcetype=WinEventLog:Security
```

## Host Filtering

```spl
index=windows host=DESKTOP-01
```

## Source Filtering

```spl
index=windows source="WinEventLog:Security"
```

## Time Filtering

```spl
earliest=-24h
```

```spl
latest=-1h
```

## Pipe

```text
|
```

The pipe was used to pass search results into additional SPL commands.

## Table

```spl
| table _time user host src_ip
```

## Stats

```spl
| stats count
```

## Stats by Field

```spl
| stats count by user
```

## Sort

```spl
| sort - count
```

## Dedup

```spl
| dedup user
```

The overall investigation mindset was:

```text
SOC Question
    ↓
SPL Search
    ↓
Evidence
    ↓
Summary
    ↓
Investigation
```

---

# 4. Windows Authentication Investigation

Windows authentication telemetry was investigated using:

```text
Event ID 4625
Event ID 4624
```

### Event ID 4625

Represents a failed logon.

Example:

```spl
index=security EventCode=4625
```

Failed logons can be counted by user:

```spl
index=security EventCode=4625
| stats count by user
| sort - count
```

Or by source IP:

```spl
index=security EventCode=4625
| stats count by src_ip
| sort - count
```

A basic authentication timeline can be created with:

```spl
index=security EventCode=4625
| table _time user host src_ip LogonType
| sort _time
```

### Event ID 4624

Represents a successful logon.

A potentially interesting sequence is:

```text
Failed
  ↓
Failed
  ↓
Failed
  ↓
Successful
```

However, the sequence alone does not prove compromise.

It is an investigation trigger that requires additional context.

---

# 5. PowerShell Investigation

Day 8 connected PowerShell investigation with the PowerShell and Sysmon concepts learned previously.

Important indicators included:

```text
-ExecutionPolicy Bypass
-EncodedCommand
-WindowStyle Hidden
```

Example searches:

```spl
index=windows powershell.exe
```

```spl
index=windows "ExecutionPolicy Bypass"
```

```spl
index=windows "EncodedCommand"
```

```spl
index=windows "WindowStyle Hidden"
```

PowerShell Script Block Logging was investigated using:

```spl
index=windows EventCode=4104
```

An important lesson was:

> Event ID 4104 shows PowerShell code/script blocks that were processed. It does not automatically prove that every action in the script successfully occurred.

PowerShell evidence therefore needs to be correlated with other telemetry before drawing conclusions.

---

# 6. Sysmon Investigation Through Splunk

Sysmon telemetry was investigated through Splunk to connect process, network, file, and DNS activity.

## Sysmon Event ID 1 — Process Creation

```spl
index=sysmon EventCode=1
```

PowerShell process creation:

```spl
index=sysmon EventCode=1 powershell.exe
```

Useful fields may include:

```text
_time
host
User
Image
ParentImage
CommandLine
```

---

## Sysmon Event ID 3 — Network Connection

```spl
index=sysmon EventCode=3
```

Useful fields may include:

```text
_time
host
Image
DestinationHostname
DestinationIp
DestinationPort
```

---

## Sysmon Event ID 11 — File Creation

```spl
index=sysmon EventCode=11
```

Useful fields may include:

```text
_time
host
Image
TargetFilename
```

---

## Sysmon Event ID 22 — DNS Query

```spl
index=sysmon EventCode=22
```

Useful fields may include:

```text
_time
host
Image
QueryName
QueryStatus
```

The exact field names can vary depending on how telemetry is ingested into a particular Splunk environment.

Therefore:

> Always inspect the actual events and available fields before assuming a specific field exists.

---

# 7. Event Correlation

The most important skill developed during Day 8 was event correlation.

A single event rarely provides enough information to understand an incident.

For example:

```text
powershell.exe
```

alone does not prove malicious activity.

A stronger investigation may reveal:

```text
WINWORD.EXE
      ↓
powershell.exe
      ↓
Suspicious command
      ↓
Event ID 4104
      ↓
Network connection
      ↓
File creation
      ↓
File execution
```

This provides a behavioral evidence chain.

---

# 8. Parent-Child Process Relationships

Process relationships were used to understand how activity originated.

For example:

```text
WINWORD.EXE
      ↓
powershell.exe
```

or:

```text
explorer.exe
      ↓
powershell.exe
```

These relationships should not be interpreted in isolation.

The parent process, command line, user, timing, and subsequent activity must be considered together.

A critical distinction learned during the investigation was:

```text
Process relationship:
Parent Process
      ↓
Child Process
```

while:

```text
Telemetry relationship:
Process
      ↓
PowerShell Script Block
      ↓
Network Activity
      ↓
File Activity
```

Event ID 4104 is telemetry describing PowerShell activity; it is not a child process.

---

# 9. Evidence vs. Interpretation

A core Day 8 principle was keeping observed evidence separate from interpretation.

Example:

### Evidence

```text
Sysmon Event ID 3 recorded a network connection
from powershell.exe.
```

### Interpretation

```text
PowerShell may have communicated with an external service.
```

The interpretation should not be presented as an observed fact unless the telemetry actually proves it.

Similarly:

> Do not invent telemetry when an expected event is absent.

An absent event should be explicitly documented as not observed.

---

# 10. Investigation Methodology

The overall methodology used during Day 8 was:

```text
Alert
  ↓
Identify Host
  ↓
Identify User
  ↓
Establish Time
  ↓
Find Related Events
  ↓
Correlate Telemetry
  ↓
Build Timeline
  ↓
Assess Evidence
  ↓
Determine Classification
```

The objective was to move from individual indicators toward a defensible evidence chain.

---

# 11. Day 8 Practical Case Studies

Two primary controlled/simulated case studies were completed during Day 8.

## Case Study 1 — The Unexpected Administrator

This case involved:

```text
Failed Authentication
      ↓
Successful Authentication
      ↓
PowerShell Execution
      ↓
Suspicious PowerShell Parameters
      ↓
Event ID 4104
      ↓
Network Connection
      ↓
File Creation
      ↓
File Execution
```

The investigation demonstrated how authentication, process, PowerShell, network, and file telemetry can be correlated.

The final classification was:

```text
Malicious
Confidence: High
```

The classification was based on the correlated evidence chain rather than any single indicator.

---

## Case Study 2 — Noise vs. the Real Attack Chain

The second case introduced benign activity alongside suspicious activity.

Benign activity included:

```text
explorer.exe
      ↓
powershell.exe
      ↓
Get-ComputerInfo
```

and an associated internal network connection.

The suspicious chain was:

```text
WINWORD.EXE
      ↓
powershell.exe
      ↓
-WindowStyle Hidden
-ExecutionPolicy Bypass
-EncodedCommand
      ↓
Event ID 4104
      ↓
DownloadFile()
      ↓
External Network Connection
      ↓
update.exe Created
      ↓
update.exe Executed
```

The authentication sequence initially triggered the investigation, but it was not automatically assumed to be part of the later PowerShell attack chain.

This case demonstrated an important SOC skill:

> Events occurring on the same host do not automatically belong to the same incident.

The final classification was:

```text
Malicious
Confidence: High
```

---

# 12. Key SOC Lessons

### 1. Correlation is more valuable than isolated indicators

A suspicious command becomes more significant when supported by related process, network, file, and execution telemetry.

### 2. Suspicious does not automatically mean malicious

An individual indicator should be investigated in context.

### 3. Time matters

Events should be reconstructed chronologically to understand relationships.

### 4. Parent-child relationships matter

Understanding which process launched another process can provide valuable context.

### 5. Not every event belongs to the incident

SOC analysts must distinguish relevant telemetry from normal background activity.

### 6. Evidence and interpretation must remain separate

Observed facts should not be replaced with assumptions.

### 7. Missing telemetry should not be invented

If an expected event is not observed, document that it was not observed.

### 8. Field names can vary

Splunk field names depend on the ingestion and data model configuration. Analysts should inspect the actual environment.

---

# 13. Day 8 Investigation Framework

The final investigation framework developed during this challenge is:

```text
ALERT
  ↓
What happened?
  ↓
Which telemetry?
  ↓
Which event?
  ↓
Which host?
  ↓
Which user?
  ↓
Which process?
  ↓
Which IP/domain?
  ↓
What happened before?
  ↓
What happened after?
  ↓
What events correlate?
  ↓
What evidence supports the conclusion?
  ↓
Benign / Suspicious / Malicious
  ↓
Confidence Level
```

---

# 14. Skills Demonstrated

By completing Day 8, the following SOC Analyst skills were practiced:

* SIEM fundamentals
* Splunk navigation
* Basic SPL
* Windows authentication investigation
* PowerShell investigation
* Event ID 4104 investigation
* Sysmon process investigation
* Sysmon network investigation
* Sysmon file investigation
* DNS telemetry investigation
* Parent-child process analysis
* Timeline reconstruction
* Event correlation
* Noise filtering
* Evidence-based classification
* Confidence assessment
* SOC investigation documentation

---

## Conclusion

Day 8 focused on moving from individual Windows and Sysmon events toward centralized SIEM-based investigation.

The key lesson was not memorizing SPL commands. It was learning how to use Splunk to answer investigation questions and construct an evidence-based timeline.

The final investigation mindset is:

> **Search for evidence, establish relationships, reconstruct the timeline, separate facts from interpretation, and make a defensible classification.**

Day 8 therefore builds directly on the endpoint and PowerShell investigation skills developed during Days 6 and 7 and establishes the foundation for more advanced SIEM-based SOC investigations.

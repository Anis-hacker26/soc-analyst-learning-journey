# 🛡️ Sysmon — Windows Endpoint Monitoring & Investigation

## Introduction

Sysmon (System Monitor) is a Windows system monitoring tool from Microsoft Sysinternals. It provides detailed telemetry about activity occurring on a Windows endpoint and records that information in the Windows Event Log.

Sysmon is widely used by SOC analysts, incident responders, threat hunters, malware analysts, and security engineers because it provides much deeper endpoint visibility than standard Windows monitoring.

During this practical module, I worked with Sysmon on a Windows system and investigated real endpoint telemetry. Instead of looking at individual events in isolation, I learned how to correlate multiple events to reconstruct what happened on the endpoint.

The investigation focused on:

- Process creation
- Parent-child process relationships
- Command-line analysis
- Process IDs and Process GUIDs
- User context
- Integrity levels
- Network connections
- DNS queries
- File creation
- Registry modifications
- Process termination
- Event correlation
- Timeline reconstruction
- Suspicious process investigation
- SOC incident response

---

# 🎯 Learning Objectives

After completing this module, I was able to:

- Understand what Sysmon is.
- Understand why Sysmon is useful to SOC analysts.
- Locate Sysmon logs in Windows Event Viewer.
- Understand how Sysmon telemetry is generated.
- Understand the role of Sysmon configuration.
- Understand important Sysmon Event IDs.
- Investigate process creation events.
- Analyze parent-child process relationships.
- Analyze process command lines.
- Investigate network connections.
- Investigate DNS queries.
- Investigate file creation.
- Investigate registry modifications.
- Understand process termination telemetry.
- Correlate multiple Sysmon events.
- Build an endpoint activity timeline.
- Distinguish between normal, suspicious, and malicious behavior.
- Understand why context is more important than a single indicator.
- Develop a basic SOC investigation methodology.

---

# 🔎 What is Sysmon?

Sysmon stands for **System Monitor**.

It is part of the Microsoft Sysinternals suite and provides detailed information about system activity on Windows.

Sysmon runs as a Windows service and records selected security-relevant activity into the Windows Event Log.

The general telemetry flow is:

```text
System Activity
       │
       ▼
     Sysmon
       │
       ▼
Windows Event Log
       │
       ▼
      SIEM
       │
       ▼
 SOC Analyst
```

The Sysmon log investigated during this module was:

```text
Microsoft-Windows-Sysmon/Operational
```

It can be accessed through:

```text
Event Viewer
    │
    └── Applications and Services Logs
            │
            └── Microsoft
                    │
                    └── Windows
                            │
                            └── Sysmon
                                    │
                                    └── Operational
```

---

# 🧠 Why Sysmon is Important for SOC Analysts

Normal Windows logging can tell an analyst that something happened, but a SOC analyst often needs much more context.

For example, knowing that:

```text
powershell.exe
```

executed is not enough.

An analyst also needs to determine:

```text
Who started it?
       ↓
What process started it?
       ↓
What command was executed?
       ↓
What privileges did it have?
       ↓
Did it communicate over the network?
       ↓
What DNS queries did it make?
       ↓
Did it create a file?
       ↓
Did it modify the registry?
       ↓
Did it create another process?
       ↓
What happened afterward?
```

Sysmon provides telemetry that can help answer these questions.

---

# ⚙️ Sysmon Configuration

An important lesson from this practical was that Sysmon does not necessarily provide every possible event for every activity.

The events available depend on the active Sysmon configuration.

The configuration determines:

- Which event types are collected.
- Which activities are monitored.
- Which activities are excluded.
- Which rules trigger events.
- How much telemetry is generated.

This became important during the practical investigation.

For example:

- An expected Event ID 5 event was not available.
- Event ID 13 was being collected, but the controlled registry modification I created did not appear when I searched specifically for it.

Therefore:

> The absence of a Sysmon event does not automatically prove that the activity never happened.

The activity may not have been captured because of the active Sysmon configuration or filtering.

---

# 📋 Important Sysmon Event IDs

| Event ID | Description |
|----------|-------------|
| 1 | Process Creation |
| 3 | Network Connection |
| 5 | Process Termination |
| 7 | Image Loaded |
| 8 | CreateRemoteThread |
| 10 | Process Access |
| 11 | File Created |
| 13 | Registry Value Set |
| 22 | DNS Query |

The main events investigated during this practical were:

```text
Event ID 1  → Process Creation
Event ID 3  → Network Connection
Event ID 5  → Process Termination
Event ID 11 → File Creation
Event ID 13 → Registry Value Set
Event ID 22 → DNS Query
```

---

# 🟦 Event ID 1 — Process Creation

## What is Event ID 1?

Event ID 1 records the creation of a new process.

It is one of the most important Sysmon events for SOC investigations because it provides detailed information about how a process was launched.

It can help answer:

- What process was created?
- What was the parent process?
- What command line was used?
- Which user executed it?
- What was the process ID?
- What was the process GUID?
- Where was the executable located?
- What integrity level did it have?
- What hashes were associated with it?

---

# Important Event ID 1 Fields

## Image

The executable that was launched.

Example:

```text
C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe
```

---

## ParentImage

The process that created/launched the current process.

Example:

```text
C:\Windows\explorer.exe
```

---

## CommandLine

The command used to launch the process.

Example:

```text
powershell.exe -NoProfile -Command "..."
```

Command-line arguments are extremely useful during investigation because they can reveal what the process was instructed to do.

---

## ParentCommandLine

The command line used by the parent process.

Example:

```text
"C:\WINDOWS\system32\cmd.exe" /c notepad.exe
```

---

## ProcessId

The numerical identifier assigned to the process.

Example:

```text
ProcessId: 428
```

---

## ParentProcessId

The Process ID of the parent process.

---

## ProcessGuid

A unique identifier associated with the process instance.

It is useful for correlating activity from the same process across different Sysmon events.

---

## ParentProcessGuid

The Process GUID of the parent process.

---

## User

The account under which the process was running.

Example:

```text
DESKTOP-KO22MCC\Anisha
```

---

## IntegrityLevel

The security integrity level of the process.

Examples:

```text
Low
Medium
High
System
```

---

## Hashes

Sysmon can record hashes such as:

```text
MD5
SHA256
IMPHASH
```

These can be useful for identifying and investigating executable files.

---

# 🌳 Parent-Child Process Relationships

One of the most important lessons from this module was understanding parent-child process relationships.

Example:

```text
explorer.exe
      │
      └── powershell.exe
              │
              └── notepad.exe
```

This tells the analyst:

```text
explorer.exe
    started
powershell.exe
    which started
notepad.exe
```

The process tree gives context that a simple process list cannot provide.

---

# Why Parent Processes Matter

A process name by itself does not tell us whether something is malicious.

For example:

```text
explorer.exe
      │
      └── powershell.exe
```

can be completely normal.

But:

```text
WINWORD.EXE
      │
      └── powershell.exe
```

can be suspicious because Microsoft Word spawning PowerShell is a behavior that deserves investigation.

The important question is:

> Why did this process start this other process?

---

# 🧪 Practical Investigation — PowerShell → Notepad

During the practical, PowerShell was opened normally through the Windows Start Menu.

Then Notepad was executed from PowerShell.

The process relationship was:

```text
explorer.exe
      │
      └── powershell.exe
              │
              └── notepad.exe
```

The Notepad process showed PowerShell as its parent.

Important information included:

```text
Image:
C:\Program Files\WindowsApps\Microsoft.WindowsNotepad...\Notepad\Notepad.exe
```

Parent:

```text
ParentImage:
C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe
```

User:

```text
DESKTOP-KO22MCC\Anisha
```

Integrity:

```text
Medium
```

Because this activity was intentionally performed during the lab and the process relationship made sense, it was classified as:

```text
NORMAL
```

This demonstrated that a process such as PowerShell should not automatically be classified as malicious.

---

# 🧪 Practical Investigation — PowerShell → CMD → Notepad

Another test produced the following process chain:

```text
powershell.exe
      │
      └── cmd.exe
              │
              └── notepad.exe
```

The CMD process had the command line:

```text
"C:\WINDOWS\system32\cmd.exe" /c notepad.exe
```

The Notepad process showed:

```text
ParentImage:
C:\Windows\System32\cmd.exe
```

and:

```text
ParentCommandLine:
"C:\WINDOWS\system32\cmd.exe" /c notepad.exe
```

This demonstrated why both:

```text
ParentImage
```

and:

```text
ParentCommandLine
```

are important during process investigation.

---

# 🌐 Event ID 3 — Network Connection

## What is Event ID 3?

Event ID 3 records network connections associated with processes.

It can help an analyst determine:

- Which process made the connection.
- Which user was involved.
- Which protocol was used.
- What source IP was used.
- What source port was used.
- What destination IP was contacted.
- What destination port was contacted.
- Whether the process initiated the connection.

---

# Important Event ID 3 Fields

## Image

The process responsible for the network connection.

Example:

```text
C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe
```

---

## Protocol

Example:

```text
tcp
```

---

## Initiated

Indicates whether the connection was initiated by the process.

Example:

```text
true
```

---

## SourceIp

The local source IP.

Example:

```text
10.0.2.15
```

---

## SourcePort

The local source port.

Example:

```text
61611
```

---

## DestinationIp

The remote destination IP.

Example:

```text
172.66.147.243
```

---

## DestinationPort

The remote destination port.

Example:

```text
443
```

---

## DestinationPortName

Example:

```text
https
```

---

# 🧪 Practical Investigation — Event ID 3

During the lab, PowerShell generated a network connection with:

```text
Image:
C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe

Protocol:
tcp

Initiated:
true

SourceIp:
10.0.2.15

SourcePort:
61611

DestinationIp:
172.66.147.243

DestinationPort:
443

DestinationPortName:
https
```

The process was:

```text
ProcessId:
428
```

This network activity was investigated together with the DNS activity associated with the same PowerShell process.

---

# Does Port 443 Mean Malicious?

No.

Port:

```text
443
```

is commonly used for HTTPS.

Therefore:

```text
PowerShell
    ↓
TCP/443
```

does not automatically mean malicious activity.

The analyst needs additional context.

Important questions include:

- Which process connected?
- Why did it connect?
- Which domain was queried?
- Which IP did the domain resolve to?
- What command line was used?
- Was a file created afterward?
- Was another process executed afterward?
- Does the destination make sense for the process?

---

# ⏹️ Event ID 5 — Process Termination

## What is Event ID 5?

Event ID 5 records process termination.

It can help establish the lifecycle of a process.

A simplified process lifecycle can look like:

```text
Event ID 1
Process Created
      │
      ▼
Process Activity
      │
      ├── Network
      ├── DNS
      ├── File
      └── Registry
      │
      ▼
Event ID 5
Process Terminated
```

---

# Event ID 5 Practical Lesson

During the practical, an expected Event ID 5 event was not available.

This demonstrated that:

> Sysmon telemetry depends on configuration.

Therefore:

```text
No Event ID 5
```

does not automatically mean:

```text
The process never terminated.
```

It means that the expected termination telemetry was not available in the collected Sysmon data.

This is an important SOC investigation principle:

> Missing telemetry is not automatically proof that an activity did not occur.

---

# 📁 Event ID 11 — File Created

## What is Event ID 11?

Event ID 11 records file creation.

It can help analysts identify:

- Newly created executables.
- Temporary files.
- Scripts.
- Dropped payloads.
- Files created by suspicious processes.

---

# Important Event ID 11 Fields

## Image

The process that created the file.

## TargetFilename

The file that was created.

## CreationUtcTime

The creation time of the file.

## User

The user associated with the activity.

---

# 🧪 Practical Investigation — Event ID 11

During the practical, PowerShell generated file creation events.

One example involved:

```text
Image:
C:\WINDOWS\System32\WindowsPowerShell\v1.0\powershell.exe
```

and:

```text
TargetFilename:
C:\Users\Anisha\AppData\Local\Temp\__PSScriptPolicyTest_....ps1
```

User:

```text
DESKTOP-KO22MCC\Anisha
```

Other Event ID 11 events were generated by legitimate Windows components such as Microsoft Edge WebView.

---

# Does File Creation Mean Malicious?

No.

File creation must be investigated in context.

For example:

```text
PowerShell
    ↓
Temporary .ps1 file
```

may be legitimate.

But:

```text
PowerShell
    ↓
Network Connection
    ↓
invoice.exe Created
    ↓
invoice.exe Executed
```

is significantly more suspicious.

The important questions are:

```text
Who created the file?
       ↓
Where was it created?
       ↓
Why was it created?
       ↓
What happened afterward?
       ↓
Was it executed?
```

---

# 📝 Event ID 13 — Registry Value Set

## What is Event ID 13?

Event ID 13 records registry value modifications.

Registry activity can be important during security investigations because attackers can abuse registry modifications for:

- Persistence
- Configuration changes
- Execution
- Security control modification

However, Windows itself performs many legitimate registry modifications.

Therefore:

> A registry modification is not automatically malicious.

---

# Important Event ID 13 Fields

## EventType

Example:

```text
SetValue
```

## Image

The process that modified the registry.

## ProcessId

The process responsible for the modification.

## ProcessGuid

The Process GUID associated with the activity.

## TargetObject

The registry key or value that was modified.

## Details

The value written to the registry.

## User

The account/security context responsible for the activity.

---

# 🧪 Practical Registry Test

A controlled registry key was created:

```text
HKCU:\Software\Sysmon-Day6-Test
```

The command used was:

```powershell
New-Item -Path "HKCU:\Software\Sysmon-Day6-Test" -Force
```

Then a registry value was created:

```powershell
New-ItemProperty -Path "HKCU:\Software\Sysmon-Day6-Test" -Name "TestValue" -Value "Day6-Lab" -PropertyType String -Force
```

The value was verified using:

```powershell
Get-ItemProperty -Path "HKCU:\Software\Sysmon-Day6-Test"
```

The result confirmed:

```text
TestValue : Day6-Lab
```

---

# Why Did the Event ID 13 Search Return Nothing?

The following command was used:

```powershell
Get-WinEvent -FilterHashtable @{LogName='Microsoft-Windows-Sysmon/Operational'; Id=13} -MaxEvents 50 |
Where-Object { $_.Message -match 'Sysmon-Day6-Test' } |
Select-Object TimeCreated, Message |
Format-List
```

It returned nothing.

However, a broader Event ID 13 query showed that Event ID 13 was being collected.

This demonstrated that:

```text
Registry Modification
        ↓
Sysmon Configuration
        ↓
Filtering / Rules
        ↓
Available Telemetry
```

Therefore, the controlled registry modification was not necessarily absent from the system.

It simply was not present in the Event ID 13 telemetry that was available for that search.

---

# 🧪 Real Event ID 13 Investigation — WMIADAP.exe

A real Event ID 13 event was observed involving:

```text
WMIADAP.exe
```

Image:

```text
C:\Windows\System32\wbem\WMIADAP.exe
```

Description:

```text
WMI Reverse Performance Adapter Maintenance Utility
```

Company:

```text
Microsoft Corporation
```

Command Line:

```text
wmiadap.exe /F /T /R
```

User:

```text
NT AUTHORITY\SYSTEM
```

Integrity Level:

```text
System
```

Parent:

```text
C:\Windows\System32\svchost.exe
```

Parent Command Line:

```text
C:\WINDOWS\system32\svchost.exe -k netsvcs -p -s Winmgmt
```

The registry activity was associated with WMI-related registry locations.

The activity appeared likely benign because:

- The executable was located in a legitimate Windows system directory.
- The company was Microsoft Corporation.
- It ran as SYSTEM.
- It had System integrity.
- The parent process was svchost.exe.
- The parent command line referenced the Winmgmt service.
- The registry activity was related to WMI.
- The process relationship was consistent with normal Windows activity.

---

# ⚠️ RuleName Does Not Equal Malicious

Some Event ID 13 events contained:

```text
RuleName:
Suspicious,ImageBeginWithBackslash
```

This does not automatically mean that the activity was malicious.

The RuleName identifies the Sysmon rule that caused the event to be logged.

It is not the final SOC verdict.

The analyst still needs to investigate:

```text
Process
   ↓
Parent Process
   ↓
Command Line
   ↓
User
   ↓
Registry Location
   ↓
Details
   ↓
Context
```

Therefore:

> A Sysmon rule name is not the same thing as a SOC analyst verdict.

---

# 🌐 Event ID 22 — DNS Query

## What is Event ID 22?

Event ID 22 records DNS queries made by processes.

It can help analysts determine:

- Which process made the query.
- Which domain was queried.
- Whether the query succeeded.
- Which IP addresses were returned.
- Which user was involved.

---

# Important Event ID 22 Fields

## ProcessGuid

The Process GUID of the process performing the DNS query.

## ProcessId

The Process ID.

## QueryName

The requested domain.

Example:

```text
example.com
```

## QueryStatus

The DNS query result/status.

Example:

```text
0
```

## QueryResults

The DNS records/IP addresses returned.

## Image

The process that performed the DNS query.

## User

The user associated with the process.

---

# 🧪 Practical Investigation — Event ID 22

During the lab, PowerShell generated DNS queries for:

```text
example.com
```

The returned addresses included:

```text
172.66.147.243
104.20.23.154
```

The responsible process was:

```text
C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe
```

Process ID:

```text
428
```

User:

```text
DESKTOP-KO22MCC\Anisha
```

---

# DNS Query Status

Multiple DNS events were observed.

Some had:

```text
QueryStatus:
0
```

with successful query results.

Another query attempt showed:

```text
QueryStatus:
1460
```

with:

```text
QueryResults:
-
```

This demonstrated that DNS telemetry can contain both successful and unsuccessful query attempts.

---

# Does a DNS Query Mean Malicious Activity?

No.

DNS is a normal part of Windows network activity.

For example:

```text
PowerShell
    ↓
DNS Query
    ↓
example.com
```

does not automatically indicate compromise.

The analyst needs to investigate the context.

---

# 🔗 DNS + Network Correlation

During the practical, DNS and network events could be correlated using the same process information.

For example:

```text
PowerShell
      │
      ├── Event ID 22
      │       │
      │       ▼
      │    DNS Query
      │       │
      │       ▼
      │    Resolved IP
      │
      └── Event ID 3
              │
              ▼
        Network Connection
```

This demonstrates why an analyst should not investigate Event ID 22 and Event ID 3 independently.

---

# 🔗 Process ID and Process GUID Correlation

Sysmon events can be correlated using:

```text
ProcessId
```

and:

```text
ProcessGuid
```

For example:

```text
Event ID 1
Process Created
      │
      ▼
ProcessGuid
      │
      ├───────────────┐
      ▼               ▼
Event ID 22        Event ID 3
DNS Query          Network Connection
```

Additional information should also be considered:

- Timestamp
- Image
- User
- Parent process
- Command line
- Process lifetime

This allows the analyst to connect activity belonging to the same process.

---

# 🧭 Complete Sysmon Investigation Workflow

My investigation workflow is:

```text
Identify Process
       │
       ▼
Identify Parent Process
       │
       ▼
Review Command Line
       │
       ▼
Identify User
       │
       ▼
Check Integrity Level
       │
       ▼
Check Process ID / Process GUID
       │
       ▼
Check Hashes
       │
       ▼
Check DNS Activity
       │
       ▼
Check Network Activity
       │
       ▼
Check File Creation
       │
       ▼
Check Registry Activity
       │
       ▼
Correlate Events
       │
       ▼
Build Timeline
       │
       ▼
Determine Context
       │
       ▼
Classify Activity
       │
       ├── Normal
       ├── Suspicious
       └── Malicious
```

---

# 🔍 Six Core Questions for Process Investigation

When investigating a process, I use these questions:

## 1. What is the process?

Example:

```text
powershell.exe
```

---

## 2. Who started it?

Check:

```text
ParentImage
ParentProcessId
ParentProcessGuid
```

---

## 3. Who is the publisher?

Check:

```text
Company
Description
Digital Signature
```

---

## 4. Is the executable trusted?

Check:

- File path
- Digital signature
- SHA256
- Hash reputation
- File location

---

## 5. How was it launched?

Check:

```text
CommandLine
ParentCommandLine
```

---

## 6. Does the behavior make sense?

Consider:

```text
User
Process
Parent
Command Line
Network
DNS
Files
Registry
Timeline
```

---

# 🟢 Normal vs 🟡 Suspicious vs 🔴 Malicious

## Normal

Example:

```text
explorer.exe
      │
      └── powershell.exe
              │
              └── notepad.exe
```

If this activity was intentionally performed by the user and the command line and process relationships are expected, it can be classified as normal.

---

# Suspicious

Example:

```text
WINWORD.EXE
      │
      └── powershell.exe
              │
              └── -WindowStyle Hidden
```

This should be investigated further.

It does not automatically prove malware, but the process relationship and command line increase suspicion.

---

# Malicious

A stronger malicious pattern could look like:

```text
WINWORD.EXE
      │
      ▼
powershell.exe
      │
      ├── Hidden
      ├── Encoded Command
      │
      ▼
DNS Query
      │
      ▼
External IP
      │
      ▼
Network Connection
      │
      ▼
Executable Created
      │
      ▼
Executable Executed
```

The important point is that the classification comes from the **combination of evidence**, not one individual event.

---

# 🚨 Full Attack-Like Investigation

A controlled attack-like scenario was analyzed during the practical.

The observed investigation chain was:

```text
WINWORD.EXE
      │
      ▼
powershell.exe
      │
      ├── -NoProfile
      ├── -WindowStyle Hidden
      └── -EncodedCommand
      │
      ▼
DNS Query
      │
      ▼
cdn-update-check.example
      │
      ▼
203.0.113.50
      │
      ▼
TCP Connection
      │
      ▼
Executable Created
      │
      ▼
invoice.exe
      │
      ▼
invoice.exe Executed
```

This was not treated as suspicious because of one event.

It became highly suspicious because multiple events formed a consistent execution chain.

---

# Initial Suspicion

The first major indicator was:

```text
WINWORD.EXE
      │
      └── powershell.exe
```

This became more suspicious because PowerShell was launched with:

```text
-NoProfile
-WindowStyle Hidden
-EncodedCommand
```

These parameters deserve attention because attackers can use PowerShell with hidden and encoded execution to conceal activity.

However:

> These parameters alone do not automatically prove malicious activity.

The surrounding context must be investigated.

---

# DNS Evidence

PowerShell then performed a DNS query for:

```text
cdn-update-check.example
```

The response returned:

```text
203.0.113.50
```

The DNS query alone was not enough to classify the activity as malicious.

However, it became significantly more important because it was associated with the suspicious PowerShell execution.

---

# Network Evidence

A network connection was then established using TCP.

The destination involved:

```text
203.0.113.50
```

and:

```text
Port 443
```

Again:

> TCP/443 alone does not prove malicious activity.

The significance came from the complete timeline and its relationship with the suspicious PowerShell process.

---

# File Creation Evidence

PowerShell subsequently created:

```text
invoice.exe
```

This added another stage to the execution chain.

The investigation therefore became:

```text
Suspicious PowerShell
        ↓
DNS Query
        ↓
Network Connection
        ↓
Executable Created
```

---

# Process Execution Evidence

The created executable was subsequently executed.

The chain became:

```text
PowerShell
      │
      ▼
invoice.exe Created
      │
      ▼
invoice.exe Executed
```

This substantially increased the confidence that the activity was not simply normal administrative behavior.

---

# Final Classification

The controlled scenario was classified as:

```text
CONFIRMED MALICIOUS
```

The classification was based on the combined evidence:

- Microsoft Word spawned PowerShell.
- PowerShell used hidden execution.
- PowerShell used an encoded command.
- PowerShell performed a DNS query.
- The DNS query resolved to an external IP.
- PowerShell established a network connection.
- PowerShell created an executable.
- The executable was subsequently executed.

The important lesson was:

> The final classification should be based on correlated endpoint evidence rather than a single Sysmon event.

---

# 🧩 MITRE ATT&CK Perspective

From a MITRE ATT&CK perspective, the investigation demonstrated behaviors associated with:

```text
Malicious Document
        ↓
PowerShell
        ↓
Encoded / Obfuscated Execution
        ↓
Network Communication
        ↓
File Creation
        ↓
Execution
```

The practical exercise helped connect raw Sysmon telemetry with attacker behavior.

The important SOC skill is not simply memorizing technique names, but recognizing suspicious behavior patterns and correlating the underlying telemetry.

---

# 🚨 Immediate SOC Response

If this were a real incident, the immediate response would be:

## 1. Isolate the Endpoint

The affected endpoint should be isolated from the network to reduce the possibility of:

- Additional command-and-control communication
- Payload downloads
- Lateral movement
- Further compromise

---

## 2. Preserve Evidence

Collect and preserve:

```text
Sysmon Logs
Windows Event Logs
PowerShell Logs
Process Information
Created Files
DNS Information
Network Indicators
Original Word Document
```

---

## 3. Investigate the Payload

Investigate:

```text
invoice.exe
```

Determine:

- What it does.
- Whether it creates additional processes.
- Whether it establishes persistence.
- Whether it communicates with external infrastructure.
- Whether it modifies the registry.
- Whether it attempts credential access.

---

## 4. Investigate the Original Document

Determine:

- Where the Word document came from.
- How it was delivered.
- Whether it arrived through email.
- Whether other users received it.
- Whether the same document exists on other endpoints.

---

## 5. Threat Hunt

Search across the environment for:

```text
cdn-update-check.example
203.0.113.50
invoice.exe
```

Also search for:

```text
WINWORD.EXE
    ↓
powershell.exe
```

and suspicious PowerShell command-line patterns.

---

# 🧠 Investigation Principles Learned

## Process Names Are Not Enough

A process name alone does not determine whether activity is malicious.

```text
powershell.exe
```

can be legitimate.

The context determines the risk.

---

## Parent Processes Matter

Compare:

```text
explorer.exe
      ↓
powershell.exe
```

with:

```text
WINWORD.EXE
      ↓
powershell.exe
```

The second relationship deserves significantly more investigation.

---

## Command Lines Matter

Command-line arguments can reveal how a process was executed.

Parameters such as:

```text
-EncodedCommand
-WindowStyle Hidden
-NoProfile
```

deserve attention.

However, they should not automatically be treated as proof of malware.

Their significance increases when combined with other suspicious behavior.

---

## Network Activity Requires Context

A network connection to:

```text
443
```

is not automatically malicious.

The analyst should identify:

- Process
- Destination
- Domain
- Command line
- User
- Timing
- Follow-up activity

---

## DNS Activity Requires Context

A DNS query is normal system activity.

The analyst should correlate:

```text
DNS Query
    ↓
Resolved IP
    ↓
Network Connection
    ↓
Process
```

---

## File Creation Requires Context

A file created by PowerShell is not automatically malicious.

Investigate:

```text
Who created it?
Where was it created?
Why was it created?
What happened afterward?
Was it executed?
```

---

## Registry Activity Requires Context

Windows processes can legitimately modify the registry.

Investigate:

```text
Process
    ↓
Registry Key
    ↓
Value
    ↓
User
    ↓
Parent Process
    ↓
Context
```

---

## Rule Names Are Not Verdicts

A Sysmon rule containing:

```text
Suspicious
```

does not automatically mean:

```text
Malicious
```

The analyst must investigate the actual event and its context.

---

## Missing Telemetry Is Important

If an expected event is not available:

```text
Missing Event
```

does not automatically mean:

```text
Activity Did Not Happen
```

The analyst must consider:

- Sysmon configuration
- Filtering
- Event collection
- Available telemetry
- Other evidence

---

# 🔗 Event Correlation

The strongest SOC investigations correlate multiple events.

A possible investigation chain is:

```text
Event ID 1
Process Creation
       │
       ▼
Event ID 22
DNS Query
       │
       ▼
Event ID 3
Network Connection
       │
       ▼
Event ID 11
File Created
       │
       ▼
Event ID 1
New Process Created
       │
       ▼
Event ID 13
Registry Modification
```

This creates a much stronger endpoint activity timeline.

---

# 🕒 Timeline Investigation

Instead of asking:

> Is this event malicious?

A better SOC question is:

> What happened before this event, what happened after it, and does the complete sequence make sense?

For example:

```text
09:00
User opens Word
       │
       ▼
09:00
Word starts PowerShell
       │
       ▼
09:00
PowerShell executes hidden encoded command
       │
       ▼
09:01
DNS Query
       │
       ▼
09:01
Network Connection
       │
       ▼
09:01
Executable Created
       │
       ▼
09:02
Executable Executed
```

The timeline provides much stronger evidence than any individual event.

---

# 🛠️ Practical Commands Used

## Query Sysmon Event ID 13

```powershell
Get-WinEvent -FilterHashtable @{LogName='Microsoft-Windows-Sysmon/Operational'; Id=13} -MaxEvents 10 |
Select-Object TimeCreated, Message |
Format-List
```

---

## Search for the Controlled Registry Test

```powershell
Get-WinEvent -FilterHashtable @{LogName='Microsoft-Windows-Sysmon/Operational'; Id=13} -MaxEvents 50 |
Where-Object { $_.Message -match 'Sysmon-Day6-Test' } |
Select-Object TimeCreated, Message |
Format-List
```

---

## Create the Test Registry Key

```powershell
New-Item -Path "HKCU:\Software\Sysmon-Day6-Test" -Force
```

---

## Create the Registry Value

```powershell
New-ItemProperty -Path "HKCU:\Software\Sysmon-Day6-Test" -Name "TestValue" -Value "Day6-Lab" -PropertyType String -Force
```

---

## Verify the Registry Value

```powershell
Get-ItemProperty -Path "HKCU:\Software\Sysmon-Day6-Test"
```

---

# ✅ Sysmon Investigation Checklist

When investigating Sysmon telemetry:

- [ ] Identify the process.
- [ ] Identify the parent process.
- [ ] Check the command line.
- [ ] Check the parent command line.
- [ ] Identify the user.
- [ ] Check the integrity level.
- [ ] Check the Process ID.
- [ ] Check the Process GUID.
- [ ] Check the parent Process ID/GUID.
- [ ] Check hashes.
- [ ] Investigate DNS activity.
- [ ] Investigate network activity.
- [ ] Investigate file creation.
- [ ] Investigate registry activity.
- [ ] Correlate timestamps.
- [ ] Build a process tree.
- [ ] Build an activity timeline.
- [ ] Check whether the behavior makes sense.
- [ ] Determine whether the activity is normal, suspicious, or malicious.
- [ ] Recommend the appropriate SOC response.

---

# 📚 What I Learned From the Practical Lab

The most important lesson from this module was that **Sysmon becomes significantly more useful when multiple events are correlated**.

I learned that:

- PowerShell is not automatically malicious.
- A suspicious parent process can significantly change the investigation.
- Parent-child relationships provide important context.
- Command-line arguments can reveal suspicious execution behavior.
- Network connections require contextual analysis.
- DNS activity can be correlated with network connections.
- File creation can reveal potential payload activity.
- Registry changes require contextual analysis.
- Process IDs and Process GUIDs help correlate events.
- Sysmon configuration determines what telemetry is available.
- A missing event does not automatically mean that the activity did not happen.
- A Sysmon rule name is not a final verdict.
- Port 443 is not automatically malicious.
- DNS queries are not automatically malicious.
- File creation is not automatically malicious.
- Registry modifications are not automatically malicious.
- Timeline reconstruction is more useful than isolated event analysis.
- A strong SOC investigation is based on evidence and context.

---

# 🔑 Key Takeaways

- Sysmon provides detailed Windows endpoint telemetry.
- Event ID 1 is fundamental for process investigations.
- Parent-child process relationships are extremely valuable.
- Command-line analysis is critical.
- Event ID 3 provides network visibility.
- Event ID 5 provides process termination information when collected.
- Event ID 11 provides file creation visibility.
- Event ID 13 provides registry modification visibility.
- Event ID 22 provides DNS visibility.
- Process IDs and Process GUIDs help correlate events.
- Sysmon configuration determines available telemetry.
- Individual events should not automatically determine the final classification.
- Context is more important than isolated indicators.
- Event correlation is one of the most important SOC investigation skills.
- Timeline reconstruction helps determine the actual sequence of activity.
- The final classification should be based on the complete evidence.

---

# 🎤 Interview Questions

1. What is Sysmon?
2. Why is Sysmon useful for SOC analysts?
3. Where does Sysmon store its logs?
4. What is Sysmon Event ID 1?
5. What information does Event ID 1 provide?
6. What is the difference between Image and ParentImage?
7. Why are parent-child process relationships important?
8. What is Sysmon Event ID 3?
9. What information does Event ID 3 provide?
10. Does a connection to port 443 mean malicious activity?
11. What is Sysmon Event ID 5?
12. Why might Event ID 5 not appear?
13. What is Sysmon Event ID 11?
14. Why is file creation important during an investigation?
15. Does file creation automatically mean malware?
16. What is Sysmon Event ID 13?
17. Why are registry modifications important?
18. Why might a controlled registry modification not appear in Sysmon?
19. What is Sysmon Event ID 22?
20. Why is DNS activity useful during threat investigations?
21. Does a DNS query automatically mean malicious activity?
22. What is the difference between ProcessId and ProcessGuid?
23. Why is command-line analysis important?
24. Why is the parent process important?
25. What does IntegrityLevel tell an analyst?
26. What are MD5, SHA256, and IMPHASH used for?
27. Does PowerShell automatically mean malware?
28. What makes Word spawning PowerShell suspicious?
29. Does a Sysmon rule named "Suspicious" automatically mean malware?
30. Does the absence of a Sysmon event prove that an activity never happened?
31. Why should analysts correlate DNS and network events?
32. Why should analysts correlate file creation with process creation?
33. How would you investigate Word spawning PowerShell?
34. How would you investigate PowerShell creating an executable?
35. What would be your immediate SOC response to confirmed malicious endpoint activity?
36. Why is event correlation important in SOC investigations?
37. Why is timeline reconstruction important?
38. How would you distinguish normal PowerShell activity from suspicious PowerShell activity?
39. What information would you collect after confirming endpoint compromise?
40. How would you investigate a suspicious process from start to finish?

---

# 🏁 Final Conclusion

Sysmon provides detailed endpoint telemetry that allows SOC analysts to move beyond basic event inspection and perform deeper Windows endpoint investigations.

The most important skill developed during this module was:

> **Event Correlation**

Instead of investigating one event in isolation:

```text
Process
```

the analyst should build a complete picture:

```text
Parent Process
      ↓
Process
      ↓
Command Line
      ↓
User
      ↓
Integrity Level
      ↓
DNS
      ↓
Network
      ↓
File
      ↓
Registry
      ↓
Additional Processes
      ↓
Timeline
```

The objective of a SOC investigation is not simply to identify a suspicious event.

The objective is to determine:

> **What happened, how it happened, what happened next, whether the behavior makes sense, and whether the complete evidence supports a Normal, Suspicious, or Malicious classification.**

This practical exercise helped me move from simply reading Windows events toward thinking like a SOC analyst: **identify the process, understand its context, correlate the evidence, reconstruct the timeline, and make an evidence-based security decision.**
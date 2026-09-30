# Case Study — Suspicious PowerShell Threat Hunt

## Case Overview

### Investigation Type

Suspicious PowerShell / Windows Threat Hunting

### Analyst Level

L1 SOC Analyst

### Investigation Objective

Determine whether the observed PowerShell activity represents normal administrative behavior or a suspicious execution chain requiring escalation.

---

# Case Study 1

## Initial Authentication Activity

The investigation began with multiple failed authentication attempts followed by a successful authentication.

```text
4625
   ↓
4625
   ↓
4625
   ↓
4624
```

This pattern was considered suspicious and worth investigating.

However, the authentication sequence alone was not treated as proof of compromise.

---

## Benign / Low-Priority Activity

The following activity was observed:

```text
explorer.exe
    ↓
powershell.exe
    ↓
Get-ComputerInfo
```

This was considered apparently benign based on the available evidence.

It was not strongly correlated with the later suspicious activity.

---

## Suspicious Process Execution

A more significant event was identified:

```text
WINWORD.EXE
    ↓
powershell.exe
```

The PowerShell command contained:

```text
-WindowStyle Hidden
-ExecutionPolicy Bypass
-EncodedCommand
```

The combination of the Office parent process and these PowerShell execution characteristics increased the investigation priority.

---

## PowerShell Script Block

Event ID 4104 showed:

```text
New-Object System.Net.WebClient
DownloadString()
IEX
```

The behavior indicated that PowerShell created a WebClient object, downloaded remote content, and executed the downloaded content.

---

## Network Activity

PowerShell subsequently established a connection to an external host.

This provided additional evidence supporting the suspicious PowerShell activity.

---

## File Creation

A file was created:

```text
C:\Users\admin\AppData\Local\Temp\update.exe
```

The creating process was:

```text
powershell.exe
```

---

## File Execution

The created executable was subsequently executed:

```text
powershell.exe
    ↓
update.exe
```

---

## Correlated Attack Chain

The complete suspicious chain was:

```text
WINWORD.EXE
    ↓
powershell.exe
    ↓
Hidden + ExecutionPolicy Bypass
    ↓
EncodedCommand
    ↓
Event ID 4104
    ↓
DownloadString + IEX
    ↓
External Network Connection
    ↓
update.exe Created
    ↓
update.exe Executed
```

---

## Strongest Correlation

The strongest evidence was the combination of:

1. Office application launching PowerShell
2. Hidden PowerShell execution
3. ExecutionPolicy Bypass
4. Encoded command
5. PowerShell Script Block showing remote content retrieval
6. External network connection
7. Executable file creation
8. Subsequent execution of the created file

The events occurred close together in time and formed a logical execution sequence.

---

## Final Assessment

### Classification

**Malicious**

### Confidence

**High**

### Reasoning

The classification was based on the combination of multiple correlated behaviors rather than a single indicator.

The strongest evidence was the progression from suspicious PowerShell execution to remote content retrieval, external network communication, file creation, and file execution.

---

# Case Study 2

## Initial Activity

A successful helpdesk logon was observed.

```text
4624
User: helpdesk
```

The event alone did not provide enough evidence to classify the activity as malicious.

Additional context would be required.

---

## Apparently Benign PowerShell Activity

The following activity was observed:

```text
services.exe
    ↓
powershell.exe
    ↓
Get-Service
```

This appeared consistent with administrative activity based on the available evidence.

---

## Internal Network Activity

PowerShell communicated with:

```text
10.10.10.10:443
```

Because the destination was internal, the activity appeared potentially legitimate, but internal traffic was not automatically considered safe.

The destination and expected administrative behavior would need to be validated.

---

## Investigation Pivot

A later event showed:

```text
EXCEL.EXE
    ↓
powershell.exe
```

with:

```text
-ExecutionPolicy Bypass
```

This increased the investigation priority.

---

## Strong Suspicious Activity

A later PowerShell process contained:

```text
-WindowStyle Hidden
-ExecutionPolicy Bypass
-EncodedCommand
```

Event ID 4104 then showed:

```text
DownloadString()
IEX()
```

PowerShell subsequently connected to an external host.

---

## File Activity

A suspicious executable was created:

```text
C:\Users\helpdesk\AppData\Local\Temp\svchost.exe
```

The file was subsequently executed.

---

## Suspicious Chain

```text
EXCEL.EXE
    ↓
PowerShell
    ↓
Hidden + ExecutionPolicy Bypass
    ↓
EncodedCommand
    ↓
DownloadString + IEX
    ↓
External Network Connection
    ↓
svchost.exe Created
    ↓
svchost.exe Executed
```

---

## Evidence

The following facts were directly supported by the telemetry:

* PowerShell established an external network connection.
* PowerShell created an executable file.
* The executable file was subsequently executed.

---

## Information Not Proven by the Available Logs

The logs alone did not establish:

* Who controlled the external server.
* Exactly what the executed executable did afterward.

Additional telemetry would be required for those conclusions.

---

## Final Assessment

### Classification

**Malicious**

### Confidence

**High**

### Escalation

The case should be escalated because multiple suspicious behaviors formed a closely timed and logically connected execution chain.

# Day 9 — Splunk Threat Hunting & Detection

## Objective

The objective of Day 9 was to move from reactive alert investigation toward proactive threat hunting using Windows telemetry and Splunk.

The focus was on identifying suspicious behavior, pivoting across related events, correlating evidence, reconstructing timelines, and determining whether activity should be escalated.

---

## 1. Threat Hunting

Threat hunting is the proactive search for suspicious activity instead of waiting for an alert.

The investigation process used during Day 9 was:

```text
Hypothesis
    ↓
Search
    ↓
Evidence
    ↓
Validation
    ↓
Correlation
    ↓
Conclusion
```

---

## 2. Suspicious PowerShell Hunting

PowerShell is a legitimate Windows administration tool, but certain execution patterns can require investigation.

Examples of suspicious characteristics include:

* `-ExecutionPolicy Bypass`
* `-WindowStyle Hidden`
* `-EncodedCommand`
* `Invoke-WebRequest`
* `DownloadString`
* `DownloadFile`
* `WebClient`
* `IEX`
* `Invoke-Expression`

Example Splunk search:

```spl
index=windows powershell.exe
```

A more focused search:

```spl
index=windows powershell.exe
| search "ExecutionPolicy Bypass"
```

---

## 3. Parent-Child Process Investigation

Process relationships provide important context.

Example:

```text
explorer.exe
    ↓
powershell.exe
```

can be normal.

A relationship such as:

```text
WINWORD.EXE
    ↓
powershell.exe
```

requires investigation, especially when combined with suspicious command-line parameters.

Important fields include:

* ParentImage
* Image
* CommandLine
* User
* Computer
* Process ID
* Parent Process ID
* Timestamp

---

## 4. PowerShell Event ID 4104

Event ID 4104 provides PowerShell Script Block Logging information.

It can reveal what PowerShell was actually attempting to execute.

Example search:

```spl
index=windows EventCode=4104
```

Useful investigation terms include:

```text
DownloadString
DownloadFile
WebClient
Invoke-WebRequest
IEX
Invoke-Expression
```

The key question is:

> What was PowerShell actually trying to do?

---

## 5. Sysmon Event ID 3 — Network Connections

Event ID 3 can provide network connection information.

Important fields include:

* Process
* Source host
* Destination
* Destination port
* User
* Timestamp

Example:

```spl
index=windows EventCode=3
```

A network connection should be investigated in context.

An internal connection is not automatically malicious or automatically legitimate.

---

## 6. Sysmon Event ID 11 — File Creation

Event ID 11 can show files created by processes.

Example:

```spl
index=windows EventCode=11
```

Important questions:

* Which process created the file?
* Which user created it?
* Where was the file created?
* What was the filename?
* When was it created?

---

## 7. Sysmon Event ID 1 — Process Creation

Event ID 1 provides process creation information.

Example:

```spl
index=windows EventCode=1
```

Important fields include:

* Image
* ParentImage
* CommandLine
* User
* Computer
* Timestamp

A useful investigation is to determine whether a file that was created later executed.

---

## 8. Windows Authentication Events

### Event ID 4624

Successful logon.

```spl
index=windows EventCode=4624
```

### Event ID 4625

Failed logon.

```spl
index=windows EventCode=4625
```

Multiple failed logons followed by a successful logon can be an investigation trigger, but this pattern alone does not prove compromise.

Additional context is required.

---

## 9. Timeline Reconstruction

Individual events become more useful when placed into chronological order.

Example:

```text
WINWORD.EXE
    ↓
PowerShell
    ↓
Suspicious command
    ↓
4104 Script Block
    ↓
Network connection
    ↓
File creation
    ↓
File execution
```

Timeline reconstruction helps determine whether events form a logical sequence.

---

## 10. Event Correlation

Events should not automatically be considered related.

Useful correlation factors include:

* Same host
* Same user
* Close timestamps
* Related process IDs
* Parent-child process relationships
* Related files
* Related network connections
* Logical behavioral sequence

Strong correlation example:

```text
WINWORD.EXE
    ↓
powershell.exe
    ↓
DownloadString()
    ↓
External connection
    ↓
update.exe created
    ↓
update.exe executed
```

---

## 11. Evidence vs Inference

### Evidence

Information directly supported by telemetry.

Example:

> PowerShell connected to an external IP.

### Inference

A conclusion based on available evidence.

Example:

> PowerShell may have downloaded a payload.

### Assumption

A conclusion without sufficient supporting evidence.

Example:

> The external server definitely belongs to an attacker.

SOC investigations should clearly separate these three.

---

## 12. Analyst Reasoning Framework

The investigation workflow used during Day 9 was:

```text
Alert
  ↓
Validate
  ↓
Collect Context
  ↓
Pivot
  ↓
Correlate
  ↓
Build Timeline
  ↓
Separate Evidence / Inference
  ↓
Determine Severity
  ↓
Close or Escalate
  ↓
Document
```

---

## 13. Key Lessons

* PowerShell is not automatically malicious.
* An external connection is not automatically malicious.
* An internal connection is not automatically legitimate.
* A suspicious event should be investigated in context.
* Parent-child process relationships provide valuable context.
* Event 4104 can reveal PowerShell behavior.
* File creation followed by file execution can strengthen an investigation.
* Multiple correlated events are stronger than a single suspicious indicator.
* Evidence should be separated from assumptions.
* A SOC analyst should explain why an alert is escalated or closed.

# Case 04 — Sysmon Process Investigation

## 🛡️ Case Overview

| Field | Details |
|---|---|
| Case ID | CASE-04-SYSMON-PROCESS-INVESTIGATION |
| Investigation Type | Windows Endpoint Investigation |
| Primary Tool | Sysmon |
| Primary Event | Event ID 1 — Process Creation |
| Supporting Events | Event ID 3 — Network Connection, Event ID 11 — File Creation, Event ID 22 — DNS Query |
| Environment | Windows VM |
| Investigation Approach | Event Correlation and Timeline Analysis |
| Final Classification | 🔴 Confirmed Malicious |

---

# 1. Investigation Objective

The objective of this case was to investigate suspicious Windows endpoint activity using Sysmon telemetry.

Instead of analyzing a single event in isolation, the investigation focused on correlating multiple Sysmon events to reconstruct the complete sequence of activity.

The investigation attempted to answer:

- What process started the suspicious activity?
- What was the parent-child process relationship?
- What command line was used?
- Was PowerShell being used normally or suspiciously?
- Did the process perform DNS queries?
- Did the process establish a network connection?
- Was a file created?
- Was the created file executed?
- What does the complete timeline tell us?
- Should the activity be classified as normal, suspicious, or malicious?

---

# 2. Investigation Methodology

The investigation followed a simple SOC workflow:

```text
Initial Event
     ↓
Process Identification
     ↓
Parent Process Analysis
     ↓
Command-Line Analysis
     ↓
DNS Investigation
     ↓
Network Investigation
     ↓
File Activity Investigation
     ↓
Process Execution Investigation
     ↓
Event Correlation
     ↓
Timeline Reconstruction
     ↓
Final Classification
     ↓
SOC Response
```

The main principle used throughout the investigation was:

> Individual events provide clues. Correlated events provide the story.

---

# 3. Initial Process Investigation

The first important concept investigated was the parent-child process relationship.

A normal process chain generated during the lab was:

```text
explorer.exe
    │
    └── powershell.exe
            │
            └── notepad.exe
```

This activity was intentionally generated from the Windows VM.

The PowerShell process was opened normally and Notepad was launched from PowerShell.

The activity was therefore classified as **normal** because:

- The activity was intentionally performed by the user.
- The parent-child relationship made sense.
- The processes were legitimate Windows applications.
- The command line matched the activity performed.

This demonstrated an important SOC principle:

> A process should not be considered malicious simply because of its name.

---

# 4. Parent Process Analysis

Parent processes provide context about how a process was started.

For example:

```text
explorer.exe
    │
    └── powershell.exe
```

is a common legitimate relationship.

Another controlled test generated:

```text
powershell.exe
    │
    └── cmd.exe
            │
            └── notepad.exe
```

The command line for the CMD process showed:

```text
"C:\WINDOWS\system32\cmd.exe" /c notepad.exe
```

The Notepad process showed CMD as its parent.

This demonstrated how Sysmon can reveal:

- Parent process
- Child process
- Process ID
- Parent Process ID
- Command line
- Parent command line
- Process GUID
- Parent Process GUID
- User
- Integrity level

These fields allow an analyst to reconstruct how a process was launched.

---

# 5. Suspicious Process Scenario

The main investigation involved a suspicious process chain in which a Microsoft Word document launched PowerShell.

The process relationship was:

```text
WINWORD.EXE
     │
     └── powershell.exe
```

This immediately required investigation.

PowerShell itself is a legitimate Windows component and is commonly used by administrators.

Therefore:

```text
powershell.exe
```

does not automatically mean malicious activity.

The important question was:

> Why did Microsoft Word start PowerShell, and what did PowerShell do afterward?

---

# 6. Suspicious PowerShell Command Line

The PowerShell command line contained suspicious execution parameters including:

```text
-NoProfile
-WindowStyle Hidden
-EncodedCommand
```

These parameters increased the level of suspicion.

### `-NoProfile`

Starts PowerShell without loading the user's PowerShell profile.

### `-WindowStyle Hidden`

Allows PowerShell to run without displaying the normal visible PowerShell window.

### `-EncodedCommand`

Allows a command to be provided in encoded form.

The important observation was not any single parameter by itself, but the combination:

```text
WINWORD.EXE
     ↓
PowerShell
     ↓
Hidden Execution
     ↓
Encoded Command
```

At this stage, the activity was considered **highly suspicious**, but additional evidence was required before making the final classification.

---

# 7. Sysmon Event ID 1 — Process Creation

Sysmon Event ID 1 records process creation.

The most useful fields during this investigation were:

```text
Image
ParentImage
CommandLine
ParentCommandLine
ProcessId
ParentProcessId
ProcessGuid
ParentProcessGuid
User
IntegrityLevel
Hashes
```

The important process relationship was:

```text
WINWORD.EXE
     │
     └── powershell.exe
```

The parent process and command line were especially important because they provided context about how PowerShell was launched.

---

# 8. Sysmon Event ID 22 — DNS Query

The PowerShell process subsequently performed a DNS query.

The investigated domain was:

```text
cdn-update-check.example
```

The DNS response returned:

```text
203.0.113.50
```

The relationship was:

```text
powershell.exe
     │
     ▼
DNS Query
     │
     ▼
cdn-update-check.example
     │
     ▼
203.0.113.50
```

## Analysis

A DNS query by itself is not malicious.

Legitimate applications perform DNS queries constantly.

Therefore, Event ID 22 alone was not enough to classify the activity.

However, the DNS event became more significant because it originated from a PowerShell process that had already demonstrated suspicious behavior.

---

# 9. Sysmon Event ID 3 — Network Connection

After the DNS activity, a network connection was identified.

The connection used:

```text
Protocol: TCP
Destination Port: 443
```

The investigated destination was:

```text
203.0.113.50
```

The activity could therefore be represented as:

```text
PowerShell
     │
     ▼
DNS Query
     │
     ▼
203.0.113.50
     │
     ▼
TCP / 443
```

## Analysis

TCP port 443 is commonly used for HTTPS and is not automatically malicious.

Therefore, Event ID 3 alone did not prove malicious activity.

The important question was:

> Which process made the connection, why did it make the connection, and what happened before and after it?

In this case, the network activity was significant because it occurred after the suspicious Word → PowerShell execution chain and DNS activity.

---

# 10. Sysmon Event ID 11 — File Creation

The next important evidence was file creation.

The suspicious PowerShell activity resulted in the creation of:

```text
invoice.exe
```

The investigation chain now became:

```text
Suspicious PowerShell
       │
       ▼
DNS Query
       │
       ▼
Network Connection
       │
       ▼
invoice.exe Created
```

This significantly increased the level of suspicion.

File creation alone does not automatically indicate malware.

However, an executable being created by a suspicious PowerShell process after network activity requires further investigation.

---

# 11. Second Sysmon Event ID 1 — Payload Execution

The newly created:

```text
invoice.exe
```

was subsequently executed.

This was an important escalation in the investigation.

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

The fact that the executable was both **created and subsequently executed** provided much stronger evidence than file creation alone.

---

# 12. Complete Attack Chain

After correlating the Sysmon events, the activity could be reconstructed as:

```text
                 WINWORD.EXE
                      │
                      ▼
                powershell.exe
                      │
              ┌───────┴────────┐
              │                │
              ▼                ▼
     Encoded Command     Hidden Execution
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
          TCP / 443
              │
              ▼
      invoice.exe Created
              │
              ▼
      invoice.exe Executed
```

This complete chain was significantly more suspicious than any individual event.

---

# 13. Timeline Reconstruction

The investigation was reconstructed into the following sequence:

```text
1. User opens a Word document.
        ↓
2. WINWORD.EXE starts PowerShell.
        ↓
3. PowerShell executes a hidden encoded command.
        ↓
4. PowerShell performs a DNS query.
        ↓
5. cdn-update-check.example resolves to 203.0.113.50.
        ↓
6. PowerShell establishes a TCP connection to port 443.
        ↓
7. PowerShell creates invoice.exe.
        ↓
8. invoice.exe is executed.
```

This timeline provided the strongest evidence for the final classification.

---

# 14. Evidence Analysis

## Evidence 1 — WINWORD.EXE → PowerShell

```text
WINWORD.EXE
     ↓
powershell.exe
```

### Assessment

**Suspicious**

### Reason

A Microsoft Word process launching PowerShell requires investigation, especially when additional suspicious PowerShell parameters are present.

---

## Evidence 2 — Encoded PowerShell Command

```text
-EncodedCommand
```

### Assessment

**Suspicious**

### Reason

Encoded commands can make the actual PowerShell command less immediately visible during investigation.

---

## Evidence 3 — Hidden PowerShell Execution

```text
-WindowStyle Hidden
```

### Assessment

**Suspicious**

### Reason

Hidden execution can reduce visibility to the user and can be abused by malicious scripts.

---

## Evidence 4 — DNS Query

```text
cdn-update-check.example
```

### Assessment

**Suspicious in context**

### Reason

DNS queries are normal, but this query originated from a PowerShell process that was already exhibiting suspicious behavior.

---

## Evidence 5 — Network Connection

```text
203.0.113.50:443
```

### Assessment

**Suspicious in context**

### Reason

TCP/443 is normal by itself, but the connection was part of the larger suspicious process and DNS activity.

---

## Evidence 6 — Executable Creation

```text
invoice.exe
```

### Assessment

**Highly Suspicious**

### Reason

A suspicious PowerShell process created an executable following network activity.

---

## Evidence 7 — Executable Execution

```text
invoice.exe
```

### Assessment

**Malicious**

### Reason

The newly created executable was subsequently executed, completing the suspicious execution chain.

---

# 15. Why Event Correlation Matters

None of the individual events automatically proves compromise.

For example:

```text
PowerShell
```

can be legitimate.

A:

```text
DNS Query
```

can be legitimate.

A:

```text
TCP/443 Connection
```

can be legitimate.

A:

```text
File Creation
```

can be legitimate.

However, when the events are correlated:

```text
WINWORD.EXE
     ↓
PowerShell
     ↓
Encoded Command
     ↓
Hidden Execution
     ↓
DNS Query
     ↓
External IP
     ↓
TCP/443
     ↓
invoice.exe Created
     ↓
invoice.exe Executed
```

the overall behavior becomes highly suspicious and ultimately malicious.

This was one of the most important lessons from the investigation:

> **Individual events provide clues. Correlated events provide the story.**

---

# 16. Initial vs Final Classification

### Initial Classification

The first PowerShell event was classified as:

```text
SUSPICIOUS
```

because of:

- Word → PowerShell relationship
- Encoded PowerShell command
- Hidden execution

At this point, further investigation was required.

### After DNS Evidence

Confidence increased because the suspicious PowerShell process performed a DNS query.

### After Network Evidence

Confidence increased further because the same process established external network communication.

### After File Creation

The activity became highly suspicious because an executable was created.

### After Payload Execution

The newly created executable was executed.

The final classification became:

```text
🔴 CONFIRMED MALICIOUS
```

---

# 17. MITRE ATT&CK Perspective

The behavior observed in the investigation can be associated with several MITRE ATT&CK concepts.

## User Execution

The scenario began when the user opened a Word document.

```text
User
  ↓
Word Document
```

## PowerShell

PowerShell was used as the execution mechanism.

```text
WINWORD.EXE
     ↓
powershell.exe
```

## Obfuscated / Encoded Execution

The PowerShell command included:

```text
-EncodedCommand
```

This is consistent with an attempt to make command contents less immediately readable.

## Network Communication

PowerShell performed DNS resolution and subsequently established a network connection.

```text
PowerShell
     ↓
DNS
     ↓
External IP
     ↓
TCP/443
```

## Payload Execution

The process created and executed:

```text
invoice.exe
```

The overall behavior therefore followed:

```text
Initial Execution
      ↓
PowerShell
      ↓
Network Communication
      ↓
Payload Creation
      ↓
Payload Execution
```

---

# 18. Immediate SOC Response

If this were a real production incident, the immediate response would be:

## 1. Isolate the Endpoint

Isolate the affected endpoint from the network.

The purpose is to reduce the possibility of:

- Further command-and-control communication
- Additional payload downloads
- Lateral movement
- Additional compromise

## 2. Preserve Evidence

Preserve relevant evidence including:

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

## 3. Investigate invoice.exe

Investigate:

```text
invoice.exe
```

including:

- File hash
- File location
- Digital signature
- Parent process
- Child processes
- Network connections
- Registry activity
- Persistence mechanisms
- Additional files
- Security detections

## 4. Investigate the Word Document

Determine:

- Where the document originated.
- How it was delivered.
- Whether it came through email.
- Whether other users received the same document.
- Whether the same document exists elsewhere.

## 5. Threat Hunt

Search the environment for:

```text
cdn-update-check.example
203.0.113.50
invoice.exe
```

Also search for suspicious:

```text
WINWORD.EXE → powershell.exe
```

relationships and suspicious PowerShell command-line patterns.

---

# 19. Investigation Limitations

During the practical investigation, not every expected Sysmon event was available.

### Event ID 5

Event ID 5 was not available during the practical.

This demonstrated that event availability depends on Sysmon configuration and the telemetry generated by the system.

### Event ID 13

A controlled registry modification was created during the lab:

```text
HKCU:\Software\Sysmon-Day6-Test
```

with:

```text
TestValue = Day6-Lab
```

The registry modification was successfully created and verified locally.

However, the targeted Event ID 13 search for the test registry key did not return the expected event.

A broader Event ID 13 search did show that Sysmon was recording registry value set activity.

This demonstrated an important investigation lesson:

> Missing telemetry does not automatically mean that an activity never happened.

The analyst must consider Sysmon configuration, filtering, timing, and available telemetry.

---

# 20. Key Lessons Learned

## Process Names Are Not Enough

`powershell.exe` is a legitimate Windows process.

The surrounding context determines whether its execution is suspicious.

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

The second relationship requires significantly more investigation.

## Command Lines Matter

Command-line parameters can reveal:

- Encoded commands
- Hidden execution
- Scripts
- Unusual parameters
- Suspicious execution methods

## DNS Requires Context

A DNS query is not automatically malicious.

It becomes more important when associated with a suspicious process and followed by network communication.

## Network Connections Require Context

TCP/443 is commonly legitimate.

The process making the connection, destination, timing, and surrounding activity are what determine its significance.

## File Creation Requires Context

A newly created file is not automatically malicious.

However:

```text
Suspicious Process
      ↓
Executable Created
      ↓
Executable Executed
```

is significantly more concerning.

## Event Correlation Is Critical

The most important lesson from this case was:

> **Do not investigate events in isolation. Correlate them and reconstruct the timeline.**

---

# 21. Final SOC Assessment

The complete investigation produced the following chain:

```text
WINWORD.EXE
     ↓
powershell.exe
     ↓
Encoded + Hidden Command
     ↓
DNS Query
     ↓
cdn-update-check.example
     ↓
203.0.113.50
     ↓
TCP/443
     ↓
invoice.exe Created
     ↓
invoice.exe Executed
```

The activity was classified as:

# 🔴 CONFIRMED MALICIOUS

The classification was based on the **correlation of multiple Sysmon events**, rather than any individual event.

---

# 22. Final SOC Response

```text
Alert
  ↓
Initial Triage
  ↓
Process Investigation
  ↓
Parent-Child Analysis
  ↓
Command-Line Analysis
  ↓
DNS Investigation
  ↓
Network Investigation
  ↓
File Creation Investigation
  ↓
Payload Execution
  ↓
Event Correlation
  ↓
Timeline Reconstruction
  ↓
CONFIRMED MALICIOUS
  ↓
ISOLATE ENDPOINT
  ↓
PRESERVE EVIDENCE
  ↓
INVESTIGATE PAYLOAD
  ↓
THREAT HUNT
```

---

# 23. Conclusion

This case demonstrated how Sysmon can be used to investigate endpoint activity from the initial process creation through network communication and payload execution.

The investigation began with:

```text
WINWORD.EXE
     ↓
powershell.exe
```

and developed into:

```text
Encoded Command
     ↓
Hidden Execution
     ↓
DNS Query
     ↓
Network Connection
     ↓
File Creation
     ↓
Payload Execution
```

The final determination was based on the correlation of:

- Process creation
- Parent-child relationships
- Command-line arguments
- DNS activity
- Network activity
- File creation
- Subsequent process execution
- Timeline analysis

The main SOC lesson from this investigation is:

> **Do not ask whether one event is malicious. Ask what the events tell you when they are connected together.**

Sysmon provided the telemetry.

Process relationships provided the context.

Command lines provided execution details.

DNS provided infrastructure information.

Network events provided communication evidence.

File creation showed payload activity.

Process creation showed execution.

Timeline reconstruction connected the evidence into one investigation.

This is the mindset required for effective endpoint detection and SOC analysis.
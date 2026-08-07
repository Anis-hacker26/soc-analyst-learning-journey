# 🚨 SOC Case File #03 – Suspicious Process Investigation

## Case Overview

An employee reported that their computer became unusually slow after opening an invoice document.

Using Process Explorer, the SOC analyst investigated the running processes to determine whether the activity was legitimate or malicious.

---

# Incident Summary

Process Explorer showed Microsoft Word spawning PowerShell, which then launched an unknown executable named `updater.exe`.

Further investigation revealed suspicious PowerShell command-line arguments, an unverified executable located in the user's temporary directory, and a high VirusTotal detection score.

These findings confirmed that the endpoint had been compromised.

---

# Initial Alert

Employee Report:

> "My computer became slow after opening an invoice document."

---

# Initial Assessment

Classification:

🟡 Suspicious

Reason:

- Microsoft Word spawned PowerShell.
- Suspicious PowerShell command line.
- Unknown child process.

---

# Investigation

## Step 1 – Process Tree Analysis

```
WINWORD.EXE
      │
      └── powershell.exe
              │
              └── updater.exe
```

Observation:

Microsoft Word does not typically launch PowerShell during normal document usage.

---

## Step 2 – PowerShell Investigation

Parent:

```
WINWORD.EXE
```

Command Line:

```
ExecutionPolicy Bypass

EncodedCommand
```

Observation:

PowerShell was launched using suspicious command-line arguments.

---

## Step 3 – updater.exe Investigation

Location

```
C:\Users\Anisha\AppData\Local\Temp\
```

Company

```
Unknown
```

Verified

```
Unable to Verify
```

Observation:

The executable appeared to be untrusted.

---

## Step 4 – VirusTotal

Detection

```
58 / 72
```

Observation

Multiple antivirus vendors identified the executable as malicious.

Confidence increased significantly.

---

# Investigation Timeline

```
Employee opens invoice

↓

WINWORD.EXE starts

↓

PowerShell launched

↓

Encoded command executes

↓

updater.exe created

↓

VirusTotal identifies malware

↓

Endpoint isolated
```

---

# Evidence Collected

| Evidence | Observation |
|----------|-------------|
| Parent Process | WINWORD.EXE |
| Child Process | powershell.exe |
| Grandchild Process | updater.exe |
| Company | Unknown |
| Signature | Unverified |
| VirusTotal | 58/72 Detection |

---

# Root Cause

The likely root cause was a malicious Microsoft Word document that abused PowerShell to execute an unknown payload.

---

# MITRE ATT&CK Mapping

| Tactic | Technique |
|---------|-----------|
| Initial Access | Phishing |
| Execution | PowerShell |
| Defense Evasion | Encoded Commands |
| Command and Control | PowerShell |
| Malware Execution | User Execution |

---

# Containment

- Isolate the affected endpoint.
- Preserve evidence.
- Block the malicious file hash.
- Notify the Incident Response team.
- Begin malware remediation.

---

# Lessons Learned

- Parent-child relationships reveal attack chains.
- Context determines whether a process is suspicious.
- Verified signatures should always be checked.
- VirusTotal provides valuable threat intelligence.
- Investigation confidence increases as evidence is collected.

---

# Analyst Reflection

Initially, the process appeared suspicious because Microsoft Word launched PowerShell. As additional evidence such as the encoded command, unverified executable, temporary file location, and VirusTotal detection became available, confidence increased until the incident was confirmed as malicious.

---

# Final Assessment

🔴 Confirmed Malicious

Confidence Level:

High

---

# Skills Practiced

- Process Explorer
- Process Tree Analysis
- Parent-Child Investigation
- Command Line Analysis
- Digital Signature Verification
- VirusTotal Investigation
- Evidence-Based Decision Making

---

# Interview Questions

1. Why is WINWORD.EXE spawning PowerShell suspicious?
2. What information does Process Explorer provide that Task Manager does not?
3. Why should analysts inspect command-line arguments?
4. Why is an executable running from the Temp folder suspicious?
5. What role does VirusTotal play during investigations?
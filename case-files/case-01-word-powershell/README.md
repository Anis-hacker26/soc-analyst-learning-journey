# 🚨 SOC Case File #01 – Microsoft Word Spawned PowerShell

## Case Overview

This investigation simulates a phishing attack where an employee opens a Microsoft Word document received through email. The document triggers PowerShell execution, which downloads and executes a malicious payload, resulting in a confirmed malware infection.

---

# Incident Summary

An employee reported that after opening a Microsoft Word document received via email, a PowerShell window briefly appeared and disappeared. Shortly afterward, the system became noticeably slow.

Initial investigation revealed that Microsoft Word spawned PowerShell, which executed an encoded command, connected to an external IP address, downloaded a malicious executable, and launched it. Windows Defender later detected **Trojan:Win32/AgentTesla**, confirming the compromise.

---

# Initial Alert

**User Report**

> "I opened a Microsoft Word document from an email. A PowerShell window flashed for a second and then disappeared. After that, my computer became slow."

---

# Investigation Process

## Step 1 – Initial Assessment

Initial Classification:

🟡 **Suspicious Activity**

Reason:

- Microsoft Word unexpectedly launched PowerShell.
- PowerShell window appeared without user interaction.
- No antivirus alert was initially generated.

---

## Step 2 – Process Investigation

### Sysmon Event ID 1

**Parent Process**

```
WINWORD.EXE
```

**Child Process**

```
powershell.exe
```

### Command Line

```
ExecutionPolicy Bypass
EncodedCommand
```

### Observation

Microsoft Word spawning PowerShell is uncommon and required further investigation.

---

## Step 3 – Network Activity

### Sysmon Event ID 3

PowerShell initiated an outbound connection.

Destination Port:

```
443
```

Destination IP:

```
185.221.44.17
```

### Observation

Port 443 is commonly used for HTTPS traffic and is not inherently malicious. However, when combined with the previous findings, this increased the confidence that malicious activity was occurring.

---

## Step 4 – File Creation

### Sysmon Event ID 11

PowerShell created:

```
invoice.exe
```

Location:

```
C:\Users\Anisha\AppData\Local\Temp\
```

---

## Step 5 – Process Execution

PowerShell launched:

```
invoice.exe
```

This indicated successful execution of the downloaded payload.

---

## Step 6 – Malware Detection

Windows Defender generated an alert:

```
Trojan:Win32/AgentTesla
```

This confirmed that the endpoint had been compromised.

---

# Investigation Timeline

```
Employee receives phishing email
        │
        ▼
Employee opens Word document
        │
        ▼
WINWORD.EXE starts
        │
        ▼
WINWORD.EXE launches PowerShell
(Sysmon Event ID 1)
        │
        ▼
PowerShell executes EncodedCommand
        │
        ▼
PowerShell connects to external IP
(Sysmon Event ID 3)
        │
        ▼
PowerShell downloads invoice.exe
(Sysmon Event ID 11)
        │
        ▼
invoice.exe executes
        │
        ▼
Windows Defender detects Trojan:Win32/AgentTesla
        │
        ▼
SOC isolates endpoint
```

---

# Evidence Collected

| Evidence | Observation |
|-----------|-------------|
| Parent Process | WINWORD.EXE |
| Child Process | powershell.exe |
| Command Line | ExecutionPolicy Bypass, EncodedCommand |
| Network Activity | Outbound connection to external IP |
| File Creation | invoice.exe |
| Malware Detection | Trojan:Win32/AgentTesla |

---

# Root Cause

The compromise was likely initiated when the employee opened a malicious Microsoft Word document received via email. The document launched PowerShell, which downloaded and executed a malicious payload.

---

# MITRE ATT&CK Mapping

| Tactic | Technique |
|----------|------------------------------|
| Initial Access | Phishing |
| Execution | PowerShell |
| Defense Evasion | Execution Policy Bypass |
| Command and Control | Outbound HTTPS Connection |
| Payload Delivery | Download and Execute Payload |

---

# Containment

- Isolated the affected endpoint.
- Prevented further communication with the external server.
- Preserved logs for investigation.
- Verified Windows Defender detection.
- Initiated malware removal procedures.

---

# Lessons Learned

- Parent-child process relationships are critical during investigations.
- PowerShell is not malicious by itself, but its context determines the level of risk.
- Multiple related events provide stronger evidence than a single event.
- Security conclusions should always be based on collected evidence rather than assumptions.
- Early endpoint isolation helps reduce the impact of confirmed compromises.

---

# Final Classification

🔴 **Confirmed Malicious Activity**

Confidence Level:

**High**

Reason:

The investigation identified malicious PowerShell execution, external network communication, payload download, payload execution, and Windows Defender confirmation of malware.

---

# Skills Practiced

- Windows Event Viewer
- Sysmon Analysis
- Process Tree Analysis
- Network Investigation
- Incident Timeline Creation
- Evidence Collection
- Root Cause Analysis
- SOC Investigation Methodology

---

# Interview Questions

1. Why is Microsoft Word spawning PowerShell considered suspicious?
2. Why does PowerShell using port 443 not automatically indicate malicious activity?
3. What information does Sysmon Event ID 1 provide?
4. Why is the Parent Process important during an investigation?
5. At what point did this incident become a confirmed security incident?
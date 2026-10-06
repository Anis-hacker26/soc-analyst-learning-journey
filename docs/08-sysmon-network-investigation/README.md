# 🔐 Day 10 — Sysmon Network Connection Investigation

## Objective

The objective of Day 10 was to develop practical skills for investigating Windows network connections using **Sysmon Event ID 3**.

The focus was not simply identifying network connections, but understanding their context by correlating:

- Process creation
- Network connections
- PowerShell Script Block Logging
- File creation
- Process execution
- User and host context
- Timeline relationships

The goal was to determine whether activity should be **closed, monitored, or escalated**.

---

## 1. Sysmon Event ID 3

**Sysmon Event ID 3 represents a network connection.**

It can provide information such as:

- Source host
- User
- Process responsible for the connection
- Destination IP
- Destination port
- Timestamp

A network connection by itself does not prove malicious activity.

The analyst must investigate the surrounding context.

---

## 2. Network Investigation Questions

For each network connection, I practiced asking:

### Who?

Which user and process initiated the connection?

### What?

What process made the connection?

### Where?

What destination IP or host was contacted?

### Which port?

Which destination port was used?

### When?

When did the connection occur?

### Why?

Why did this process need to communicate with that destination?

---

## 3. Internal vs External Connections

An important lesson from Day 10 was:

> **Internal does not automatically mean safe, and external does not automatically mean malicious.**

For an internal destination, I would investigate:

- What system owns the destination?
- What service is running?
- Is the communication expected?
- Is it normal for this user and host?

For an external destination, I would investigate:

- Who controls the destination?
- Why is the endpoint communicating with it?
- What process initiated the connection?
- What happened immediately before and after the connection?

---

## 4. Investigation Workflow

The investigation workflow practiced during Day 10 was:

```text
Network Connection
        ↓
Identify Process
        ↓
Identify User
        ↓
Identify Destination
        ↓
Check Port
        ↓
Review Previous Events
        ↓
Review Following Events
        ↓
Correlate Events
        ↓
Build Timeline
        ↓
Separate Evidence from Unknowns
        ↓
Classify Activity
        ↓
Close / Monitor / Escalate
```

---

## 5. Important Correlation

A single network connection may not be enough to classify an event.

A stronger investigation can look like:

```text
Suspicious Process
      ↓
PowerShell
      ↓
External Network Connection
      ↓
Payload Download
      ↓
File Creation
      ↓
File Execution
```

The combination of multiple related events provides stronger evidence than any individual event.

---

## 6. PowerShell Investigation

PowerShell activity was investigated using:

- Sysmon Event ID 1 — Process Creation
- Sysmon Event ID 3 — Network Connection
- Sysmon Event ID 11 — File Creation
- Event ID 4104 — PowerShell Script Block Logging

Suspicious PowerShell characteristics included:

```text
-WindowStyle Hidden
-ExecutionPolicy Bypass
-EncodedCommand
```

These indicators should not automatically be treated as proof of compromise individually.

Their significance increases when they correlate with other suspicious behavior.

---

## 7. Evidence vs Inference vs Unknown

### Evidence

Information directly supported by telemetry.

Example:

> PowerShell connected to `198.51.100.25:80`.

### Inference

A conclusion supported by multiple pieces of evidence.

Example:

> PowerShell retrieved external content.

### Unknown

Something that cannot yet be established from the available telemetry.

Example:

> What the downloaded payload did after execution.

Keeping these categories separate helps prevent overconfident conclusions.

---

## 8. SOC Decision Framework

After investigation, the analyst determines the appropriate action.

### Close

Use when the activity is confirmed legitimate or expected.

### Monitor

Use when activity is unusual or unclear but there is insufficient evidence of malicious behavior.

### Escalate

Use when correlated evidence indicates likely or confirmed malicious activity.

A high-confidence malicious chain may require escalation for:

- Further investigation
- Containment
- Scope determination
- Persistence analysis
- Impact assessment

---

## 9. Key Analyst Questions

During investigations, I practiced asking:

- Who initiated the activity?
- What process was involved?
- What happened before the connection?
- What happened after the connection?
- Is the destination expected?
- Is the process expected?
- Was content downloaded?
- Was a file created?
- Was a process executed?
- Is there evidence of persistence?
- What is proven?
- What is inferred?
- What remains unknown?

---

## 10. Key Takeaways

The major lessons from Day 10 were:

1. A network connection alone does not prove malicious activity.
2. Sysmon Event ID 3 is valuable as an investigation pivot.
3. Internal destinations must still be validated.
4. External destinations require contextual investigation rather than automatic classification.
5. Process-to-network relationships are important.
6. PowerShell activity should be correlated with surrounding telemetry.
7. Timeline reconstruction helps establish relationships between events.
8. File creation followed by execution is significantly more concerning than file creation alone.
9. Evidence, inference, and unknowns should be kept separate.
10. SOC analysts must determine whether to close, monitor, or escalate an investigation.

---

## Day 10 Outcome

By the end of Day 10, I practiced investigating network connections from a SOC analyst perspective and learned how to correlate network activity with process execution, PowerShell activity, file creation, and follow-on behavior.

The main lesson was:

> **A network connection is only one piece of the story. The analyst's job is to correlate the surrounding evidence and determine what the activity actually represents.**
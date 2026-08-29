# Case 06 — Splunk SIEM Investigation & Event Correlation

## Case Type

**SOC Investigation / SIEM Event Correlation**

## Challenge Day

**Day 8 — Splunk & SIEM Investigation**

## Investigation Level

**L1 SOC Analyst**

## Case Status

**Completed**

## Environment

* SIEM: Splunk
* Operating System Telemetry: Windows
* Endpoint Telemetry: Sysmon
* Security Telemetry: Windows Event Logs
* Investigation Focus: Authentication, PowerShell, Process Creation, Network Activity, File Activity, Event Correlation

---

# 1. Executive Summary

This case file documents two controlled SOC investigation exercises completed as part of the Day 8 Splunk and SIEM investigation module.

The primary objective was to develop the ability to move from individual security events toward a complete, evidence-based attack sequence.

The investigations focused on:

1. **The Unexpected Administrator**
2. **Noise vs. the Real Attack Chain**

The first case focused on identifying suspicious authentication followed by PowerShell-based activity and determining whether the sequence represented malicious behavior.

The second case introduced benign activity alongside malicious activity. The objective was to determine which events were actually related to the attack and which events represented legitimate activity or investigation noise.

The second case was particularly important because real SOC investigations rarely consist entirely of malicious events. Analysts must determine which events belong to the same behavioral chain rather than assuming that every event occurring on the same endpoint is related.

The investigation methodology developed during these cases was:

```text
Alert / Initial Indicator
        ↓
Identify Host
        ↓
Identify User
        ↓
Establish Timeline
        ↓
Inspect Individual Events
        ↓
Analyze Process Relationships
        ↓
Correlate Authentication
        ↓
Correlate PowerShell
        ↓
Correlate Network Activity
        ↓
Correlate File Activity
        ↓
Separate Noise
        ↓
Build Attack Chain
        ↓
Assess Evidence
        ↓
Classify Activity
        ↓
Assign Confidence
```

---

# 2. Investigation Objectives

The objectives of these exercises were to demonstrate the following SOC investigation capabilities:

* Investigate Windows authentication events
* Identify failed and successful authentication patterns
* Understand why authentication sequences can trigger investigation
* Investigate PowerShell activity
* Identify suspicious PowerShell execution parameters
* Understand PowerShell Script Block Logging
* Analyze parent-child process relationships
* Correlate process activity with network connections
* Correlate network activity with file creation
* Correlate file creation with subsequent execution
* Reconstruct a chronological attack sequence
* Distinguish an investigation trigger from confirmed attack evidence
* Separate benign activity from malicious activity
* Distinguish observed evidence from analyst inference
* Assign an appropriate classification
* Assign a confidence level based on the strength of available evidence

---

# 3. Investigation Methodology

The investigation was performed using an evidence-first approach.

The objective was not to label an individual event as malicious simply because it contained a suspicious keyword.

Instead, each event was evaluated in context.

The methodology can be represented as:

```text
                    ┌──────────────────┐
                    │ Initial Alert /  │
                    │ Investigation    │
                    │ Trigger          │
                    └────────┬─────────┘
                             ↓
                    ┌──────────────────┐
                    │ Identify Host   │
                    │ and User         │
                    └────────┬─────────┘
                             ↓
                    ┌──────────────────┐
                    │ Establish        │
                    │ Timeline         │
                    └────────┬─────────┘
                             ↓
              ┌──────────────┼──────────────┐
              ↓              ↓              ↓
       Authentication    Process        PowerShell
              │              │              │
              └──────────────┼──────────────┘
                             ↓
                    ┌──────────────────┐
                    │ Network / DNS    │
                    └────────┬─────────┘
                             ↓
                    ┌──────────────────┐
                    │ File Activity    │
                    └────────┬─────────┘
                             ↓
                    ┌──────────────────┐
                    │ Execution        │
                    └────────┬─────────┘
                             ↓
                    ┌──────────────────┐
                    │ Correlation &    │
                    │ Noise Filtering  │
                    └────────┬─────────┘
                             ↓
                    ┌──────────────────┐
                    │ Classification   │
                    └──────────────────┘
```

---

# 4. Telemetry Considered

The investigations used several types of Windows and Sysmon telemetry.

## 4.1 Windows Authentication Events

### Event ID 4625

Windows Security Event ID 4625 represents a failed logon.

A sequence of repeated failures can become an investigation trigger, particularly when followed by a successful authentication.

### Event ID 4624

Windows Security Event ID 4624 represents a successful logon.

A sequence such as:

```text
4625
 ↓
4625
 ↓
4625
 ↓
4624
```

can indicate that authentication attempts eventually succeeded.

However:

> A failed → successful authentication sequence does not, by itself, prove that an attacker successfully compromised the account.

Additional context is required.

---

# 5. Sysmon Telemetry

## Sysmon Event ID 1 — Process Creation

Used to identify:

* Process image
* Parent process
* Command line
* User
* Process execution time

Important relationship:

```text
ParentImage
     ↓
Image
```

Example:

```text
WINWORD.EXE
     ↓
powershell.exe
```

---

## Sysmon Event ID 3 — Network Connection

Used to identify network activity generated by a process.

Relevant information can include:

* Process
* Destination IP
* Destination hostname
* Destination port
* Timestamp

The important investigation question is:

> Which process initiated the network connection?

---

## Sysmon Event ID 11 — File Creation

Used to identify newly created files.

Important information includes:

* Creating process
* Target filename
* Timestamp

This becomes particularly useful when correlated with PowerShell network activity.

---

## Sysmon Event ID 22 — DNS Query

Used to identify DNS queries generated by a process.

A useful correlation can be:

```text
PowerShell
   ↓
DNS Query
   ↓
Network Connection
```

---

# 6. PowerShell Script Block Logging

## Event ID 4104

Event ID 4104 represents PowerShell Script Block Logging telemetry.

It can provide visibility into PowerShell script content processed by the PowerShell engine.

For example, a script block containing a download operation provides much stronger context than simply observing:

```text
powershell.exe
```

An important distinction established during the investigation was:

```text
4104 ≠ Child Process
```

Instead:

```text
PowerShell Process
       ↓
4104 Script Block Telemetry
```

The 4104 event should therefore be correlated with process, network, and file telemetry.

---

# CASE STUDY 1

# 7. The Unexpected Administrator

## 7.1 Scenario

The investigation began with an authentication anomaly involving repeated failed logons followed by a successful authentication.

The initial concern was whether an unauthorized user had eventually authenticated successfully.

The investigation then expanded into process and PowerShell telemetry.

---

## 7.2 Initial Investigation Trigger

The first activity that attracted attention was:

```text
Failed Login
      ↓
Failed Login
      ↓
Failed Login
      ↓
Successful Login
```

This sequence was considered noteworthy because repeated failed authentication followed by successful authentication can warrant investigation.

The key question was:

> Was the successful authentication legitimate, or did someone eventually obtain or guess valid credentials?

---

# 8. Authentication Sequence

The observed sequence was:

```text
4625
Failed Authentication
        ↓
4625
Failed Authentication
        ↓
4625
Failed Authentication
        ↓
4624
Successful Authentication
```

The authentication sequence established an anomaly.

However, the investigation did not treat the sequence as definitive proof of compromise.

The sequence was classified as:

```text
Investigation Trigger
```

rather than:

```text
Confirmed Attack Evidence
```

until additional telemetry was examined.

---

# 9. Process Investigation

The investigation then moved to process telemetry.

The relevant relationship was:

```text
WINWORD.EXE
       ↓
powershell.exe
```

The PowerShell process contained suspicious execution parameters.

These included:

```text
-ExecutionPolicy Bypass
-WindowStyle Hidden
-EncodedCommand
```

---

# 10. Why the PowerShell Command Was Suspicious

Several characteristics increased the risk associated with the PowerShell execution.

## 10.1 ExecutionPolicy Bypass

The command used:

```text
-ExecutionPolicy Bypass
```

This indicates that PowerShell was instructed to bypass the configured execution policy restrictions for that invocation.

By itself, this is not proof of malicious activity.

However, in combination with other suspicious behavior, it becomes a significant indicator.

---

## 10.2 Hidden Window

The command included:

```text
-WindowStyle Hidden
```

This indicates that the PowerShell window was intended to operate without being visibly presented to the user.

Again, this is not independently sufficient to prove malicious activity, but it increases suspicion when combined with other indicators.

---

## 10.3 Encoded Command

The command also contained:

```text
-EncodedCommand
```

Encoding can be used for legitimate reasons, but it can also make command-line content more difficult to inspect.

The combination of:

```text
EncodedCommand
+
ExecutionPolicy Bypass
+
Hidden Window
```

was substantially more suspicious than ordinary PowerShell administration.

---

# 11. PowerShell Script Block Investigation

The next layer of evidence was PowerShell Script Block Logging.

Event ID 4104 provided additional visibility into PowerShell activity.

The investigation correlated:

```text
PowerShell Process
        ↓
4104 Script Block
```

The Script Block activity was associated with subsequent network and file behavior.

---

# 12. Network Correlation

The investigation then identified a network connection associated with the PowerShell process.

The sequence became:

```text
Suspicious PowerShell
        ↓
4104 Script Block
        ↓
Network Connection
```

This was significant because the network activity was not being evaluated independently.

It was being evaluated as part of the same PowerShell execution sequence.

---

# 13. File Creation

The investigation then identified file creation following the PowerShell and network activity.

The behavioral sequence became:

```text
PowerShell
      ↓
Network Activity
      ↓
File Created
```

The created file was subsequently executed.

---

# 14. File Execution

The final part of the chain was:

```text
PowerShell
      ↓
File Created
      ↓
File Executed
```

This provided additional evidence that the PowerShell activity was associated with executable activity rather than being limited to a harmless administrative command.

---

# 15. Case 1 — Complete Timeline

The overall investigation sequence was reconstructed as:

```text
Failed Authentication
        ↓
Failed Authentication
        ↓
Failed Authentication
        ↓
Successful Authentication
        ↓
WINWORD.EXE
        ↓
powershell.exe
        ↓
ExecutionPolicy Bypass
        ↓
WindowStyle Hidden
        ↓
EncodedCommand
        ↓
4104 Script Block
        ↓
Network Connection
        ↓
File Created
        ↓
File Executed
```

---

# 16. Case 1 — Evidence Assessment

The strongest part of the investigation was not any individual event.

The strength came from the correlation of multiple telemetry sources.

### Authentication

```text
Repeated failures
        ↓
Successful authentication
```

### Process

```text
WINWORD.EXE
        ↓
powershell.exe
```

### PowerShell

```text
Hidden
+
ExecutionPolicy Bypass
+
EncodedCommand
```

### Script Block

```text
4104
```

### Network

```text
PowerShell
        ↓
Network Connection
```

### File

```text
File Created
        ↓
File Executed
```

Together these formed a coherent suspicious execution chain.

---

# 17. Case 1 — Evidence vs. Inference

## Observed Evidence

* Multiple failed authentication events were observed.
* A successful authentication followed.
* PowerShell was launched by an Office application.
* The PowerShell command contained suspicious execution parameters.
* PowerShell Script Block Logging was observed.
* Network activity was associated with PowerShell.
* A file was created.
* The created file was subsequently executed.

## Analyst Inference

The combined evidence is consistent with a malicious PowerShell-driven execution chain.

The authentication activity was considered suspicious and relevant to the investigation, but the evidence available did not independently establish the identity or intent of the actor.

---

# 18. Case 1 — Final Classification

```text
Classification: MALICIOUS

Confidence: HIGH
```

### Analyst Reasoning

The classification was based on the combined behavioral chain rather than a single indicator.

The presence of suspicious PowerShell parameters, script block activity, network communication, file creation, and subsequent execution provided multiple mutually supporting pieces of evidence.

---

# CASE STUDY 2

# 19. Noise vs. the Real Attack Chain

## 19.1 Scenario

The second case was specifically designed to test the analyst's ability to distinguish legitimate activity from malicious activity.

Several events occurred on the same endpoint.

However:

> Not every event belonged to the same attack chain.

The investigation therefore required explicit noise filtering.

---

# 20. Initial Authentication Activity

The initial sequence was:

```text
4625
     ↓
4625
     ↓
4624
```

This activity was important enough to begin an investigation.

However, it was not automatically assumed to be part of the later PowerShell activity.

The correct classification of this evidence was:

```text
Authentication anomaly
+
Investigation trigger
```

rather than:

```text
Confirmed component of attack chain
```

---

# 21. Benign PowerShell Activity

The investigation identified an earlier PowerShell process:

```text
explorer.exe
       ↓
powershell.exe
       ↓
Get-ComputerInfo
```

The command:

```text
Get-ComputerInfo
```

is consistent with ordinary system-information gathering.

There was no additional malicious behavior associated with this activity in the provided evidence.

Therefore, this activity was treated as benign.

---

# 22. Benign Network Activity

A network connection was also associated with the earlier PowerShell activity.

The destination was:

```text
intranet.hr.local
```

and the connection used:

```text
443
```

The activity was assessed as benign in the context of the provided evidence because:

1. It was associated with the earlier legitimate PowerShell activity.
2. The destination was an internal HR hostname.
3. It occurred in the context of the `Get-ComputerInfo` activity.
4. No additional suspicious behavior connected it to the later attack chain.

Therefore:

```text
Benign PowerShell
       ↓
Internal Network Activity
```

was treated as noise relative to the malicious sequence.

---

# 23. Suspicious PowerShell Activity

Later in the timeline, a different PowerShell process appeared:

```text
WINWORD.EXE
       ↓
powershell.exe
```

The command line contained:

```text
-WindowStyle Hidden
-ExecutionPolicy Bypass
-EncodedCommand
```

This represented a materially different execution context from the earlier legitimate PowerShell activity.

---

# 24. Why the Two PowerShell Events Were Different

## Earlier Activity

```text
explorer.exe
       ↓
powershell.exe
       ↓
Get-ComputerInfo
```

Characteristics:

* Interactive user context
* Normal system-information command
* No suspicious execution flags
* Associated internal network activity
* No subsequent malicious file execution in the provided evidence

---

## Later Activity

```text
WINWORD.EXE
       ↓
powershell.exe
       ↓
Hidden
ExecutionPolicy Bypass
EncodedCommand
```

Characteristics:

* Office application spawning PowerShell
* Hidden execution
* Execution policy bypass
* Encoded command
* Followed by script, network, file creation, and execution activity

Therefore, the two PowerShell processes should not be treated as equivalent simply because both use `powershell.exe`.

---

# 25. PowerShell Script Block Correlation

The suspicious PowerShell activity was followed by Event ID 4104.

The Script Block contained a download operation.

The resulting chain was:

```text
WINWORD.EXE
       ↓
powershell.exe
       ↓
4104
       ↓
Download Operation
```

This was a significant escalation in evidence quality.

The investigation now had visibility not only into the fact that PowerShell executed, but also into the behavior being performed by PowerShell.

---

# 26. Network Correlation

A subsequent network connection was associated with the suspicious PowerShell process.

The sequence became:

```text
Suspicious PowerShell
       ↓
4104 Script Block
       ↓
Download Operation
       ↓
External Network Connection
```

This relationship was important because the network connection occurred as part of a broader behavioral sequence.

---

# 27. File Creation

The investigation then identified:

```text
update.exe
```

being created.

The sequence became:

```text
PowerShell
       ↓
Download Operation
       ↓
Network Connection
       ↓
update.exe Created
```

This provided a strong connection between the PowerShell activity and the newly created executable.

---

# 28. File Execution

The newly created executable was subsequently executed.

The final sequence became:

```text
PowerShell
       ↓
Download Operation
       ↓
Network Connection
       ↓
update.exe Created
       ↓
update.exe Executed
```

This was the strongest part of the case.

---

# 29. Case 2 — Complete Attack Chain

The suspicious chain was reconstructed as:

```text
WINWORD.EXE
       ↓
powershell.exe
       ↓
-WindowStyle Hidden
       ↓
-ExecutionPolicy Bypass
       ↓
-EncodedCommand
       ↓
4104 Script Block
       ↓
Download Operation
       ↓
External Network Connection
       ↓
update.exe Created
       ↓
update.exe Executed
```

---

# 30. Case 2 — Events Excluded as Noise

The investigation intentionally excluded the following from the malicious chain:

### Authentication Sequence

```text
4625
 ↓
4625
 ↓
4624
```

Reason:

The authentication activity triggered the investigation but the available evidence did not establish a direct relationship to the later PowerShell chain.

---

### Benign PowerShell

```text
explorer.exe
 ↓
powershell.exe
 ↓
Get-ComputerInfo
```

Reason:

The command was consistent with legitimate system-information activity and lacked the suspicious characteristics associated with the later PowerShell process.

---

### Internal Network Activity

```text
powershell.exe
 ↓
intranet.hr.local:443
```

Reason:

The connection was associated with the benign PowerShell activity and did not have evidence connecting it to the malicious execution chain.

---

# 31. Case 2 — Noise Filtering Model

The investigation effectively separated the events into two categories.

## Category A — Investigation / Benign Activity

```text
Authentication anomaly
        +
Legitimate PowerShell
        +
Internal network connection
```

## Category B — Correlated Malicious Activity

```text
WINWORD.EXE
        ↓
PowerShell
        ↓
Suspicious Parameters
        ↓
4104
        ↓
Download
        ↓
Network
        ↓
File Creation
        ↓
File Execution
```

This distinction was one of the primary learning objectives of the case.

---

# 32. Case 2 — Strongest Evidence

The strongest evidence was not the authentication sequence.

It was the **multi-stage PowerShell execution chain**.

The strongest correlation was:

```text
Suspicious PowerShell
        ↓
4104 Download Operation
        ↓
Network Connection
        ↓
Executable Creation
        ↓
Executable Execution
```

Each stage reinforced the previous stage.

This is stronger than classifying the activity solely because:

```text
"ExecutionPolicy Bypass"
```

was present.

---

# 33. Evidence vs. Inference

The investigation maintained a distinction between facts and conclusions.

## Fact

```text
PowerShell executed with
ExecutionPolicy Bypass.
```

## Inference

```text
The PowerShell execution is suspicious.
```

---

## Fact

```text
A PowerShell Script Block contained
a file download operation.
```

## Inference

```text
PowerShell was likely being used to retrieve
an executable as part of the observed chain.
```

---

## Fact

```text
An executable file was created and
subsequently executed.
```

## Inference

```text
The activity is consistent with a
download-and-execution workflow.
```

This approach prevents the analyst from presenting assumptions as telemetry.

---

# 34. Case 2 — Final Classification

```text
Classification: MALICIOUS

Confidence: HIGH
```

### Reasoning

The classification was supported by a coherent sequence involving:

* Office application spawning PowerShell
* Hidden PowerShell execution
* Execution Policy Bypass
* Encoded Command
* PowerShell Script Block Logging
* Download operation
* External network communication
* Executable file creation
* Executable file execution

The benign PowerShell and internal network activity were separated from the malicious chain.

---

# 35. Comparison of the Two Cases

| Investigation Area           | Case 1    | Case 2             |
| ---------------------------- | --------- | ------------------ |
| Authentication anomaly       | ✅         | ✅                  |
| Failed → successful sequence | ✅         | ✅                  |
| PowerShell activity          | ✅         | ✅                  |
| Parent-child analysis        | ✅         | ✅                  |
| ExecutionPolicy Bypass       | ✅         | ✅                  |
| Hidden execution             | ✅         | ✅                  |
| Encoded command              | ✅         | ✅                  |
| Event ID 4104                | ✅         | ✅                  |
| Network correlation          | ✅         | ✅                  |
| File creation                | ✅         | ✅                  |
| File execution               | ✅         | ✅                  |
| Noise filtering              | Limited   | **Core objective** |
| Evidence vs. inference       | ✅         | **Core objective** |
| Final classification         | Malicious | Malicious          |
| Confidence                   | High      | High               |

---

# 36. Key SOC Lessons

## 36.1 A successful login after failed attempts is an investigation trigger

A pattern such as:

```text
4625
 ↓
4625
 ↓
4624
```

should attract attention.

However, it should not automatically be classified as successful credential compromise.

---

## 36.2 PowerShell should be investigated in context

The presence of:

```text
powershell.exe
```

alone does not indicate malicious behavior.

The analyst should investigate:

* Parent process
* Command line
* User
* Timestamp
* Script block
* Network activity
* File activity
* Subsequent execution

---

## 36.3 Parent-child relationships provide context

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

The parent process changes the investigative context.

However, the parent process alone should not determine the final classification.

---

## 36.4 Suspicious PowerShell parameters become stronger when correlated

The combination:

```text
Hidden
+
ExecutionPolicy Bypass
+
EncodedCommand
```

is significantly more suspicious when followed by:

```text
4104
+
Network
+
File Creation
+
File Execution
```

---

## 36.5 Event ID 4104 provides behavioral context

4104 can show what PowerShell processed.

It should be correlated with other telemetry.

It should not be represented as a process.

---

## 36.6 Network activity needs process context

A network connection alone does not automatically indicate malicious behavior.

The analyst should determine:

```text
Which process?
Which user?
Which destination?
Which port?
When?
What happened immediately before?
What happened immediately after?
```

---

## 36.7 File creation followed by execution is important

The sequence:

```text
File Created
      ↓
File Executed
```

can provide stronger evidence than file creation alone.

When preceded by:

```text
PowerShell
+
Download
+
Network Connection
```

the overall behavioral chain becomes significantly more suspicious.

---

## 36.8 Same host does not mean same incident

This was the most important lesson from Case Study 2.

Multiple events can occur on the same endpoint without being part of the same attack.

The analyst must establish relationships using:

* Time
* User
* Process
* Parent process
* Destination
* File
* Behavioral sequence

---

# 37. Investigation Decision Framework

The investigation methodology developed during these cases can be summarized as:

```text
                START
                  ↓
        What triggered the alert?
                  ↓
        Identify host and user
                  ↓
        Establish time window
                  ↓
       ┌──────────┴──────────┐
       ↓                     ↓
 Authentication          Process Activity
       ↓                     ↓
 Failed/Success?       Parent/Child?
       │                     │
       └──────────┬──────────┘
                  ↓
            PowerShell?
                  ↓
       ┌──────────┴──────────┐
       ↓                     ↓
    4104?              Suspicious CLI?
       │                     │
       └──────────┬──────────┘
                  ↓
          Network Activity?
                  ↓
            File Activity?
                  ↓
           File Executed?
                  ↓
        Is there a logical chain?
                  ↓
       ┌──────────┴──────────┐
       ↓                     ↓
      YES                     NO
       ↓                     ↓
Correlated Evidence      Isolated Event
       ↓                     ↓
Classification          More Context
```

---

# 38. Analyst Questions Used During Investigation

The following questions formed the core of the investigation process:

### Authentication

* Who authenticated?
* From where?
* Were there failed attempts?
* Was there eventually a successful authentication?
* Does the sequence prove compromise?

### Process

* Which process executed?
* Which process spawned it?
* Is the parent-child relationship expected?
* What user executed the process?
* What command line was used?

### PowerShell

* Was PowerShell executed normally?
* Was execution policy bypassed?
* Was the window hidden?
* Was the command encoded?
* What does the 4104 script block contain?

### Network

* Did the process communicate externally?
* What destination was contacted?
* What port was used?
* Was DNS activity observed?
* Does the network activity correlate with the PowerShell script?

### File

* Was a file created?
* Which process created it?
* Where was it created?
* Was it subsequently executed?

### Correlation

* Do the timestamps align?
* Is the same user involved?
* Is the same process involved?
* Does one event logically explain the next?
* Which events are unrelated noise?

---

# 39. What Was Not Claimed

The investigations deliberately avoided unsupported conclusions.

The following were **not automatically claimed** without supporting evidence:

* The identity of the attacker
* The exact initial access method
* That the authentication anomaly definitely represented credential compromise
* That every PowerShell process was malicious
* That every network connection was malicious
* The exact contents or behavior of a downloaded executable when not directly observed
* Successful persistence
* Successful privilege escalation
* Data exfiltration
* Specific malware family attribution

The classification was based on the evidence available within the controlled case study.

---

# 40. Final Analyst Perspective

The most important transition demonstrated during Day 8 was the transition from:

```text
"I found a suspicious event."
```

to:

```text
"I found multiple related events that form
a defensible behavioral sequence."
```

The first approach focuses on indicators.

The second approach focuses on **evidence correlation**.

A mature SOC investigation should therefore move through:

```text
Indicator
   ↓
Context
   ↓
Correlation
   ↓
Timeline
   ↓
Behavior
   ↓
Evidence
   ↓
Classification
```

---

# 41. Final Case Outcomes

## Case 1 — The Unexpected Administrator

```text
Classification: MALICIOUS
Confidence: HIGH
```

### Core finding

A sequence involving authentication anomalies, suspicious PowerShell execution, Script Block Logging, network activity, file creation, and subsequent execution formed a coherent malicious activity chain.

---

## Case 2 — Noise vs. the Real Attack Chain

```text
Classification: MALICIOUS
Confidence: HIGH
```

### Core finding

The investigation successfully separated legitimate PowerShell and internal network activity from the malicious chain involving Office-spawned PowerShell, suspicious execution parameters, Script Block Logging, download activity, network communication, file creation, and execution.

---

# 42. Skills Demonstrated

The following SOC Analyst skills were demonstrated through the two case studies:

* SIEM investigation
* Splunk investigation methodology
* Windows authentication analysis
* Event ID 4624 analysis
* Event ID 4625 analysis
* PowerShell investigation
* Event ID 4104 analysis
* Sysmon Event ID 1 analysis
* Sysmon Event ID 3 analysis
* Sysmon Event ID 11 analysis
* Sysmon Event ID 22 analysis
* Parent-child process analysis
* Command-line analysis
* Network correlation
* File activity correlation
* Timeline reconstruction
* Event correlation
* Noise filtering
* Evidence assessment
* Evidence vs. inference
* Incident classification
* Confidence assessment
* L1 SOC investigation methodology

---

# 43. Day 8 Case Study Conclusion

These investigations demonstrated that effective SIEM analysis is not simply about finding suspicious events.

The analyst must determine:

```text
What happened?
       ↓
When did it happen?
       ↓
Who was involved?
       ↓
Which process initiated it?
       ↓
What happened next?
       ↓
Which telemetry confirms it?
       ↓
Which events are unrelated?
       ↓
What does the complete evidence chain show?
```

The strongest investigation result came from correlating multiple independent telemetry sources.

The final methodology established during these cases was:

```text
SEARCH
   ↓
FILTER
   ↓
INSPECT
   ↓
CORRELATE
   ↓
RECONSTRUCT
   ↓
SEPARATE NOISE
   ↓
ASSESS
   ↓
CLASSIFY
```

## Final Status

**Day 8 Case Studies: COMPLETED**

**Case 1: Malicious — High Confidence**

**Case 2: Malicious — High Confidence**

**Primary Skill Demonstrated: SIEM Event Correlation**

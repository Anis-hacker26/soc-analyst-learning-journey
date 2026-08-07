# 🚨 SOC Case File #02 – Windows Account Lockout Investigation

## Case Overview

This investigation simulates multiple employee account lockouts caused by repeated authentication failures. The objective is to determine whether the activity is normal user behavior or a potential password-spraying attack.

---

# Incident Summary

Several employees reported that their Windows accounts had been locked.

Initial investigation showed multiple failed authentication attempts originating from the same source IP address. As additional accounts became targeted, the activity became increasingly consistent with a password-spraying attack.

---

# Initial Alert

Helpdesk reported:

> "Multiple employees are unable to log into their Windows accounts because their accounts have been locked."

---

# Initial Assessment

Classification:

🟡 **Suspicious Activity**

Reason:

- Multiple account lockouts
- Authentication failures
- No malware alerts
- Required further investigation

---

# Investigation

## Step 1 – Review Security Log

Relevant Events:

- Event ID 4625
- Event ID 4740

Observation:

Repeated failed login attempts against the same account resulted in account lockout.

---

## Step 2 – Analyze Source IP

Source Network Address:

```
10.10.5.25
```

Observation:

Multiple authentication failures originated from the same endpoint.

---

## Step 3 – Asset Identification

Asset:

```
FINANCE-PC-07
```

Assigned User:

```
John Smith
```

---

## Step 4 – Expand Investigation

Additional failed logins observed:

- m.brown
- a.lee

Observation:

Multiple user accounts were targeted from the same source IP.

Confidence level increased.

---

# Investigation Timeline

```
Multiple failed logins
        │
        ▼
Account lockout
        │
        ▼
SOC reviews Security Log
        │
        ▼
Same Source IP identified
        │
        ▼
Additional user accounts targeted
        │
        ▼
Suspicion increases
        │
        ▼
Endpoint isolated
        │
        ▼
Incident investigation continues
```

---

# Evidence Collected

| Evidence | Observation |
|----------|-------------|
| Event ID 4625 | Failed Logon |
| Event ID 4740 | Account Lockout |
| Source IP | 10.10.5.25 |
| Multiple Accounts | Targeted |
| Asset | FINANCE-PC-07 |

---

# Initial Hypothesis

The activity initially appeared to be a brute-force attempt against a single account.

As more accounts were targeted from the same source IP, the behavior became more consistent with password spraying.

Further investigation would be required to confirm the attacker's intent.

---

# MITRE ATT&CK Mapping

| Tactic | Technique |
|---------|-----------|
| Credential Access | Password Spraying |
| Credential Access | Brute Force |
| Discovery | Account Discovery (Possible) |

---

# Containment

- Isolate FINANCE-PC-07 if compromise is confirmed.
- Reset affected account passwords.
- Preserve Security Logs.
- Notify the IT team.
- Continue monitoring authentication events.

---

# Lessons Learned

- Authentication events should always be investigated using context.
- The Source Network Address is valuable for identifying attack origins.
- Confidence grows as additional evidence is collected.
- Multiple failed logins do not always indicate malicious activity.
- A structured investigation process reduces false positives.

---

# Final Assessment

Current Confidence:

🟠 **Medium to High**

Reason:

Evidence strongly suggests coordinated authentication attacks originating from a single source endpoint. Additional forensic investigation would be required to confirm compromise.

---

# Skills Practiced

- Windows Security Log Analysis
- Authentication Investigation
- Event Correlation
- Incident Timeline Creation
- Evidence Collection
- Root Cause Analysis
- SOC Investigation Methodology

---

# Interview Questions

1. What does Event ID 4625 represent?
2. What information can the Source Network Address provide?
3. How can you distinguish brute force from password spraying?
4. When should an endpoint be isolated during an authentication investigation?
5. Why is context essential during authentication-related incidents?
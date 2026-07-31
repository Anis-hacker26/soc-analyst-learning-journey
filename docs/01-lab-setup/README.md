# 🛡️ SOC Lab Setup
## Table of Contents

- [Introduction](#introduction)
- [Objectives](#objectives)
- [Lab Architecture](#lab-architecture)
- [Why Virtual Machines?](#why-virtual-machines)
- [Why Windows 11 Enterprise?](#why-windows-11-enterprise)
- [Why Kali Linux?](#why-kali-linux)
- [Why Snapshots?](#why-snapshots)
- [Lab Network Design](#lab-network-design)
- [Lab Specifications](#lab-specifications)
- [Tools Used](#tools-used)
- [Lessons Learned](#lessons-learned)
- [Screenshots](#screenshots)
- [Reflection](#reflection)
- [Next Steps](#next-steps)

## Introduction

A Security Operations Center (SOC) analyst requires a safe and isolated environment to practice monitoring, investigating, and responding to security events without affecting production systems.

This lab was built to simulate a real-world enterprise environment where Windows systems can be monitored while Linux-based attacker machines generate realistic attack activity.

The lab serves as the foundation for learning Windows Internals, Sysmon, Event Viewer, Splunk, Threat Hunting, and Incident Response throughout this learning journey.

## Objectives

The objectives of this lab are:

- Build an isolated cybersecurity practice environment
- Investigate Windows security events
- Learn Sysmon event analysis
- Simulate attacks safely
- Practice incident investigations
- Prepare for real SOC analyst responsibilities

## Lab Architecture

The current lab consists of:

### Host Machine

- Windows 11
- ASUS Vivobook M6500QF
- AMD Ryzen 5 5600H
- 16 GB RAM

### Virtualization

- Oracle VirtualBox

### Virtual Machines

#### Windows 11 Enterprise

Purpose:

- Security monitoring
- Sysmon logging
- Event Viewer analysis
- Windows investigations

#### Kali Linux

Purpose:

- Attack simulation
- Security testing
- Network analysis
- Offensive security practice

## Why Virtual Machines?

Virtual machines provide isolated environments where operating systems can run independently on the same physical computer.

For a SOC analyst, isolation is essential because it allows malware analysis, attack simulation, and security testing without affecting the host operating system.

Using virtual machines also makes it possible to quickly restore the environment using snapshots, enabling repeated experiments and investigations without rebuilding the lab.

### Benefits

- Safe environment for cybersecurity practice
- Easy recovery using snapshots
- Multiple operating systems on one computer
- Realistic attack and defense scenarios
- No risk to the host operating system

### Key Takeaway

Virtual machines provide a safe and repeatable environment for cybersecurity practice by isolating experiments from the host operating system.

## Why Windows 11 Enterprise?

Windows is the primary operating system used in most enterprise environments, making it one of the most common targets for cyberattacks. Since SOC analysts are responsible for monitoring and investigating security incidents on enterprise systems, understanding Windows internals is essential.

Windows 11 Enterprise provides access to features and logging capabilities that closely resemble those found in corporate environments. This makes it an ideal platform for learning how to analyze security events, investigate suspicious activity, and understand attacker behavior.

### Why Windows 11 Enterprise?

- Investigate Windows Event Logs
- Analyze Sysmon events
- Monitor process creation and network activity
- Understand Windows security mechanisms
- Simulate enterprise environments

### SOC Perspective

In a real Security Operations Center (SOC), analysts spend a significant amount of time investigating Windows systems because they generate the majority of security events in many organizations. Learning Windows first provides a strong foundation for incident response and threat hunting.

### Key Takeaway

Windows is not just the operating system we are practicing on—it is the environment we are learning to defend.

## Why Kali Linux?

Kali Linux is a Debian-based Linux distribution designed for cybersecurity professionals. It comes pre-installed with hundreds of security tools used for penetration testing, vulnerability assessment, digital forensics, and network analysis.

In this SOC lab, Kali Linux is used to simulate attacker activity against the Windows virtual machine. This allows security events to be generated naturally, providing realistic logs and artifacts for investigation.

### Why Kali Linux?

- Simulate attacks in a controlled environment
- Generate realistic security events
- Perform network reconnaissance
- Test defensive tools and detections
- Learn attacker techniques in a safe environment

### SOC Perspective

SOC analysts investigate evidence left behind by attackers. By using Kali Linux to perform controlled attack simulations, I can better understand how malicious activities appear in Windows Event Logs, Sysmon logs, and other monitoring tools. This helps bridge the gap between offensive techniques and defensive investigations.

### Key Takeaway

Understanding attacker techniques helps SOC analysts recognize suspicious behavior more effectively and improve their investigation skills.

## Why Snapshots?

A snapshot captures the complete state of a virtual machine at a specific point in time, including its operating system, installed applications, system configuration, and stored data.

Snapshots allow the lab environment to be restored quickly after experiments, malware execution, or configuration changes. Instead of reinstalling the operating system, the virtual machine can be reverted to a known good state within minutes.

### Benefits of Snapshots

- Restore the lab after malware testing
- Recover from accidental system changes
- Repeat experiments consistently
- Save time by avoiding full reinstallation
- Maintain a clean baseline for investigations

### SOC Perspective

SOC analysts often need to reproduce security incidents multiple times to understand attacker behavior and validate detection rules. Snapshots make this possible by allowing the environment to be reset to an identical starting point for every investigation.

### Best Practices

- Create a snapshot before installing new software.
- Take a snapshot before running attack simulations.
- Name snapshots clearly (e.g., "Clean Windows Install" or "Before Sysmon Installation").
- Delete outdated snapshots to conserve disk space.

### Key Takeaway

Snapshots provide a fast and reliable way to restore the lab environment, making cybersecurity experiments safe, repeatable, and efficient.

## Lab Network Design

The SOC lab is designed to provide a safe and isolated environment for cybersecurity learning. The virtual machines communicate with each other through a controlled virtual network while remaining separated from production systems.

### Lab Components

- **Host Machine**
  - Runs Oracle VirtualBox
  - Manages all virtual machines
  - Stores snapshots and lab files

- **Windows 11 Enterprise VM**
  - Primary system for monitoring and investigation
  - Generates Windows Event Logs and Sysmon events
  - Simulates an enterprise workstation

- **Kali Linux VM**
  - Simulates attacker activity
  - Performs security testing in a controlled environment
  - Generates realistic attack scenarios for investigation

### Network Flow

Kali Linux generates security events by interacting with the Windows virtual machine. These activities produce logs that can later be analyzed using Windows Event Viewer, Sysmon, and eventually Splunk.

```
Host Machine
│
├── Oracle VirtualBox
│
├── Windows 11 Enterprise VM
│      ▲
│      │
│      │ Attack Traffic
│      │
└──────┼────────────────────
       │
       ▼
   Kali Linux VM
   (Attack Simulation)
```

### Security Considerations

- Perform attack simulations only within the isolated lab.
- Never target systems outside the lab environment.
- Keep the host operating system separate from testing activities.
- Restore virtual machines using snapshots after major experiments.
- Maintain updated virtual machine images and security tools.

### SOC Perspective

A SOC analyst investigates communication between systems rather than individual machines in isolation. Understanding how attackers interact with target systems helps identify the origin of attacks, trace suspicious activity, and reconstruct the sequence of events during an investigation.

### Key Takeaway

A well-designed lab network enables safe attack simulations while providing realistic security data for investigation and threat analysis.

## Lab Specifications

### Host Machine

- **OS:** Windows 11
- **Processor:** AMD Ryzen 5 5600H
- **RAM:** 16 GB
- **Virtualization:** Oracle VirtualBox

### Windows 11 Enterprise VM

- **Purpose:** Investigation Machine
- **OS:** Windows 11 Enterprise
- **RAM:** 4 GB
- **CPU:** 2 Cores
- **Storage:** 60 GB

### Kali Linux VM

- **Purpose:** Attack Simulation
- **OS:** Kali Linux
- **RAM:** 4 GB
- **CPU:** 2 Cores
- **Storage:** 40 GB

## Tools Used

- **Oracle VirtualBox** – Virtual machine platform
- **Windows 11 Enterprise** – Investigation machine
- **Kali Linux** – Attack simulation
- **Sysinternals Suite** – Windows troubleshooting tools
- **Sysmon** – Advanced event logging
- **Event Viewer** – Windows log analysis
- **Git** – Version control
- **Visual Studio Code** – Documentation and development

## Lessons Learned

- Understood the importance of an isolated SOC lab.
- Learned the role of Windows and Kali Linux in security investigations.
- Learned why virtual machines and snapshots are essential.
- Designed the initial network architecture for the lab.

## Screenshots

Screenshots will be added as the lab environment evolves throughout this learning journey.

## Reflection

Building the SOC lab helped me understand that cybersecurity is not just about using tools but about creating a safe environment to learn, investigate, and experiment without affecting production systems.

## Next Steps

- Install and configure Sysmon
- Explore Windows Event Viewer
- Begin analyzing Windows Event Logs

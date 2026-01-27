# Incident Handling

Incident handling is a clearly defined set of procedures for responding to security incidents. This document summarizes the basics of incident handling, and is by no means an exhaustive guide.

# Table of Contents

- [Overview](#overview)
- [Cyber Kill Chain](#cyber-kill-chain)
  - [Reconnaissance](#reconnaissance)
  - [Weaponize](#weaponize)
  - [Delivery](#delivery)
  - [Exploitation](#exploitation)
  - [Installation](#installation)
  - [Command and Control](#command-and-control)
  - [Action](#action)
- [MITRE ATT&CK Framework](#mitre-attck-framework)
- [The Hive](#the-hive)
- [The Incident Handling Process](#the-incident-handling-process)
  - [Preparation](#preparation)
  - [Detection and Analysis](#detection-and-analysis)
    - [Detection](#detection)
    - [Investigation](#investigation)
  - [Containment, Eradication and Recovery](#containment-eradication-and-recovery)
    - [Containment](#containment)
    - [Eradication](#eradication)
    - [Recovery](#recovery)
  - [Post-Incident Activity](#post-incident-activity)

---

# Overview

Incident handling capability is a necessity for any organization looking to uphold the three pillars of information security:

- Confidentiality
- Integrity
- Availability

Examples of incidents include:

- Leaked credentials
    - Colonial Pipeline ransomware attack (2021)
- Weak credentials
    - Mirai Botnet (2016)
- Outdated software
    - WannaCry ransomware attack (2017)
- Rogue employees
    - Cash App (2021)
- Social engineering
    - U.S. Interior Department (2015)

---

# Cyber Kill Chain

The cyber kill chain consists of seven stages, describing the lifecycle of an attack. 

![Filtered output](.images/cyber-kill-chain.PNG)

Keep in mind that adversaries rarely operate linearly, as the cyber kill chain suggests. Some stages might be repeated multiple times, and some stages might be skipped.

## Reconnaissance

The attacker gather as much useful information as possible about the target. 

Active reconnaissance involves mapping out the network, by identifying hosts, open ports, and running services. This involves interacting directly with the target, often through some automated tool, such as NMAP. 

Passive reconnaissance involves gathering information from public sources such as social media, job ads, and company web pages. This is a more stealthy approach, since it doesn't require direct interaction with the target.  

## Weaponize

The attacker develops a payload and embeds it in an exploit to gain initial access. The main purpose of the payload is to gain remote access to the target machine, preferably through a persistent payload. 

## Delivery

The payload is delivered to the target. The delivery method varies, but often include some type of phishing campaign. A solid payload rarely requires the user to do anything more than to double-click on a link. 

In some cases the payload is delivered through physical means, such as a USB stick.

## Exploitation

The payload is triggered on the target machine. The attacker attempts to execute code on the target machine in order to gain control.

## Installation

The initial stager is executed and running on the target machine. The installation stage can be carried out in different ways:

- Droppers
    - Small piece of code designed to execute malware.
- Backdoors
    - Designed to provide the attacker with persistent access.
- Rootkits
    - Designed to hide its presence on the compromised machine.

## Command and Control

The attacker establishes remote access capability to the target machine.

## Action

Means to achieve the actual objectives of the attack are carried out. 

Example objectives are:

- Exfiltrating data
- Deploy ransomware

---

# MITRE ATT&CK Framework

MITRE ATT&CK is another framework for understanding adversary behavior. It is a matrix-based system of tactics and techniques observed in the wild. The columns represent adversary goals, and the rows (cells) represent the techniques used to achieve those goals.

![Filtered output](.images/mitre.PNG)

## The Hive

![Filtered output](.images/the-hive.PNG)

A case management platform designed to effectively handle incidents by processing alerts. It collects alerts from various devices and presents them in a centralized way. 

The Hive has the capability to import all MITRE ATT&CK tactics and techniques into its alert management system. 

![Filtered output](.images/the-hive2.PNG)

---

# The Incident Handling Process

The incident handling process contains four stages:

- Preparation
- Detection and analysis
- Containment, eradication and recovery
- Post incident activity

Incident handlers spend the majority of their time in the first two stages: preparation and detection and analysis. 

## Preparation

The preparation stage is about establishing an incident handling capability by creating processes and procedures. 

Protective measures may include:

- DMARC
- Endpoint and server hardening
- AD tiering
- MFA

DMARC is an email protection mechanism against phishing built on top of SPF and DKIM. The idea is to reject emails that pretend to originate from in-house sources. 

Effective ways of achieving endpoint hardening include:

- Disable LLMNR/NetBIOS
- Remove admin privileges from regular users
- Configure PowerShell in "ConstrainedLanguage" mode
- Host-based firewalls
- Implement an EDR solution

## Detection and Analysis

The detection and analysis stage involves all aspects of detecting and investigating incidents. 

### Detection

Incidents are usually detected through alerts from various security systems, such as:

- Firewalls
- EDR
- IDS/IPS
- SIEM

Detection capabilities should be categorized in levels, depending on where it occurs in the network:

- Network Perimeter Level
    - Firewalls, DMZ, Internet facing IDS/IPS
- Internal Network Level
    - Local firewalls, host-based IDS/IPS
- Endpoint Level
    - AVS, EDR
- Application Level
    - Logs

When an incident is detected, the following information should be collected:

- Date
    - 09/1/2025
- Time of the event
    - 04:41 CET
- Hostname
    - SQLServer01
- Event description
    - Hacker tool Mimikatz was detected
- Data source
    - Antivirus software

The information is usually collected from the security system that generated the alert:

![Filtered output](.images/the-hive3.PNG)

### Investigation

Once the investigation starts, the goal is to understand **what happened** and **how it happened**. Without this knowledge it will be impossible to stop the same thing from happening again. 

An iterative 3-step process is used:

- Creation and usage of IOCs
    - IPs, hashes, file names
- Identification of new leads and impacted systems
- Data collection and analysis from new leads and impacted systems

IOCs can be added to alerts in The Hive:

![Filtered output](.images/the-hive4.PNG)


## Containment, Eradication and Recovery

Once the investigation is complete and the type of incident and its impact is understood, its time to prevent the incident from causing more damage. 

### Containment

Containment actions should be coordinated and executed across all systems simultaneously. Otherwise we might alert the attackers, causing them to change their techniques. 

Short-term containment actions may include:

- Placing a system in an isolated VLAN
- Pulling the network cable
- Changing the attackers C2 DNS

Long-term containment actions may include:

- Changing passwords
- Implementing new firewall rules
- Implementing a host IDS
- Patching systems
- Shutting down systems

### Eradication

The eradication process is meant to eliminate the root cause of the incident and make sure that the attackers are out of the system. 

Eradication actions may include:

- Removing malware
- Rebuilding systems
- Restoring systems from backups
- Applying additional patches

### Recovery

In the recovery stage, systems are brought back to normal operation. When the systems are verified as working properly, they are brought back into the production environment. 

Restored systems are subject to heavy monitoring, since attackers tend to be persistent. 

Suspicious events to monitor for include:

- Unusual logins
- Unusual processes
- Registry changes

## Post-Incident Activity

The last stage is meant for documentation and reflection. The incident is properly documented and the lessons learned are implemented throughout the organisation. Everything is tied together in a final report. 
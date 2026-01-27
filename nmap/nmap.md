# Network Enumeration with Nmap

This document summarizes core techniques for network discovery and enumeration using **Nmap**. This is by no means an exhaustive guide. 

---

## Table of Contents

- [Overview](#overview)
- [Host Discovery](#host-discovery)
  - [ICMP-Based Discovery](#icmp-based-discovery)
  - [Extracting Live Hosts](#extracting-live-hosts)
  - [Scanning From a Host List](#scanning-from-a-host-list)
  - [Multiple Hosts and Host Ranges](#multiple-hosts-and-host-ranges)
  - [Debugging Host Discovery](#debugging-host-discovery)
  - [Forcing ICMP Discovery](#forcing-icmp-discovery)
- [Port Scanning](#port-scanning)
  - [Default Scan Behavior](#default-scan-behavior)
  - [Port Selection](#port-selection)
- [Service and OS Detection](#service-and-os-detection)
- [Nmap Scripting Engine (NSE)](#nmap-scripting-engine-nse)
  - [Common NSE Usage](#common-nse-usage)
- [Timing and Performance](#timing-and-performance)
  - [Timing Templates](#timing-templates)
- [IDS/IPS Evasion](#idsips-evasion)
  - [Decoys](#decoys)
  - [Spoofing Source IP](#spoofing-source-ip)
  - [Source Port Manipulation](#source-port-manipulation)

---

## Overview

Nmap is a powerful open-source tool used for:

- Host discovery
- Port scanning
- Service and version enumeration
- Operating system detection
- Vulnerability detection

It is often the first tool used during network-based reconnaissance in penetration tests.

## Host discovery

Host discovery is the process of identifying live systems on a network and is often the first step during internal network assessments.

### ICMP-Based Discovery

The most common method is sending **ICMP Echo Requests** (ping). 

CIDR notation is used to specify network ranges.

**Example:**

```bash
nmap 10.129.2.0/24 -sn -oA hosts
```

The **-sn** flag disables port scanning, while **-oA** saves output in all major formats.

![Filtered output](.images/nmap2.PNG)

### Extracting Live Hosts

To extract only IP addresses and hostnames from the output:

```bash
nmap 10.129.2.0/24 -sn | grep for | cut -d " " -f5
```

![Filtered output](.images/nmap1.PNG)

### Scanning From a Host List

During engagements, a list of in-scope hosts is often provided.

Nmap supports scanning from a file:

```bash
nmap -sn -iL hosts.txt | grep for | cut -d " " -f5
```

### Multiple Hosts and Host Ranges

Multiple hosts:

```bash
nmap -sn 10.129.2.18 10.129.2.19 10.129.2.20 | grep for | cut -d" " -f5
```

IP range:

```bash
nmap -sn 10.129.2.18-20 | grep for | cut -d" " -f5
```

### Debugging Host Discovery

View sent and received packets:

```bash
nmap 10.129.2.18 -sn --packet-trace
```

![Filtered output](.images/nmap3.PNG)

Understand why a host is marked as "up":

```bash
nmap 10.129.2.18 -sn --reason
```

![Filtered output](.images/nmap4.PNG)

### Forcing ICMP Discovery

On local networks, Nmap may default to ARP scanning.

To force ICMP Echo Requests:

```bash
nmap 10.129.2.18 -sn -PE --disable-arp-ping
```

---

## Port Scanning

After identifying live hosts, the next step is to enumerate:

- Open ports
- Running services
- Operating system information

**Port states:**

| State             | Description                                             |
| ----------------- | ------------------------------------------------------- |
| `open`            | `Connection established`                                |
| `closed`          | `No service listening`                                  |
| `filtered`        | `Usually indicates firewall silently dropping packets`  |
| `unfiltered`      | `Port reachable, but can't determine open/closed state` |
| `open/filtered`   | `No response (possible firewall)`                       |
| `closed/filtered` | `Indeterminate state`                                   |

Filtered states are common when firewalls silently drop packets.

### Default Scan Behavior

By default, Nmap performs a **TCP SYN scan** (-sS) on the top 1000 ports when run as root.

- Sends SYN
- Receives SYN/ACK (open)
- Terminates with RST
- Does not complete the TCP handshake

This makes it relatively stealthy.

**Example:**

```bash
sudo nmap 10.129.2.49
```

![Filtered output](.images/nmap5.PNG)

Without root privileges, Nmap falls back to a **TCP Connect scan** (-sT), which completes the handshake and is more easily logged.

### Port Selection

| Syntax            | Description       |
| ----------------- | ------------------|
| `-p-`             | `All 65535 ports` |
| `-p 22`           | `Single port`     |
| `-p 21,22,80`     | `Multiple ports`  |
| `-p 21-8080`      | `Port range`      |

**Example:**

```bash
nmap 10.129.2.49 -p 22,80,445
```

---

## Service and OS Detection

To gather additional information about discovered services:

| Flag              | Description                      |
| ----------------- | -------------------------------- |
| `-sV`             | `Service and version detection`  |
| `-O`              | `Operating system detection`     |

OS detection requires at least one open and one closed port to be reliable.

**Example:**

```bash
nmap 10.129.2.49 -p 22,80,445 -sV -O
```

![Filtered output](.images/nmap6.PNG)

---

## Nmap Scripting Engine (NSE)

Nmap includes hundreds of scripts for advanced enumeration and vulnerability discovery.

| Template         | Description                       |
| ---------------- | --------------------------------- |      
| `auth`           | `Authentication checks`           |
| `broadcast`      | `Broadcast-based host discovery`  |
| `brute`          | `Brute force attacks`             |
| `default`        | `Default safe scripts (-sC)`      |
| `discovery`      | `Network discovery`               |
| `dos`            | `Denial-of-service`               |
| `exploit`        | `Active exploitation`             |
| `external`       | `Third-party communication`       |
| `fuzzer`         | `Fuzzing`                         |
| `intrusive`      | `Potentially disruptive scripts`  |
| `malware`        | `Malware detection`               |
| `safe`           | `Non-intrusive scripts`           |
| `version`        | `Version detection`               |
| `vuln`           | `Vulnerability identification`    |

### Common NSE Usage

**Run default scripts:**

```bash
nmap 10.129.2.49 -sC
```

**Run host scripts only:**

```bash
nmap 10.129.2.49 -sn -sC
```

**Run a specific script:**

```bash
nmap 10.129.2.49 -p 445 --script smb-os-discovery
```

**Run a category of scripts:**

```bash
nmap 10.129.2.49 --script vuln
```

**Use wildcards:**

```bash
nmap 10.129.2.49 -p 80,443 --script "http-*"
```

---

## Timing and Performance

Nmap provides extensive control over scan timing and performance.

Fine-tuning options:

| Flag                 | Description             |
| -------------------- | ----------------------- |
| `--script-timeout`   | `Max script runtime`    |
| `--scan-delay`       | `Delay between packets` |
| `--max-rate`         | `Packets per second`    |
| `--max-retries`      | `Retransmission limit`  |
| `--host-timeout`     | `Abort scan per host`   |     

**Examples:**

```bash
nmap 10.129.2.49 -p 22,80,445 --script-timeout 5s
```

```bash
nmap 10.129.2.49 -p 22,80,445 --scan-delay 10s
```

```bash
nmap 10.129.2.49 -p 22,80,445 --max-rate 2
```

```bash
nmap 10.129.2.49 -p 22,80,445 --max-retries 1
```

```bash
nmap 10.129.2.49/24 --host-timeout 10s
```

### Timing Templates

NMAP also offer **timing templates** for an easier and more convenient way to control timing and performance.

**Timing templates:**

| Template        | Description        |
| ----------------| ------------------ |
| `-T0`           | `Paranoid`         |
| `-T1`           | `Sneaky`           |
| `-T2`           | `Polite`           |
| `-T3`           | `Normal (default)` |
| `-T4`           | `Aggressive`       |
| `-T5`           | `Insane`           |

The **paranoid** and **sneaky** options may be useful for IDS/IPS evasion, but are quite slow. If you're on a decent ethernet connection and not concerned about being stealthy, you are advised to use the **aggressive** option.

**Example:**

```bash
nmap 10.129.2.49 -p- -T4
```

---

## IDS/IPS Evasion

There are several techniques utilized for IDS/IPS evasion. But it's important to keep in mind that many IDS/IPS systems can still detect these techniques through behavioral analysis.

### Decoys

Generate random decoy IP addresses:

```bash
nmap 10.129.2.49 -p 80 -D RND:5
```

### Spoofing Source IP

Change source IP address: 

```bash
nmap 10.129.2.49 -p 80 -S 10.129.2.200
```

### Source Port Manipulation

DNS traffic (port 53) is often trusted:

```bash
nmap 10.129.2.49 -p 80 -sV --source-port 53
```

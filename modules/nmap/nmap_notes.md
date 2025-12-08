# Network Enumeration with NMAP

---

## Host discovery

**Host discovery** is the process of discovering systems on a network. This is usually a good starting point when conducting internal penetration tests.

The most common host discovery method is probing with **ICMP Echo Requests**, also known as **ping**. The following example utilizes **ping** to probe an entire network for online systems. The network subnet mask is specified in **CIDR** notation.

```
nmap 10.129.2.0/24 -sn -oA hosts
```

The **-oA** flag saves the output in all major formats.

![Filtered output](images/nmap2.PNG)

By adding **grep** and **cut** we can filter out the relevant information, and end up with a clean list of only IP addresses and domain names.

```
nmap 10.129.2.0/24 -sn | grep for | cut -d " " -f5
```

![Filtered output](images/nmap1.PNG)

During penetration tests it is not uncommon to be provided with a list of **in-scope hosts**. Nmap can scan directly from a list of IP addresses with the **-iL** flag.

```
nmap -sn -iL hosts.txt | grep for | cut -d " " -f5
```

**Multiple IP addresses** can be specified by listing them one after the other.

```
nmap -sn 10.129.2.18 10.129.2.19 10.129.2.20 | grep for | cut -d" " -f5
```

If the IP addresses of interest are **adjacent** to one another a range can be specified in the last octet.

```
nmap -sn 10.129.2.18-20| grep for | cut -d" " -f5
```

To get an overview of all packages sent and received the **--packet-trace** flag is used.

```
nmap 10.129.2.18 -sn --packet-trace
```

![Filtered output](images/nmap3.PNG)

To determine why NMAP has labeled a host as **"up"**, we can utilize the **--reason** flag.

```
nmap 10.129.2.18 -sn --reason
```

![Filtered output](images/nmap4.PNG)

On a local network NMAP might determine the status of a host through **ARP Requests**, even though we told NMAP to use **ICMP Echo Requests**. Use the **-PE** and **--disable-arp-ping** flags to force NMAP to use **ICMP**.

```
nmap 10.129.2.18 -sn -PE --disable-arp-ping
```

---

## Port Scanning

Once a target has been identified through the **host discovery process**, we want to get a more accurate picture of that system. This includes information about:

- **Open ports**
- **Services**
- **Operating systems**

A scanned port is assigned one of six different states:

| State             | Description                                                  |
| ----------------- | ------------------------------------------------------------ |
| `open`            | `Connection to port established`                             |
| `closed`          | `Connection to port not established`                         |
| `filtered`        | `Port returns no response or an error code`                  |
| `unfiltered`      | `Port is accessible but not able to conclude if open/closed` |
| `open/filtered`   | `No response (indication of firewall)`                       |
| `closed/filtered` | `Unable to determine if closed or filtered by firewall`      |

By default NMAP scans the top 1000 TCP ports using the **TCP-SYN** scan, also known as the **Stealth Scan** (**-sS**). This scan is relatively unobtrusive and stealthy since it never completes a full TCP handshake. NMAP initiates the first step in the TCP **three-way handshake** by sending a TCP packet with the **SYN** flag set. If the target port is open it will respond by sending a packet with the **SYN** and **ACK** flags back. Instead of finalizing the handshake by sending a TCP ACK, NMAP will send a packet with the **RST** flag set in order to terminate the connection attempt.

It might be good to know that the **-sS** scan is only the default option when NMAP is executed with **root privileges**. This is because of socket permissions required to create raw TCP packets. Otherwise NMAP will run a **TCP Connect Scan** (**-sT**) as the default option. This scan actually completes the TCP three-way handshake, making it slower and **more likely to get logged** by the target system. Most IDS/IPS solutions can easily detect a TCP Connect Scan.

```
sudo nmap 10.129.2.49
```

![Filtered output](images/nmap5.PNG)

The **-p** flag is used to specify which ports to scan.

| Syntax            | Description       |
| ----------------- | ------------------|
| `-p-`             | `All 65535 ports` |
| `-p 22`           | `Specific port`   |
| `-p 21,22,80`     | `List of ports`   |
| `-p 21-8080`      | `Range of ports`  |

```
nmap 10.129.2.49 -p 22,80,445
```

To get additional information from open ports we can utilize the **-O** and **-sV** flags.

| Flag              | Description                              |
| ----------------- | -----------------------------------------|
| `-O`              | `Enable OS detection`                    |
| `-sV`             | `Enable service and version detection`   |

```
nmap 10.129.2.49 -p 22,80,445 -sV -O
```

![Filtered output](images/nmap6.PNG)

---

## NMAP Scripting Engine (NSE)

NMAP comes equipped with a bunch of **scripts** that can be run against the target. There are a total of **14** different script categories.

| Template        | Description                                                                        |
| ----------------| ---------------------------------------------------------------------------------- |      
| `auth`           | `Authentication and bypassing (non bruteforce)`                                   |
| `broadcast`      | `Host discovery through broadcasting`                                             |
| `brute`          | `Brute force attacks`                                                             |
| `default`        | `Collection of default scripts (-sC)`                                             |
| `discovery`      | `Network discovery`                                                               |
| `dos`            | `Denial of service`                                                               |
| `exploit`        | `Active exploitation`                                                             |
| `external`       | `Scripts that communicate with third party resources`                             |
| `fuzzer`         | `Fuzzing scripts`                                                                 |
| `intrusive`      | `Scripts with high risk of crashing target system`                                |
| `malware`        | `Scripts that test for malware infections and backdoors`                          |
| `safe`           | `Safe scripts that do not crash target systems or use large amounts of bandwidth` |
| `version`        | `Version detection extension`                                                     |
| `vuln`           | `Scripts that identify vulnerabilities (no exploitation)`                         |

Run **default scripts** on 1000 most common ports.

```
nmap 10.129.2.49 -sC
```

Disable port scanning and only run default **host** scripts.

```
nmap 10.129.2.49 -sn -sC
```

Run a **specific** script.

```
nmap 10.129.2.49 -p 445 --script smb-os-discovery
```

Run all scripts from a **specific category**.

```
nmap 10.129.2.49 --script vuln
```

Use **wildcards** to select specific script from the script database.

```
nmap 10.129.2.49 -p 80,443 -script "http-*"
```

---

## Fine Tuning (Timing and Performance)

NMAP has many options for timing and performance. Some of the most common options for **fine-grained** control are:

| Flag                 | Description                                                                                |
| -------------------- | ------------------------------------------------------------------------------------------ |
| `--script-timeout`   | `Set a ceiling on script execution time. Useful for efficiency.`                           |
| `--scan-delay`       | `Wait given amount of time between packets. Useful for evading threshold based IDS/IPS.`   |
| `--max-rate`         | `Limit number of packets sent per second. Useful for stealth and BBH.`                     |
| `--max-retries`      | `Maximum number of retransmissions in case of no response. Useful for efficiency.`         |
| `--host-timeout`     | `Abondon host after specified amount of time (ms, s, m). Useful for efficieny.`            |

```
nmap 10.129.2.49 -p 22,80,445 --script-timeout 5s
```

```
nmap 10.129.2.49 -p 22,80,445 --scan-delay 10s
```

```
nmap 10.129.2.49 -p 22,80,445 --max-rate 2
```

```
nmap 10.129.2.49 -p 22,80,445 --max-retries 1
```

```
nmap 10.129.2.49/24 --host-timeout 10s
```

NMAP also offer **timing templates** for an easier and more convenient way to control timing and performance. There are 6 different timing templates.

| Template        | Description        |
| ----------------| ------------------ |
| `-T0`           | `Paranoid`         |
| `-T1`           | `Sneaky`           |
| `-T2`           | `Polite`           |
| `-T3`           | `Normal (default)` |
| `-T4`           | `Aggressive`       |
| `-T5`           | `Insane`           |

The **paranoid** and **sneaky** options may be useful for IDS/IPS evasion, but are quite slow. Cautious scanners are advised to use the **normal** (**-T3**) option. If you're on a decent ethernet connection and not concered about being stealthy, you are advised to use the **aggressive** (**-T4**) option.

```
nmap 10.129.2.49 -p- -T4
```

---

## IDS/IPS Evasion

If you're blocked by an IPS, or if your target simply blocks IP addresses from a specific region, you can utilize **decoys** in an attempt to evade these restrictions. NMAP can generate random IP addresses and insert them into the IP header in order to disguise the true source of the packet.

The following example creates 5 random decoys.

```
nmap 10.129.2.49 -p 80 -D RND:5
```

Another option is to attempt evasion by simply changing the source IP address with the **-S** flag. 

```
nmap 10.129.2.49 -p 80 -S 10.129.2.200
```

A third option is utilizing DNS proxying. We can specify port **53** as the source port and communicate with the target from that port. DNS traffic is **often trusted** since most servers are supposed to be found and visited. 

```
nmap 10.129.2.49 -p 80 --source-port 53
```
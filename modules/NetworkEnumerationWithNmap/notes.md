# Network Enumeration with NMAP

---

## Host discovery

**Host discovery** is utilized to discover systems on a network. This is usually a good starting point when conducting internal penetration tests.

The most basic host discovery method is **ICMP Echo Requests**, also known as **ping**. The following example utilizes **ping** to probe an entire network for online systems.

```
nmap 10.129.2.0/24 -sn -oA hosts
```

The **-oA** flag saves the output in all major formats.

![Filtered output](images/nmap2.PNG)

By adding **grep** and **cut** we can filter out the relevant information, and end up with a clean list of only IP addresses and domain names.

```
nmap 10.129.2.0/24 -sn oA hosts | grep for | cut -d " " -f5
```

![Filtered output](images/nmap1.PNG)

During penetration tests it is not uncommon to be provided with a list of **in-scope hosts**. Nmap can scan directly from a list of IP addresses with the **-iL** flag.

```
nmap -sn oA hosts -iL hosts.txt | grep for | cut -d " " -f5
```

**Multiple IP addresses** can be specified by listing them one after the other.

```
nmap -sn -oA hosts 10.129.2.18 10.129.2.19 10.129.2.20 | grep for | cut -d" " -f5
```

If the IP addresses of interest are adjacent to one another a range can be specified in the last octet.

```
nmap -sn -oA hosts 10.129.2.18-22| grep for | cut -d" " -f5
```

To get an overview of all packages sent and received the **--packet-trace** flag can be used.

```
nmap 10.129.2.18 -sn -oA hosts --packet-trace
```

![Filtered output](images/nmap3.PNG)

# Network Enumeration with NMAP

My notes from HTB module **Network Enumeration with NMAP**.

---

## Host discovery

**Host discovery** is utilized to discover systems on a network. This is usually a good starting point when conducting internal penetration tests.

The most basic host discovery method is **ICMP Echo Requests**, also known as **ping**. The following example utilizes **ping** to probe an entire network for online systems:

```
nmap 10.129.2.0/24 -sn -oA hosts
```

The **-oA** flag saves the output in all major formats.

By adding **grep** and **cut** we can filter out the relevant information, and end up with a clean list of only IP addresses and domain names.

```
nmap 10.129.2.0/24 -sn oA hosts | grep for | cut -d " " -f5
```

![Filtered output](images/nmap1.PNG)

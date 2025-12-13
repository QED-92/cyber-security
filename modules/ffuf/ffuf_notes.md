# Attacking Web Applications with FFUF

These notes summarize practical techniques for attacking web applications using ffuf, as covered in the HTB module *Attacking Web Applications with ffuf*.

## Wordlists

On most HTB and Kali Linux systems, commonly used wordlists are located in:

- **/opt/useful/seclists/**
- **/usr/share/wordlists/**

Choosing the correct wordlist is critical and depends on the fuzzing objective (directories, extensions, parameters, etc.).

---

## Directory Fuzzing

Directory fuzzing is used to discover hidden directories on a web server.

Common wordlists:

- **directory-list-2.3-small/medium/big.txt**
- **raft-small/medium/large-directories.txt**

Basic syntax:

```bash
ffuf -w <WORDLIST>:FUZZ -u http://<IP>:<PORT>/FUZZ
```

Some wordlists contain commented lines that may clutter results. Use the **-ic** flag to ignore comments:

```bash
ffuf -w directory-list-2.3-small.txt:FUZZ -u http://94.237.61.242:8080/FUZZ -ic
```

---

## Extension Fuzzing

Extension fuzzing is used to discover valid file extensions and is typically performed before page fuzzing.

Common wordlists:

- **web-extensions.txt**
- **web-extensions-big.txt**
- **raft-small/medium/large-extensions.txt**
- **file-extensions-all-cases.txt**

Basic syntax:

```bash
ffuf -w <WORDLIST>:FUZZ -u http://<IP>:<PORT>/<FILE>FUZZ
```

The **index** file is commonly present and often used as a base

```bash
ffuf -w web-extensions.txt:FUZZ -u http://94.237.61.242:8080/indexFUZZ
```

---

## Page Fuzzing

Page fuzzing is used to enumerate hidden pages once valid extensions are known.

Common wordlists for page fuzzing include the **same ones used for directory fuzzing**.

Basic syntax:

```bash
ffuf -w <WORDLIST>:FUZZ -u http://<IP>:<PORT>/FUZZ.<EXT>
```

Example:

```bash
ffuf -w directory-list-2.3-small.txt:FUZZ -u http://94.237.61.242:8080/blog/FUZZ.php -ic
```

If no extensions were discovered earlier during extension fuzzing, wordlists that combine filenames and extensions can be used:

- **raft-small/medium/large-files.txt**

---

## Recursive Fuzzing

Recursive fuzzing automatically continues enumeration whenever a new directory is discovered, combining directory, page, and extension fuzzing.


It it advised to specify a recursion depth to avoid excessive requests.

Basic syntax:

```bash
ffuf -w <WORDLIST>:FUZZ -u http://<IP>:<PORT>/FUZZ -recursion
```

Useful flags:

- **-recursion-depth**
- **-e (extensions)**
- **-v (verbose)**

Example:

```bash
ffuf -w directory-list-2.3-small.txt:FUZZ -u http://94.237.61.242:8080/FUZZ -recursion -recursion-depth 3 -e .php -v -ic
```

---

## Subdomain Fuzzing

HTB lab domains are not publicly indexed by DNS. To resolve a domain, it must be mapped in the **/etc/hosts** file.

Example:

```bash
echo "94.237.61.242 inlanefreight.htb" | sudo tee -a /etc/hosts
```

Common wordlists:

- **subdomains-top1million-5000/20000/110000.txt**

Basic syntax:

```bash
ffuf -w <WORDLIST>:FUZZ -u http://FUZZ.<IP/DOMAIN>:<PORT>
```

Example (public DNS only):

```bash
ffuf -w subdomains-top1million-5000.txt:FUZZ -u https://FUZZ.inlanefreight.com/
```

This approach does not work reliably in HTB labs due to missing DNS records.

---

## Virtual Host (VHOST) Fuzzing

VHOST fuzzing is the preferred method for subdomain discovery in HTB environments. Virtual hosts share the same IP address and are distinguished by the **Host HTTP header**.

Basic syntax:

```bash
ffuf -w <WORDLIST>:FUZZ -u http://<IP/DOMAIN>:<PORT>/ -H 'Host: FUZZ.<DOMAIN>'
```

Example:

```bash
ffuf -w subdomains-top1million-5000.txt:FUZZ -u http://academy.htb:80/ -H 'Host: FUZZ.academy.htb'
```

All requests will typically return **200 OK**. Valid virtual hosts are identified by different response sizes.

Filtering by response size:

- **-fs** &rarr; filter size
- **-ms** &rarr; match size

```bash
ffuf -w subdomains-top1million-5000.txt:FUZZ -u http://academy.htb:80/ -H 'Host: FUZZ.academy.htb' -fs 900
```

Any discovered subdomains should be added to the **/etc/hosts** file:

```bash
echo "<IP> <DOMAIN>" | sudo tee -a /etc/hosts
```

---

## Parameter Fuzzing (GET)

GET parameters are appended to the URL after a **?**.

Example:

```
http://admin.academy.htb:80/admin/admin.php?parameter=key
```

Common wordlists:

- **burp-parameter-names.txt**
- **fuzz-lfi-params-list.txt**

Basic syntax:

```bash
ffuf -w <WORDLIST>:FUZZ -u <DOMAIN>:<PORT>/<PATH>?FUZZ=value
```

```bash
ffuf -w burp-parameter-names.txt:FUZZ -u http://admin.academy.htb:8080/admin/admin.php?FUZZ=key
```

---

## Parameter Fuzzing (POST)

POST parameters are sent in the request body.

For PHP applications, the following **Content-Typ header** is required:

- **Content-Type: application/x-www-form-urlencoded**

Example:

```bash
ffuf -w burp-parameter-names.txt:FUZZ -u http://admin.academy.htb:8080/admin/admin.php -X POST -d 'FUZZ=key' -H 'Content-Type: application/x-www-form-urlencoded'
```

For complex requests, capture the request using a proxy (e.g., Burp Suite), replace the desired value with FUZZ, and save it to a file.

Required flags:

- **-request**
- **-request-proto**

Basic syntax:

```bash
ffuf -w <WORDLIST>:FUZZ -request <FILE> -request-proto <PROTOCOL>
```

Example:

```bash
ffuf -w burp-parameter-names.txt:FUZZ -request req.txt -request-proto http
```

---

## Value Fuzzing

Once a valid parameter is identified, the next step is to fuzz its value.

For numeric IDs, a simple wordlist can be generated:

```bash
for i in $(seq 1 1000); do echo $i >> ids.txt; done
```

Example:

```bash
ffuf -w ids.txt:FUZZ -u http://admin.academy.htb:PORT/admin/admin.php -X POST -d 'id=FUZZ' -H 'Content-Type: application/x-www-form-urlencoded'
```
---

## Timing and Performance

Web services may enforce rate limits, often returning **HTTP 429** responses.

Relevant flags:

| Flag                 | Description                                   |
| -------------------- | --------------------------------------------- |
| `-p`                 | `Delay between requests (seconds)`            |
| `-rate`              | `Max requests per second`                     |
| `-t`                 | `Number of concurrent threads (default: 40)`  |
| `-se`                | `Stop on spurious errors`                     |

The following example enforces a 1 second pause between requests. Since the default number of concurrent threads is 40, this will amount to 40 requests per second.

**Examples:**

Fixed delay:

```bash
ffuf -w directory-list-2.3-small.txt:FUZZ -p 1 -u http://94.237.61.242/FUZZ 
```

Random delay range:

```bash
ffuf -w directory-list-2.3-small.txt:FUZZ -p 0.5-2.0 -u http://94.237.61.242/FUZZ 
```

Rate-limited:

```bash
ffuf -w directory-list-2.3-small.txt:FUZZ -rate 5 -u http://94.237.61.242/FUZZ 
```

Threads + delay:

```bash
ffuf -w directory-list-2.3-small.txt:FUZZ -t 5 -p 0.1 -u http://94.237.61.242/FUZZ 
```

Stop on excessive errors:

```bash
ffuf -w directory-list-2.3-small.txt:FUZZ -se -rate 100 -u http://94.237.61.242/FUZZ 
```

## Final Notes

ffuf is an extremely flexible and powerful tool.

Effective usage depends on:

- Choosing the correct wordlist
- Understanding the target’s behavior
- Proper filtering and rate control

These techniques form a solid foundation for real-world web enumeration and exploitation.
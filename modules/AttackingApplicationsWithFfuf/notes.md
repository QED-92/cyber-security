# Attacking Web Applications with FFUF

Notes from HTB module **Attacking Web Applications with FFUF**.

On HTB VM's and Kali Linux machines most wordlists can be found in the following directory:

- /opt/useful/seclists/

In the examples below i will simply write the name of the wordlist instead of absolute path.

---

## Directory Fuzzing

Enumerate hidden directories on a web server.

Common wordlists for directory fuzzing include:

- directory-list-2.3-small/medium/big.txt
- raft-small/medium/large-directories.txt

Basic syntax:

```
ffuf -w <WL>:FUZZ -u http://<IP>:<PORT>/FUZZ
```

Some wordlists contain comments at the beginning of the document. These **comments may clutter the results**. Utilize the '**-ic**' flag to ignore such comments.

```
ffuf -w directory-list-2.3-small.txt:FUZZ -u http://94.237.61.242:8080/FUZZ -ic
```

---

## Extension Fuzzing

Enumerate file extensions on a web server. Extension fuzzing is usually performed **before page fuzzing**.

Common wordlists for extension fuzzing include:

- web-extensions.txt
- web-extensions-big.txt
- raft-small/medium/large-extensions.txt
- file-extensions-all-cases.txt

Basic syntax:

```
ffuf -w <WL>:FUZZ -u http://<IP>:<PORT>/<FILE>FUZZ
```

The **index** file is present on most web servers and often used for extension fuzzing:

```
ffuf -w web-extensions.txt:FUZZ -u http://94.237.61.242:8080/indexFUZZ
```

---

## Page Fuzzing

Enumerate hidden pages on a web server. Leveraging the information found during the extension fuzzing process, we can proceed by fuzzing for pages.

Common wordlists for page fuzzing include the **same ones used for directory fuzzing**.

Basic syntax:

```
ffuf -w <WL>:FUZZ -u http://<IP>:<PORT>/FUZZ.<EXT>
```

```
ffuf -w directory-list-2.3-small.txt:FUZZ -u http://94.237.61.242:8080/blog/FUZZ.php -ic
```

If unable to find any file extensions during the extension fuzzing process, you can still fuzz for pages by utilizing wordlists that **combine filenames and extensions**. The following wordlists can be utilized:

- raft-small/medium/large-files.txt

---

## Recursive Fuzzing

Recursive fuzzing combines directory, extension and page fuzzing into one process. A new branch is automatically started whenever a new directory is discovered. This continues until the entire web server has been enumerated.

Recursive fuzzing may save a lot of time, depending on the size of the web server. **Specifying a recursive depth is strongly advised**.

Basic syntax:

```
ffuf -w <WL>:FUZZ -u http://<IP>:<PORT>/FUZZ -recursion
```

Useful flags include:

- -recursion-depth
- -e (extensions)
- -v (verbose)

```
ffuf -w directory-list-2.3-small.txt:FUZZ -u http://94.237.61.242:8080/FUZZ -recursion -recursion-depth 3 -e .php -v -ic
```

---

## Subdomain Fuzzing

Keep in mind that exercises, labs and exams provided by HTB are not hosted on public facing servers, thus, are **not indexed by public DNS servers**. In order to access a domain, it must be resolved to an IP address. The browser first checks the **/etc/hosts** file, and then, if necessary, a public DNS.

In order for DNS resolution to work on a HTB hosted domain an entry must be added to the **/etc/hosts** file:

```
echo "94.237.61.242 inlanefreight.htb" >> /etc/hosts
```

Common wordlists for subdomain fuzzing include:

- subdomains-top1million-5000/20000/110000.txt

Basic syntax:

```
ffuf -w <WL>:FUZZ -u http://FUZZ.<IP/DOMAIN>:<PORT>
```

```
ffuf -w subdomains-top1million-5000.txt:FUZZ -u https://FUZZ.inlanefreight.com/
```

The above method only works on public facing servers. Since we do not know which subdomains exists, we cannot add them to the **/etc/hosts** file.

---

## VHOST Fuzzing

**Vhost fuzzing is the go-to method** for subdomain fuzzing in a HTB environment. A vhost is basically a subdomain served on the same server as the main domain, and thus, has the **same IP-address**. Vhosts allow a single IP-address to serve several different web pages. Vhost fuzzing work by fuzzing the **Host header** in the HTTP request

Basic syntax:

```
ffuf -w <WL>:FUZZ -u http://<IP/DOMAIN>:<PORT>/ -H 'Host: FUZZ.<IP/DOMAIN>'
```

```
ffuf -w subdomains-top1million-5000.txt:FUZZ -u http://academy.htb:80/ -H 'Host: FUZZ.academy.htb'
```

Be aware that when vhost fuzzing we are simply changing the **Host header** while visiting the same page, so, every response will return a **200 OK** whether the vhost exists or not. However, an existing vhost will return a **different response size**.

The following flags are used to filter based on response size:

- -ms (match size)
- -fs (filter size)

```
ffuf -w subdomains-top1million-5000.txt:FUZZ -u http://academy.htb:80/ -H 'Host: FUZZ.academy.htb' -fs 900
```

---

## Parameter Fuzzing (GET)

**GET** parameters are usually passed after the URL, and are initiated by a question mark (?):

```
http://admin.academy.htb:80/admin/admin.php?parameter=key
```

Common wordlists for parameter fuzzing include:

- burp-parameter-names.txt
- fuzz-lfi-params-list.txt

Basic syntax:

```
ffuf -w <WL>:FUZZ -u <IP/DOMAIN>:<PORT>/<DIR><PAGE>?FUZZ=KEY
```

```
ffuf -w burp-parameter-names.txt:FUZZ -u http://admin.academy.htb:8080/admin/admin.php?FUZZ=key
```

---

## Parameter Fuzzing (POST)

**Post requets** are passed in the data field within the HTTP request. When fuzzing **PHP** pages the POST data **must have the following content-type**:

- Content-Type: application/x-www-form-urlencoded

It is good practice to set the above **Content-type** with the **-H** flag.

Basic syntax:

```
ffuf -w burp-parameter-names.txt:FUZZ -u http://admin.academy.htb:8080/admin/admin.php -X POST -d 'FUZZ=key' -H 'Content-Type: application/x-www-form-urlencoded'
```

When POST based fuzzing require complex parameters i highly recommend using FFUF's built-in ability to **parse** files. Simply capture a request with a **web-proxy**, such as BurpSuite. Insert the FUZZ keyword where you want to FUZZ and save the request to file.

The following flags are required for parsing a request from file:

- -request
- -request-proto

Basic syntax:

```
ffuf -w <WL>:FUZZ -request <FILE> -request-proto <PROTOCOL>
```

```
ffuf -w burp-parameter-names.txt:FUZZ -request req.txt -request-proto http
```

---

## Value Fuzzing

After finding a working parameter through **parameter fuzzing**, the next step is usually to fuzz for the correct value (key) to that parameter. The type of value differs depending on the type of parameter, thus, we may not always find a pre-made wordlist. However, for parameters such as user IDs, usernames and passwords, we can probably find a suitable wordlist, or create one ourselves.

User IDs often consists of integer values, so, we can easily create a wordlist with a simple bash one-liner:

```
for i in $(seq 1 1000); do echo $i >> ids.txt; done
```

Basic syntax:

```
ffuf -w ids.txt:FUZZ -u http://admin.academy.htb:PORT/admin/admin.php -X POST -d 'id=FUZZ' -H 'Content-Type: application/x-www-form-urlencoded'
```

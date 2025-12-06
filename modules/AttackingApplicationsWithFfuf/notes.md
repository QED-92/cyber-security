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

Some wordlists contain comments at the beginning of the document. These comments may clutter the results. Utilize the '**-ic**' flag to ignore comments.

```
ffuf -w directory-list-2.3-small.txt:FUZZ -u http://94.237.61.242:8080/FUZZ -ic
```

---

## Extension Fuzzing

Enumerate file extensions on a web server. Extension fuzzing is usually performed before page fuzzing.

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

Common wordlists for page fuzzing include the same ones used for directory fuzzing.

Basic syntax:

```
ffuf -w <WL>:FUZZ -u http://<IP>:<PORT>/FUZZ.<EXT>
```

```
ffuf -w directory-list-2.3-small.txt:FUZZ -u http://94.237.61.242:8080/blog/FUZZ.php -ic
```

If unable to find any file extensions during the extension fuzzing process, you can still fuzz for pages by utilizing wordlists that combine filenames and extensions. The following wordlists can be utilized:

- raft-small/medium/large-files.txt

---

## Recursive Fuzzing

Recursive fuzzing combines directory, extension and page fuzzing into one process. A new branch is automatically started whenever a new directory is discovered. This continues until the entire web server has been enumerated.

Recursive fuzzing may save a lot of time, depending on the size of the web server. Specifying a recursive depth is strongly advised.

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

Keep in mind that exercises, labs and exams provided by HTB are not hosted on public facing servers, and thus, are not indexed by public DNS servers. In order to access a domain, it must first be resolved to an IP address. The browser first checks the **/etc/hosts** file, and then, if necessary, a public DNS.

In order for DNS resolution to work on a HTB hosted domain an entry must first be added to the **/etc/hosts** file:

```
echo “94.237.61.242 inlanefreight.htb” >> /etc/hosts
```

| Tabell           | Primärnyckel     | Beskrivning               |
| ---------------- | ---------------- | ------------------------- |
| `Elevxxxxxx`     | `pnr`            | Elevens personuppgifter   |
| `Kursxxxxxx`     | `kursnamn`       | Kurser                    |
| `KursElevxxxxxx` | `pnr + kursnamn` | Kopplingstabell elev–kurs |

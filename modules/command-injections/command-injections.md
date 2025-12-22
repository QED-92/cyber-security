# Command Injections

This document summarizes core techniques for discovery and exploitation of **command injection vulnerabilities**. This is by no means an exhaustive guide. 

---

## Table of Contents
- [Command Injections](#command-injections)
    - [Overview](#overview)
    - [Basic Discovery and Exploitation](#basic-discovery-and-exploitation)

---

## Overview

Command injection vulnerabilities are among the most critical ones. This type of vulnerability may allow an attacker to execute system commands directly on the back-end server. 

**Sanitization** refers to modifying or filtering user input to remove or escape potentially dangerous characters. **Sanitization** is a common technique used to mitigate command injection attacks; however, **sanitization alone is often insufficient** to fully prevent them. When user input is not properly handled, attackers can utilize special characters to escape the intended context of user input and inject a payload. The payload is then executed as part of the original query.

---

## Basic Discovery and Exploitation

An attacker is attempting to exploit a basic web application that is used to test connectivity to a host. 

![Filtered output](images/target.png)

When interacting with the target, by entering an IP address, it returns the result of a `PING` command.

```
127.0.0.1
```

![Filtered output](images/target2.png)

The input from the attacker appears to be used as input to the `PING` command. The relevant section of source-code probably looks something like this:

```bash
ping -c 1 127.0.0.1
```

This means that user-input is being utilized to execute commands on the back-end server. If there are no **sanitization filters** in place, an attacker can trick the server by appending malicious commands after the original one. 

The following special characters are commonly used to escape the intended context of user input:

| Operator   | URL Encoded Operator   | Description      | Executed Command (first/second/both)     |
| ---------- | ---------------------- | ---------------- |----------------------------------------- |
| `;`        | `%3b`                  | Semicolon        | Both                                     |
| `\n`       | `%0a`                  | New line         | Both                                     |
| `&`        | `%26`                  | Background       | Both                                     |
| `\|`       | `%7c`                  | Pipe             | Both                                     |
| `&&`       | `%26%26`               | AND              | Both (if first command succeeds)         |
| `\|\|`     | `%7c%7c`               | OR               | Second (if first command fails)          |
| ``` `` ``` | `%60%60`               | Sub-shell        | Both (Linux only)                        |
| `$()`      | `%24%28%29`            | Sub-shell        | Both (Linux only)                        |



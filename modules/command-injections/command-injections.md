# Command Injections

This document summarizes core techniques for discovery and exploitation of **command injection vulnerabilities**. This is by no means an exhaustive guide. 

---

## Table of Contents
- [Command Injections](#command-injections)
    - [Overview](#overview)
    - [Basic Discovery and Exploitation](#basic-discovery-and-exploitation)
    - [Filter Evasion](#filter-evasion)
        - [Single Character Filters - Part 1](#single-character-filters---part-1)
        - [Single Character Filters - Part 2](#single-character-filters---part-2)


---

## Overview

Command injection vulnerabilities are among the most critical ones. This type of vulnerability may allow an attacker to execute system commands directly on the back-end server. 

**Sanitization** refers to modifying or filtering user input to remove or escape potentially dangerous characters. **Sanitization** is a common technique used to mitigate command injection attacks; however, **sanitization alone is often insufficient** to fully prevent them. When user input is not properly handled, attackers can utilize special characters to escape the intended context of user input and inject a payload. The payload is then executed as part of the original command.

---

## Basic Discovery and Exploitation

We want to exploit a basic web application that is used to test connectivity to a host. 

![Filtered output](images/target.png)

When interacting with the target, by entering an IP address, it returns the result of a `PING` command.

```
127.0.0.1
```

![Filtered output](images/target2.png)

Our input appears to be used as input to the `PING` command. The relevant section of source-code probably looks something like this:

```bash
ping -c 1 127.0.0.1
```

This means that user-input is being utilized to execute commands on the back-end server. If there are no **sanitization filters** in place, we can trick the server by appending malicious commands after the original one. 

The following special characters are commonly used to escape the intended context of user input:

| Operator   | URL Encoded Operator   | Description      | Executed Command (first/second/both)     |
| ---------- | ---------------------- | ---------------- |----------------------------------------- |
| `;`        | `%3b`                  | Semicolon        | Both                                     |
| `\n`       | `%0a`                  | New-line         | Both                                     |
| `&`        | `%26`                  | Background       | Both                                     |
| `\|`       | `%7c`                  | Pipe             | Both                                     |
| `&&`       | `%26%26`               | AND              | Both (if first command succeeds)         |
| `\|\|`     | `%7c%7c`               | OR               | Second (if first command fails)          |
| ``` `` ``` | `%60%60`               | Sub-shell        | Both (Linux only)                        |
| `$()`      | `%24%28%29`            | Sub-shell        | Both (Linux only)                        |

When testing any of the above operators on the target an error message is displayed:

```
127.0.0.1;id
```

```
Please match the requested format.
```

![Filtered output](images/target3.png)

Some applications perform input validation on the front-end and erroneously neglect sanitization on the back-end. An easy way to check if input validation happens on the front-end or not, is to examine the requests being sent by opening the browsers **Network** tab. If no new requests are being made when sending the payload, input validation is done on the front-end. 

![Filtered output](images/front-end-validation.png)

Front-end validation runs in the user’s browser and provides no real security guarantees. Front-end validation can often be bypassed by sending modified requests directly to the back-end server through a **web proxy**, such as BurpSuite. 

We intercept a request in BurpSuite and modify the POST parameter `ip` to contain a simple URL encoded payload:

```bash
# Original payload
ip=127.0.0.1;whoami

# URL encoded payload
ip=127.0.0.1%3bwhoami
```

![Filtered output](images/front-end-validation-bypass.png)

The application returns the original `PING` output, as well as the output from the injected command:

```
www-data
```

![Filtered output](images/front-end-validation-exploit.png)

---

## Filter Evasion

Blacklist filters are a common mitigation technique against command injection vulnerabilities. A blacklist filter consists of a set of disallowed characters and/or keywords; if user input matches any entry in the blacklist, the request is rejected. Modern applications often combine blacklist-based input filtering with a Web Application Firewall (WAF) to introduce an additional layer of defense.

Despite their prevalence, blacklist filters are inherently fragile. They attempt to block known-bad input rather than enforce what is explicitly allowed, making them susceptible to bypass through alternative encodings, shell features, or overlooked characters.

---

### Single Character Filters - Part 1

In this section, we interact with an updated version of the web application introduced earlier. This version includes additional security controls intended to prevent command injection. When attempting to reuse the previously successful payload, the application rejects the request:

```bash
ip=127.0.0.1%3bwhoami
```

```
Invalid input
```

![Filtered output](images/character-filter.png)

This response differs from the earlier `Please match the requested format` error message, indicating that the payload triggered a security mechanism rather than a simple input validation failure.

The rejected payload contains two potentially suspicious elements:

- A command separator (`;`)
- A system command (`whoami`)

The rejection may be caused by a blacklist entry matching the separator, the command, or both. To determine the exact trigger, we can probe the filter incrementally by submitting minimal payloads and observing the application’s response.

Injecting only a semicolon (`;`) is sufficient to trigger the filter, confirming that this character is blacklisted. Continuing this process with other common command injection operators reveals that the newline character (`\n`) is not filtered and successfully bypasses the blacklist:

```bash
ip=127.0.0.1%0a
```
![Filtered output](images/character-filter-bypass.png)

The newline character acts as a command separator in many shell environments, allowing execution to continue on a new line. However, while the injection operator bypass is successful, attempts to execute commands after the newline fail, indicating the presence of additional filtering mechanisms.

Appending a space character after the newline results in another rejection:

```bash
ip=127.0.0.1%0a+
```

![Filtered output](images/character-filter-bypass2.png)

This behavior is expected, as space characters are frequently blacklisted to prevent argument separation. In shell environments, however, whitespace can often be represented in alternative ways.

One common bypass technique is the use of tab characters (`\t`), which are treated as whitespace by the shell but may not be included in blacklist filters:

```bash
ip=127.0.0.1%0a%09
```

![Filtered output](images/character-filter-bypass3.png)

We successfully bypassed the space filter by using tabs instead! 

Another effective technique is leveraging the `${IFS}` environment variable. The IFS (Internal Field Separator) variable defines how the shell splits input into arguments and, by default, contains whitespace characters:

```bash
ip=127.0.0.1%0a${IFS}
```

![Filtered output](images/character-filter-bypass4.png)

A third approach involves brace expansion. In Bash, brace expansion occurs before command execution and can be used to construct arguments without explicitly including spaces:

```bash
ip=127.0.0.1%0a{ls,-la}
```

At this stage, we have identified one method for bypassing the command separator filter and multiple techniques for bypassing space restrictions:

- `\n` (`%0a`)
- `\t` (`%09`)
- `${IFS}`
- `{arg1, arg2}`

Using these techniques, we can construct payloads that evade the blacklist and successfully execute commands on the back-end server:

```bash
ip=127.0.0.1%0a%09ls%09-la

ip=127.0.0.1%0a${IFS}ls${IFS}-la

ip=127.0.0.1%0a{ls,-la}
```

![Filtered output](images/character-filter-bypass5.png)

This demonstrates how blacklist-based defenses can be systematically bypassed by exploiting shell parsing behavior and alternative representations of filtered characters.

---

### Single Character Filters - Part 2

The previous section focused on bypassing blacklist filters targeting command separators and whitespace. In addition to these characters, many applications also blacklist the forward slash (`/`) and backslash (`\`). These characters are essential for referencing files and directories and are therefore commonly restricted in an attempt to prevent command execution.

In Linux environments, several environment variables contain characters such as slashes (`/`), semicolons (`;`), and colons (`:`). When direct usage of these characters is blocked, they can often be reconstructed indirectly by extracting them from environment variable values.

The `PATH` environment variable is a useful starting point, as it typically contains multiple directory paths separated by colons and includes forward slashes. By printing its value, we can observe the characters it contains:

```bash
echo ${PATH}
```

![Filtered output](images/echo-path.png)

Bash supports substring expansion, allowing individual characters to be extracted from a variable by specifying an offset and length. By extracting a single character starting at index 0, we obtain the forward slash (`/`):

```bash
echo ${PATH:0:1}
```

![Filtered output](images/echo-path2.png)

Similar techniques can be applied to other environment variables such as `HOME`, `PWD`, or `LS_COLORS`, depending on which characters are required.

For example, the `LS_COLORS` variable often contains semicolons. By extracting a single character at the appropriate offset, we can recover the semicolon character (`;`):

```bash
echo ${LS_COLORS:10:1}
```

![Filtered output](images/echo-ls-colors.png)

By dynamically reconstructing blacklisted characters, it becomes possible to build payloads that bypass character-based input filters.

The following payload reconstructs a semicolon using `LS_COLORS` and bypasses whitespace restrictions using `${IFS}`:

```bash
ip=127.0.0.1${LS_COLORS:10:1}${IFS}ls${IFS}-la
```

Similarly, the next payload bypasses a blacklist on the forward slash (`/`) by extracting it from the `PATH` variable and uses alternative whitespace representations to execute a command:

```bash
ip=127.0.0.1%0als%09-al%09${PATH:0:1}home
```

![Filtered output](images/echo-path3.png)

This demonstrates a fundamental weakness of blacklist-based filtering: even when individual characters are blocked, shell features such as parameter expansion allow attackers to reconstruct those characters at runtime. As long as user input is evaluated by a shell interpreter, seemingly restrictive filters can often be bypassed through indirect character generation.

---

### Word Filters
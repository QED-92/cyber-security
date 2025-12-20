# File Inclusion

These notes summarize core techniques for discovery and exploitation of **file inclusion vulnerabilities**. This is by no means an exhaustive guide. 

---

## Overview

Many back-end languages use HTTP parameters to identify which resources are shown on a web page. If the underlying mechanisms are not securely coded, an attacker can manipulate the parameter values and display any file on the back-end server. This is known as a **Local File Inclusion** (LFI) vulnerability. 

## Basic LFI

Many applications allow the user to change the language of the content presented. This is often done through a GET parameter that loads the content from some file, such as **en.php** or **es.php**. 

In the most basic of cases, the attacker may simply change the value of the GET parameter to some other file on the system, such as **/etc/passwd**:

```bash
# Original request
http://94.237.49.23:48568/index.php?language=en.php
```

```bash
# LFI
http://94.237.49.23:48568/index.php?language=../../../../etc/passwd
```

![Filtered output](images/basic-lfi.png)
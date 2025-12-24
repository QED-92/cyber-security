# Cross Site Scripting (XSS)

This document summarizes core techniques for identifying and exploiting **Cross-Site Scripting (XSS)** vulnerabilities. It is intended as a practical reference and does not aim to be an exhaustive guide.

---

## Table of Contents

- [Cross Site Scripting (XSS)](#cross-site-scripting-xss)
  - [Overview](#overview)
  - [Stored XSS](#stored-xss)
  - [Reflected XSS](#reflected-xss)
  - [DOM XSS](#dom-xss)
  - [Automated XSS Discovery](#automated-xss-discovery)

---

## Overview

Cross-Site Scripting (XSS) is one of the most prevalent web application vulnerabilities and has remained a persistent security issue for over two decades. A significant percentage of modern web applications are still affected by XSS in one form or another.

XSS vulnerabilities arise from **improper handling and sanitization of user-controlled input**, allowing attackers to inject malicious JavaScript code that is executed in the context of a victim’s browser. In a typical web application, HTML content is generated on a back-end server and rendered by the client’s browser. If user input is incorporated into this content without adequate validation or encoding, an attacker can inject JavaScript through **input fields or HTTP parameters**. When a victim loads the affected page, the injected script is executed unknowingly within their browser.

XSS payloads are executed **entirely client-side** and do not directly compromise the back-end server. In the case of stored (persistent) XSS, malicious payloads are saved on the server, but execution still occurs only when the content is retrieved and rendered by a client. Because XSS does not typically result in immediate server-side compromise, it is often underestimated or deprioritized by developers. XSS attacks are **constrained to the browser’s JavaScript execution environment** and cannot directly execute system-level commands on the server.

Despite this, XSS can have serious security implications, including:

- Session hijacking
- Credential theft
- Account takeover
- Unauthorized actions performed on behalf of users

There are three primary types of XSS vulnerabilities:

- Stored (Persistent) XSS
- Reflected (Non-Persistent) XSS
- DOM-based XSS

---

## Stored XSS

Stored XSS, also referred to as **persistent XSS**, is generally considered the most **severe** form of cross-site scripting vulnerability. In this scenario, malicious payloads are stored on the back-end server and executed whenever the affected content is retrieved and rendered in a user’s browser. Because the payload is persisted server-side, it survives page refreshes and impacts **every user** who accesses the vulnerable page.

Payloads are typically injected through input fields (e.g., forms, comment sections) or directly via HTTP parameters using a web proxy such as **Burp Suite**. If the injected payload remains present after a page refresh and executes consistently, the vulnerability can be classified as stored XSS.

A common initial discovery payload leverages the JavaScript `alert()` function to confirm code execution. The following example displays the **origin** of the page where the payload executes:

```javascript
// Payload
<script>alert(window.origin)</script>

// Example
task=<script>alert(window.origin)</script>
```

![Filtered output](images/xss-discovery.png)

The same technique can be used to display the user’s **session cookies**, which demonstrates the potential for session hijacking:

```javascript
// Payload
<script>alert(document.cookie)</script>

// Example
task=<script>alert(document.cookie)</script>
```

![Filtered output](images/xss-discovery2.png)

Modern browsers or application-level defenses may block the `alert()` function. In such cases, alternative payloads that do not rely on `alert()` are useful for confirming exploitability.

One such technique uses the HTML `<plaintext>` tag, which causes the browser to render all subsequent content as raw text:

```html
// Payload
<plaintext>

// Example
task=<plaintext>
```

![Filtered output](images/xss-discovery3.png)

Another common discovery payload invokes the browser’s print dialog using the `print()` function:

```javascript
// Payload
<script>print()</script>

// Example
task=<script>print()</script>
```

![Filtered output](images/xss-discovery4.png)

**Note for Defenders:**

Although XSS vulnerabilities execute exclusively **client-side** and do not directly lead to server-side command execution, they remain highly impactful. Stored XSS can enable session theft, credential harvesting, phishing attacks, and full account compromise. As such, it should be treated as a critical security issue despite its client-side execution model.

---

## Reflected XSS

Reflected XSS vulnerabilities are **non-persistent**. While the malicious input is processed by the back-end server, it is **not stored**, and therefore does not persist across page refreshes. As a result, reflected XSS typically impacts only the targeted victim rather than all users of the application.

Reflected XSS often appears in **error messages**, **validation responses**, or **confirmation banners** that include user-supplied input in the response. These messages usually disappear once the page is refreshed, making them good candidates for testing reflected XSS.

When attempting to add a task named `test` in the target application, the server responds with an error message that includes our input:

```
Task 'test' could not be added.
```

![Filtered output](images/xss-reflected.png)

This behavior indicates that the application is **reflecting user input** back into the response without proper output encoding. 

To test for reflected XSS, we can reuse the same discovery payloads used for stored XSS:

```javascript
// Payload
<script>alert(window.origin)</script>

// Example
task=<script>alert(window.origin)</script>
```

![Filtered output](images/xss-reflected2.png)

The payload executes successfully, confirming that injected JavaScript is being interpreted by the browser. Inspecting the page source reveals that the payload is embedded directly in the HTML returned by the server.

![Filtered output](images/xss-reflected3.png)

After refreshing or revisiting the page, the payload is no longer present in the server response. This confirms that the vulnerability is **reflected**, not stored.

![Filtered output](images/xss-reflected4.png)

Because reflected XSS payloads are not stored on the server, they must be delivered to the victim at the time of execution. This is typically achieved by embedding the payload in a **crafted URL** and convincing the victim to visit it (for example, via phishing or social engineering).

If the input is accepted through a GET parameter, a malicious URL may look like this:

```
http://94.237.60.55:51429/index.php?task=<script>alert(window.origin)</script>
```

When the victim visits the link, the payload is reflected by the server and executed in the victim’s browser.

---

## DOM XSS

DOM-based XSS (Document Object Model XSS) is a **non-persistent** client-side vulnerability. Unlike **reflected XSS**, DOM XSS does not involve the back-end server at all. The vulnerability exists entirely within client-side JavaScript that processes user-controlled input and dynamically modifies the page.

The DOM is a programming interface that represents a web page as a tree of objects (nodes). JavaScript can read from and write to these nodes to dynamically update content. DOM XSS vulnerabilities occur when JavaScript reads user-controlled input and writes it back to the page without proper sanitization.

When attempting to add a task named `test`, we observe that the application updates the URL using a fragment identifier (`#`):

```
http://94.237.57.115:55333/#task=test
```

![Filtered output](images/dom-xss.png)

The `#` character indicates a **client-side parameter** (URL fragment). Fragment identifiers are processed entirely by the browser and are **never sent to the server** as part of an HTTP request. This behavior strongly suggests a DOM-based vulnerability.

Two key concepts are central to understanding DOM XSS:

- Source: A JavaScript object that reads user-controlled input (e.g., `document.URL`, `location.hash`)
- Sink: A JavaScript function or property that writes data to the DOM

If user input flows from a source to a sink without sanitization, a DOM XSS vulnerability may exist.

Common sink functions and properties include:

- document.write()
- element.innerHTML
- element.outerHTML
- add()
- after()
- append()

Reviewing the page source reveals that user input is extracted from the `task` parameter (source) and written to the page using `innerHTML` (sink):

```javascript
var pos = document.URL.indexOf("task=");
var task = document.URL.substring(pos + 5, document.URL.length);
document.getElementById("todo").innerHTML = "<b>Next Task:</b> " + decodeURIComponent(task);
```

![Filtered output](images/dom-xss2.png)

Because the application uses `innerHTML` without sanitization, user-controlled input is injected directly into the DOM, creating a DOM XSS vulnerability.

The `innerHTML` sink does not allow execution of `<script>` tags. As a result, traditional `<script>`-based payloads will not work in this context.

However, JavaScript execution can still be achieved by injecting HTML elements with event handlers. For example, the `onerror` attribute of an `<img>` element executes JavaScript when the image fails to load. By specifying an invalid image source, the error condition is guaranteed.

```javascript
// Payloads
<img src="" onerror=alert(window.origin)>

<img src="" onerror=alert(document.cookie)>
```

```javascript
// Examples
task=<img src="" onerror=alert(window.origin)>

task=<img src="" onerror=alert(document.cookie)>
```

![Filtered output](images/dom-xss3.png)

Because DOM XSS vulnerabilities are **non-persistent**, payloads must be delivered **at the time of execution**. This is typically accomplished by crafting a malicious URL and persuading a victim to visit it (e.g., via phishing or social engineering).

An example crafted URL may look like this:

```
http://94.237.57.115:55333/#task=<img src="" onerror=alert(window.origin)>
```

When the victim opens the link, the browser processes the fragment identifier, the vulnerable JavaScript executes, and the payload runs in the victim’s browser.

## Automated XSS Discovery

Manual testing is essential for understanding XSS vulnerabilities, but it can be time-consuming when assessing large applications with many parameters. Automated tools help speed up the discovery process and identify potential injection points that warrant further manual verification.

`XSStrike` is a well-known, actively maintained tool designed specifically for advanced XSS detection. Unlike basic scanners, it uses context-aware analysis and payload generation to reduce false positives and improve detection accuracy.

Download and install `XSStrike`:

```bash
git clone https://github.com/s0md3v/XSStrike.git
cd XSStrike
pip install -r requirements.txt
```

To test a single parameter for XSS, provide a target URL using the `-u` flag:

```bash
python xsstrike.py -u "http://94.237.50.221:32974/index.php?task=test"
```

`XSStrike` will analyze how the input is reflected in the response, identify injection contexts, and attempt to generate payloads tailored to the application’s filtering behavior.

If a URL contains multiple parameters, `XSStrike` will automatically enumerate and test each one:

```bash
python xsstrike.py -u "http://94.237.50.221:32974/?fullname=Test&username=Tester&password=123&email=test%40tester.com"
```

![Filtered output](images/dom-xss4.png)

In this case, XSStrike identified a reflected XSS vulnerability in the email parameter. The tool then generated multiple payloads suitable for the detected injection context.

![Filtered output](images/dom-xss5.png)

---


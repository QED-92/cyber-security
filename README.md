# Cross Site Scripting (XSS)

This document summarizes core techniques for identifying and exploiting **Cross-Site Scripting (XSS)** vulnerabilities. It is intended as a practical reference and does not aim to be an exhaustive guide.

---

## Table of Contents

- [Cross Site Scripting (XSS)](#cross-site-scripting-xss)
  - [Overview](#overview)
  - [Stored XSS](#stored-xss)

---

## Overview

Cross-Site Scripting (XSS) is one of the most prevalent web application vulnerabilities and has remained a persistent security issue for over two decades. A significant percentage of modern web applications are still affected by XSS in one form or another.

XSS vulnerabilities arise from **improper handling and sanitization of user-controlled input**, allowing attackers to inject malicious JavaScript code that is executed in the context of a victim’s browser. In a typical web application, HTML content is generated on a back-end server and rendered by the client’s browser. If user input is incorporated into this content without adequate validation or encoding, an attacker can inject JavaScript through **input fields or HTTP parameters**. When a victim loads the affected page, the injected script is executed unknowingly within their browser.

XSS payloads are executed **entirely client-side** and do not directly compromise the back-end server. In the case of stored (persistent) XSS, malicious payloads are saved on the server, but execution still occurs only when the content is retrieved and rendered by a client. Because XSS does not typically result in immediate server-side compromise, it is often underestimated or deprioritized by developers. XSS attacks are constrained to the browser’s JavaScript execution environment and cannot directly execute system-level commands on the server.

Despite this, XSS can have serious security implications, including:

- Session hijacking
- Credential theft
- Account takeover
- Unauthorized actions performed on behalf of users

There are three primary types of XSS vulnerabilities:

- Stored (Persistent) XSS
- Reflected (Non-Persistent) XSS
- DOM-based XSS

## Stored XSS

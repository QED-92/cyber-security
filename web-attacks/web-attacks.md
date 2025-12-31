# Web Attacks

This document covers common techniques for identifying and exploiting **web vulnerabilities**. It is intended as a practical, hands-on reference rather than a comprehensive theoretical guide.

---

# Table of Contents

- [Web Attacks](#web-attacks)
    - [Overview](#overview)
    - [HTTP Verb Tampering - Overview](#http-verb-tampering---overview)


---

## Overview

Three common web attacks include:

- HTTP Verb Tampering
- Insecure Direct Object Reference (IDOR)
- XML External Entity (XXE) Injection

**HTTP verb tampering** exploits web servers that accept unexpected or unsupported HTTP methods. By sending malicious requests using alternative HTTP verbs, an attacker may bypass access controls, authentication checks, or security filters that are only enforced for specific methods (such as `GET` or `POST`).

**Insecure Direct Object Reference (IDOR)** is one of the most prevalent web vulnerabilities. IDOR occurs when an application exposes direct references to internal resources on the back-end server. These resources are often identified using predictable values such as numeric IDs. By manipulating these identifiers, an attacker may gain unauthorized access to other users’ data or restricted resources

**XML External Entity (XXE) injection** vulnerabilities arise when applications process XML input using outdated or insecure XML parsers. In such cases, an attacker may be able to inject malicious XML entities to read local files from the back-end server or interact with internal systems.

---

## HTTP Verb Tampering - Overview

The HTTP protocol supports multiple request methods, commonly referred to as **HTTP verbs**. Web applications are typically configured to accept specific verbs for particular functionalities and perform different actions depending on the method used.

The most common HTTP methods are `GET` and `POST`. However, an attacker can send **any valid HTTP method** and observe how the application responds. If the application or back-end server is not properly configured to handle unexpected or uncommon HTTP methods, this behavior may be abused to bypass security controls.

There are a total of **nine standard HTTP methods**. Aside from `GET` and `POST`, the most commonly encountered include:

| Verb            | Description                                                   |
| ----------------| --------------------------------------------------------------|
| `HEAD`          | Similar to `GET` but returns only HTTP headers                |
| `PUT`           | Writes a resource to a specified location                     |
| `DELETE`        | Deletes a resource at a specified location                    |
| `OPTIONS`       | Returns the HTTP methods supported by the server              |
| `PATCH`         | Applies a partial modification to a resource                  |

If not properly restricted, methods such as `PUT` or `DELETE` may allow an attacker to write or delete files on the back-end server.

HTTP verb tampering vulnerabilities typically arise due to **misconfigurations** in either the web server or the application logic itself. 

In some cases, server-side authentication controls are applied only to specific HTTP methods. This may leave other methods accessible without authentication. For example, the following Apache configuration restricts access only for `GET` and `POST` requests:

```xml
<Limit GET POST>
    Require valid-user
</Limit
```

In this configuration, requests using `GET` and `POST` require authentication. However, an attacker may attempt to use another HTTP method, such as `HEAD`, to access the same resource and potentially bypass authentication controls.

Applications may also be vulnerable due to **insecure or incomplete input validation logic** that does not account for all HTTP methods. For example, the following filter attempts to mitigate SQL injection:

```php
$pattern = "/^[A-Za-z\s]+$/";

if(preg_match($pattern, $_GET["code"])) {
    $query = "Select * from ports where port_code like '%" . $_REQUEST["code"] . "%'";
    ...SNIP...
}
```

In this case, the input validation is applied only to parameters received via `GET`. An attacker could still inject malicious SQL payloads by supplying the code parameter via a `POST` request, effectively bypassing the filter.

---
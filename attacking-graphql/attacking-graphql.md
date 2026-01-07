# GraphQL

This document outlines common techniques for identifying and exploiting vulnerabilities related to **GraphQL**. It is intended as a practical, hands-on reference rather than a comprehensive theoretical guide.

---

# Table of Contents

- [GraphQL](#graphql)
    - [Overview](#overview)

---

## Overview

GraphQL is a **query language for APIs** and is commonly used as an alternative to **Representational State Transfer (REST)**. Unlike REST, which exposes multiple endpoints for different resources, GraphQL APIs typically operate through a **single endpoint** that handles all queries and mutations.

GraphQL queries can be used to **read, create, update, and delete data**, offering increased efficiency in both resource utilization and request handling compared to traditional REST-based APIs.

A GraphQL service is commonly exposed at endpoints such as:

- `/graphql`
- `/api/graphql`
- Similar application-specific paths

Interacting directly with the GraphQL endpoint can reveal **misconfigurations and security weaknesses**, making it a valuable attack surface during application testing.

GraphQL operates on **objects**, each of which is defined by a specific **type**. Objects expose **fields** that can be queried by the client. According to GraphQL syntax, queries are executed from the **root level**, where the name of the query determines the entry point.

The following example demonstrates a query named `users` that requests the `id`, `username`, and `role` fields for all `User` objects:

```graphql
{
  users {
    id
    username
    role
  }
}
```

The corresponding response returns two `User` objects:

```graphql
{
  "data": {
    "users": [
      {
        "id": 1,
        "username": "htb-stdnt",
        "role": "user"
      },
      {
        "id": 2,
        "username": "admin",
        "role": "admin"
      }
    ]
  }
}
```

If a query supports **arguments**, they can be used to filter the returned results. For example, if the `users` query supports a `username` argument, the following request retrieves information for the `admin` user only:

```graphql
{
  users(username: "admin") {
    id
    username
    role
  }
}
```

Queries can also be modified to request **additional or alternative fields**. For instance, the `role` field can be replaced with the `password` field:

```graphql
{
  users(username: "admin") {
    id
    username
    password
  }
}
```

Objects in GraphQL may reference other objects. GraphQL supports **nested queries**, allowing a client to retrieve data from related objects within a single request.

Suppose the `posts` query exposes an `author` field, which references a `User` object. The following example queries fields from the nested `author` object:

```graphql
{
  posts {
    title
    author {
      username
      role
    }
  }
}
```

---


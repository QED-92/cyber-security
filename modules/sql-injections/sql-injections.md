# SQL Injections

This document summarizes core techniques for discovery and exploitation of **SQL injection vulnerabilities**. This is by no means an exhaustive guide. 

---

## Table of Contents
- [SQL Injections](#sql-injections)
    - [Overview](#overview)
    - [Authenticate to MySQL](#authenticate-to-mysql)
    - [Create Databases and Tables](#create-databases-and-tables)
    - [Manipulate and Retrieve Data from Tables](#manipulate-and-retrieve-data-from-tables)

---

## Overview

User input is often involved when applications send queries to a back-end database. If not securely coded, SQL injection vulnerabilities may be present.

---

## Authenticate to MySQL

The `mysql` utility is **CLI tool** used to authenticate to and interact with MySQL/MariaDB databases.

The following flags are commonly used to authenticate to a database:

| Flag        | Description   |
| ----------- | ------------- |
| `-u`        | Username      |
| `-h`        | Host          |
| `-P`        | Port          |
| `-p`        | Password      |

**Examples:**

When no host is specified, `mysql` defaults to **localhost**. The password can be supplied directly after the `-p` flag, with no space inbetween:

```bash
# Syntax
mysql -u <username> -p<password>

# Example
mysql -u root -pROOT123!
```

It is good practice to pass the `-p` flag without a password and instead be prompted interactively. This prevents the password from being stored in the `.bash_history` file:

```bash
# Syntax
mysql -u <username> -p

# Example
mysql -u root -p
```

The default port for MySQL/MariaDB is port `3306`. Use the `-h` and `-P` flags to connect to a specific host and port:

```bash
# Syntax
mysql -u <username> -h <ip/domain> -P <port> -p

# Example
mysql -u root -h 94.237.57.211 -P 46600 -p
```

---

## Create Databases and Tables

The semicolon (`;`) works as a statement terminator, much like in the `C` programming language. SQL keywords are case-insensitive; however, best practice is to write keywords in UPPERCASE and identifiers (such as database and table names) in lowercase.

The `CREATE DATABASE` statement creates a new database.

**Example:**

```sql
-- Syntax
CREATE DATABASE <name>;

-- Example
CREATE DATABASE users;
```

The `SHOW DATABASES` statement lists all databases.

**Example:**

```sql
SHOW DATABASES;
```

![Filtered output](images/show-databases.png)

The `USE` statement switches to a particular database.

**Example:**

```sql
-- Syntax
USE <name>;

-- Example
USE users;
```

SQL databases store data in tables made up of horizontal rows and vertical columns. The intersection of a row and a column is called a `cell`. A column is of a particular data-type. 

Tables are created with the `CREATE TABLE` statement.

**Example:**

```sql
-- Syntax
CREATE TABLE <name> (
    col1 DATATYPE,
    col2 DATATYPE,
    col3 DATATYPE
);

-- Example
CREATE TABLE logins (
    id INT,
    username VARCHAR(100),
    password VARCHAR(100),
    join_date DATETIME
);
```

![Filtered output](images/create-table.png)

The `SHOW TABLES` statement lists all tables in the database.

**Example:**

```sql
SHOW TABLES;
```

![Filtered output](images/show-tables.png)

The `DESCRIBE` statement is used to get more information about a table and its structure.

**Example:**

```sql
-- Syntax
DESCRIBE <name>;

-- Example
DESCRIBE logins;
```

![Filtered output](images/describe.png)

---

## Manipulate and Retrieve Data from Tables

The `INSERT` statment adds a `record` to a table. A `record` is a row, in other words, values are added to each column in a row of the table. 

**Example:**

```sql
-- Syntax
INSERT INTO <name> VALUES (col1_val, col2_val, ...);

-- Example
INSERT INTO logins VALUES(1, 'admin', 'p@ssw0rd', '2025-12-21');
```

Values can also be added to individual columns, instead of adding entire records. 

**Example:**

```sql
-- Syntax
INSERT INTO <name> (col1, col2, ...) VALUES (col1_val, col2_val, ...);

-- Example
INSERT INTO logins (username, password) VALUES('admin', 'p@ssw0rd');
```

The `SELECT` statement is used to retrieve data from tables.

**Example:**

Select all records from a table:

```sql
-- Syntax
SELECT * FROM <name>;

-- Example
SELECT * FROM logins;
```

![Filtered output](images/select-all.png)

Select specific columns from a table:

```sql
-- Syntax
SELECT <col1, col2, ...> FROM <name>;

-- Example
SELECT username, password FROM logins;
```

![Filtered output](images/select-columns.png)
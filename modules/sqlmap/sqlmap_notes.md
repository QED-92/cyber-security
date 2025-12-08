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

When testing for authentication bypasses the highest risk- and level settings should be used.

```
sqlmap -r req.txt --risk=3 --level=5 --batch -v
```

## Injection Techniques


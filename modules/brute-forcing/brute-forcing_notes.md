# Login Brute Forcing

---

# Overview

Brute forcing is a trial-and-error method commonly used to crack passwords, hashes and encryption keys. The process can be likened to a thief trying every key on a giant key-ring until they find one that unlocks the vault. 

The success of a brute force attack depends on three main components:

- Password complexity
- Computational power
- Security measures

A longer and more complex password obviously require more time and computational resources to crack. The following guidelines should be followed when creating passwords:

| Attribute        | Guideline                                                   |
| ---------------- | ----------------------------------------------------------- |
| `Length`         | `Minimum of 12 characters.`                                 |
| `Complexity`     | `Combination of lowercase, uppercase, numbers and symbols.` |
| `Uniqueness`     | `A unique password for each service (no reuse).`            |
| `Randomness`     | `As much randomness as possible.`                           |

To fully grasp the challenge of brute forcing passwords one must understand the underlying equation that determines the total number of possible combinations:

- $N = c^n$
- N = total number of possible combinations
- c = number of characters in character set
- n = number of characters in password

Example:

A 6 character password containing only lowercase letters from the english alphabet has over 300 million possible combinations.

- $N = 26^6 = 308,915,776$

# Brute Force Attacks

## Pure Brute Force Attack

A pure brute force attack tests every possible combination of characters within a predetermined character set. This approach guarantees success given enough time, however, this time span can be extremely long. 

## Dictionary Attack

Humans have a tendency to prioritize memorable passwords over secure ones. This makes them vulnerable to dictionary attacks. A dictionary attack systematically tests a pre-defined wordlist of passwords against the target. This significantly reduces the search space compared to pure brute force attacks.

Common wordlists:

- rockyou.txt
- xato-net-10-million-passwords-1000000.txt
- 2020-200_most_used_passwords.txt

## Hybrid Attack

Hybrid attacks combine the strengths of dictionary and brute force attacks, thus increasing the likelihood of success. Hybrid attacks are commonly used when the attacker has knowledge of the targets password policy. 

Suppose that the target organization implements the following password policy:

- Minimum length: 8 characters
- Must include:
- - At least one uppercase letter
- - At least one lowercase letter
- - At least one number
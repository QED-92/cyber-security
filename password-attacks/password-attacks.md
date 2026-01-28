# Password Attacks

This document outlines common techniques used in **password attacks**. It is intended as a practical, hands-on reference rather than a comprehensive theoretical guide.

---

# Table of Contents

- [Password Attacks](#password-attacks)
  - [Overview](#overview)
  - [Password Cracking Techniques](#password-cracking-techniques)
    - [John The Ripper](#john-the-ripper)
    - [Hashcat](#hashcat)


---

## Overview

Authentication is fundamentally the process of verifying identity. Most authentication mechanisms rely on one or more of the following four factors:

- `Something you know` – Password, PIN, passphrase
- `Something you have` – ID card, smart card, hardware token, authenticator app
- `Something you are` – Biometrics (fingerprint, facial recognition, voice)
- `Somewhere you are` – Geolocation, IP address

Depending on the sensitivity of the system or data being accessed, authentication may require a single factor or multiple factors (MFA).

Despite improvements in authentication technologies, **passwords remain the most widely used mechanism**. While Multi-Factor Authentication (MFA) significantly increases security, it can negatively impact usability, so many organizations continue to rely primarily on passwords.

Numerous studies consistently show that:

- Users frequently choose weak or predictable passwords
- Password manager adoption remains relatively low
- Password reuse across multiple services is common
- Many users fail to change passwords even after known breaches

These behaviors significantly increase the effectiveness of password-based attacks, particularly when combined with credential stuffing or brute-force techniques.

A useful resource for identifying breached email addresses and passwords is:

- [HaveIBeenPwned](https://haveibeenpwned.com/)

---

## Password Cracking Techniques

Stored passwords are typically hashed to provide an additional layer of protection in the event of a data breach. Common hashing algorithms include `MD5` and `SHA-256`, though modern applications increasingly use stronger, adaptive algorithms such as `bcrypt`, `scrypt`, or `PBKDF2`.

The following examples generate `MD5` and `SHA-256` hashes for the password `Welcome1`:

```bash
echo -n Welcome1 | md5sum

# b56e0b4ea4962283bee762525c2d490f
```

```bash
echo -n Welcome1 | sha256sum

# 7e19e31ae82d749034fc921f777f717ba5b57c6add9add889eb536ac6effcde0
```

Hash functions are one-way operations, meaning the original plaintext password cannot be directly recovered from the hash. Instead, attackers attempt to reproduce the hash by guessing candidate passwords and comparing their computed hashes against the target.

Common cracking approaches include:

- **Dictionary attacks** – testing words from curated wordlists
- **Brute-force attacks** – attempting every possible character combination
- **Hybrid attacks** – combining wordlists with mutations (numbers, symbols, casing)

A rainbow table is a precomputed lookup table that maps plaintext passwords to their corresponding hashes. If a target hash exists in the table, the original password can be recovered almost instantly.

To mitigate rainbow table attacks, most modern systems implement **salting**. A salt is a random value appended or prepended to a password before hashing. This ensures identical passwords generate different hashes and dramatically reduces the effectiveness of precomputed tables.

Example of hashing a salted password:

```bash
echo -n Th1sIsmyS@lt_Welcome1 | md5sum

# d34c7d34c2240fc6ada520c9f3685eb0  -
```

Because each user typically has a unique salt, attackers must crack each hash individually, significantly increasing computational cost.

Brute-force attacks attempt every possible character combination until the correct password is discovered. While feasible for short or simple passwords, this approach becomes impractical as password length and complexity increase.

Cracking speed is heavily influenced by the hashing algorithm:

- Fast hashes (e.g., `MD5`, `SHA1`) are highly susceptible to brute force
- Slow, adaptive hashes (e.g., `bcrypt`, `DCC2`) are intentionally designed to resist cracking by increasing computational overhead

As a result, attacking `MD5` hashes is orders of magnitude faster than attacking `bcrypt` or `DCC2`.

---

### John The Ripper

John the Ripper is an open-source password cracking utility that has been actively developed since 1996. It supports multiple cracking modes, including:

- Single crack mode
- Wordlist mode
- Incremental mode

Each mode targets different attack scenarios depending on the available data and password complexity.

**Single Crack Mode**
Single crack mode is a rule-based technique commonly used when targeting Linux credentials. Password candidates are generated using information associated with each account, including:

- Username
- Home directory name
- GECOS fields (real name and metadata)

These values are typically extracted from `/etc/passwd`.

Example `passwd` entry:

```
r0lf:$6$ues25dIanlctrWxg$nZHVz2z4kCy1760Ee28M1xtHdGoy0C2cYzZ8l2sVa1kIa8K9gAcdBP.GI6ng/qA4oaMrgElZ1Cb9OeXO4Fvy3/:0:0:Rolf Sebastian:/home/r0lf:/bin/bash
```

In this case, John leverages:

- Username: `r0lf`
- Real name: `Rolf Sebastian`
- Home directory: `/home/r0lf`

to generate targeted password guesses.

Run single crack mode:

```bash
john --single passwd
```

![Filtered output](./.images/john-single.PNG)

The hash is successfully cracked:
```
NAITSABES
```

**Wordlist Mode**
Wordlist mode performs a dictionary attack by hashing each entry from a supplied wordlist and comparing it against the target hash.

The following example cracks a `RIPEMD-128` hash using `rockyou.txt`:

```bash
john --wordlist=rockyou.txt --format=ripemd-128 hash.txt
```

![Filtered output](./.images/john-wordlist.PNG)

Recovered password:

```
50cent
```

**Incremental Mode**
Incremental mode is a brute-force–based technique that generates passwords dynamically using statistical models (Markov chains). Unlike wordlist attacks, it does not rely on predefined dictionaries.

Instead, candidate passwords are generated based on probabilistic patterns, making this approach more efficient than traditional brute force.

Character sets and password lengths are defined in `john.conf` and can be customized as needed.

Example:

```bash
john --incremental --format=ripemd-128 hash.txt
```

![Filtered output](./.images/john-incremental.PNG)

Recovered password:
```
50cent
```

**Hash Identification**
In some cases, hash types may not be immediately obvious. Tools such as `hashid` can assist with identification. Using the `-j` flag also displays the corresponding John the Ripper format:

```bash
hashid -j 193069ceb0461e1d40d216e32c79c704
```

![Filtered output](./.images/hashid.PNG)

---

### Hashcat

Hashcat is an open-source password cracking utility capable of attacking hundreds of different hash types. Each supported hash is assigned a specific mode ID.

A full list of supported hashes and their corresponding IDs can be displayed with:

```bash
hashcat --help
```

![Filtered output](./.images/hashcat-id.PNG)

When the hash type is unknown, tools such as `hashid` can assist with identification. Using the `-m` flag also provides the appropriate Hashcat mode:

```bash
hashid -m '$1$FNr44XZC$wQxY6HHLrgrGX0e1195k.1'
```

In this example, the hash is identified as `MD5`.

![Filtered output](./.images/hashcat-hashid.PNG)

The most commonly used Hashcat attack modes are:

- Dictionary attack (`-a 0`)
- Mask attack (`-a 3`)

**Dictionary Attack**
A dictionary attack compares one or more hashes against entries from a predefined wordlist.

The attack mode is specified with `-a`, and the hash mode with `-m`. Dictionary attacks use mode `0`:

```bash
hashcat -a 0 -m 0 'e3e3ec5831ad5e7288241960e5d4fdb8' rockyou.txt
```

Recovered password:

```
crazy!
```

![Filtered output](./.images/hashcat-dictionary.PNG)

**Rule-Based Attacks**
A raw wordlist may not always be sufficient. Hashcat supports rule-based mutations that modify each wordlist entry (adding digits, changing case, substituting characters, etc.).

Predefined rule files are located at:

```
/usr/share/hashcat/rules
```

![Filtered output](./.images/hashcat-rules.PNG)

Rules are applied using the `-r` flag. The following example uses `best64.rule`, which contains 64 common transformation rules:

```bash
hashcat -a 0 -m 0 '1b0556a75770563578569ae21392630c' rockyou.txt -r /usr/share/hashcat/rules/best64.rule
```

Recovered password:

```
c0wb0ys1
```

![Filtered output](./.images/hashcat-rules-best64.PNG)

**Mask Attacks**
A mask attack (`-a 3`) is a targeted brute-force technique where the password structure is explicitly defined. This method is highly effective when password policies or formatting patterns are known.

Hashcat provides built-in character sets represented by special symbols:

| Symbol          | Character set                                                              |
| --------------- | -------------------------------------------------------------------------- |
| `?l`            | `abcdefghijklmnopqrstuvwxyz` (lowercase letters)                           |
| `?u`            | `ABCDEFGHIJKLMNOPQRSTUVWXYZ` (UPPERCASE letters)                           |
| `?d`            | `0123456789` (digits)                                                      |
| `?h`            | `0123456789abcdef` (hexadecimal - lowercase)                               |
| `?H`            | `0123456789ABCDEF` (hexadecimal - UPPERCASE)                               |
| `?s`            | ``«space»!"#$%&'()*+,-./:;<=>?@[]^_`{`` (special characters)               |
| `?a`            | `?l?u?d?s` (any character)                                                 |
| `?b`            | `0x00 - 0xff` (binary)                                                     |

The following example defines a mask consisting of:

- One uppercase letter
- Four lowercase letters
- One digit
- One special character

```bash
hashcat -a 3 -m 0 '1e293d6912d074c0fd15844d803400dd' '?u?l?l?l?l?d?s'
```

Recovered password:

```
Mouse5!
```

![Filtered output](./.images/hashcat-mask.PNG)

---
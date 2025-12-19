# Hashcat

Password cracking is a useful skill for a penetration tester, red teamer, or even those on the defensive side of information security. During an assessment we will often retrieve a password hash that we must attempt to crack offline to proceed further towards our goal. 

Hashcat is a powerful open-source tool used for password cracking. Hashcat has extensive documentation and claims to be the world's fastest and most advanced password recovery utility. 

This document covers the basic usage of Hashcat, and is by no means an exhaustive guide.

---

## Hashing

Hashing is the process of converting some text to a unique string particular to that text. Hashing is a one-way process, meaning that there is no way of reconstructing the original plaintext from the hash. 

Hashing can be used for various purposes; for example, the **MD5** and **SHA256** algorithms are commonly used to verify file integrity, while algorithms such as **PBKDF2** are used to hash passwords before storage.

Unix systems support four different hashing algorithms:
	
- SHA-512
    - Fast and efficient. However, there are rainbow table attacks where an attacker can reconstruct the original password.
		
- Blowfish
    - A symmetric block cipher algorithm that encrypts a password with a key. More secure than SHA-512 but also slower.
	
- BCrypt
    - Uses a slow hash function, making it more difficult for attackers to successfully perform rainbow table attacks.
	
- Argon2
    - Considered one of the most secure algorithms. Uses multiple rounds of hash functions and a large amount of memory to mitigate password cracking attempts.

A common protection mechanism employed against password cracking is **"salting"**. A salt is a random piece of data added to the plaintext before hashing it. This increases computation time but does not prevent brute forcing altogether.

---

## Encryption

Encryption is the process of converting data into a format in which the original content is not accessible. Unlike hashing, encryption is reversible, meaning that it's possible to decrypt the ciphertext and obtain the original data.

There are two types of encryption algorithms: 

- Symmetric encryption
    - Symmetric algorithms use a key to encrypt data. The same key is used to decrypt it. Anyone who has the key can decrypt the ciphertext and obtain the data.
	
- Asymmetric encryption
    - Asymmetric algorithms divide the key into two parts (public and private). The public key can be given to anyone who wishes to encrypt data and pass it securely to the owner. The owner then uses their private key to decrypt the data.

---

## Identifying Hashes

Most hashing algorithms produce hashes of constant length. The length of a particular hash can be used to map it to the hashing algorithm. For example, a hash of 32 characters in length can be either an **MD5** or **NTLM** hash.

Hashid is a Python tool that can be used to detect various kinds of hashes. Simply pass the hash as an argument to the program:

```bash
pip install hashid
hashid '$apr1$71850310$gh9m4xcAn3MGxogwX/ztb.'
```

It's not always possible to identify the algorithm based on the obtained hash. The plaintext might undergo multiple encryption rounds and salting transformations, making it difficult to recover. The **hashid** tool uses regular expressions to make a **best-effort guess** regarding the type of hash. Oftentimes **hashid** will provide many possibilities for a given hash, leaving us with a certain amount of guesswork in order to identify the hash.

Hashcat provides an excellent reference, that maps hash modes to example hashes. This reference is very handy when determining the type of hash, and the associated **hash mode** required for hashcat to work:

- https://hashcat.net/wiki/doku.php?id=example_hashes

---

## Hashcat Overview

Install hashcat and display help page:

```bash
sudo apt install hashcat
hashcat -h
```

View list of example hashes:

```bash
hashcat --example-hashes | less
```

Hashcat support five different attack modes. Each mode have different applications depending on the type of hash and the complexity of the password.

The following attack modes are supported:

- 0 - Straight
- 1 - Combination
- 3 - Brute-force
- 6 - Hybrid Wordlist + Mask
- 7 - Hybrid Mask + Wordlist

---

## Straight Attack

A straight attack, also known as a dictionary attack, is the most straightforward mode. Dictionary attacks uses a pre-compiled wordlist for password cracking. Each password from the wordlist is hashed using the specified hash type and compared against the stored hash.

The attack mode is specified with the **-a** flag and the hash type with the **-m** flag. 

**Basic syntax:**

```bash
hashcat -a <ATTACK MODE> -m <HASH TYPE> <HASH FILE> <WORDLIST>
```

**Example:**

```bash
# Create a SHA 256 hash
echo -n '!PasswordCracking' | sha256sum | cut -f1 -d ' ' > hash.txt
```

```bash
# Dictionary attack
hashcat -a 0 -m 1400 hash.txt rockyou.txt
```

---

## Combination Attack

A combination attack utilizes two wordlists and creates combinations from them. It's quite common for users to join words together, thinking that this creates stronger passwords. 

You can see which passwords Hashcat will produce given two wordlists, without hashing anything:

```bash
hashcat -a 1 --stdout wordlist1 wordlist2
```

Syntax:

```bash
# Create an MD5 hash
echo -n 'secretpassword' | md5sum | cut -f1 -d ' ' > hash.txt
```

```bash
# Combination attack
hashcat -a 1 -m 0 hash.txt wordlist1 wordlist2
```

---

## Mask Attack

Mask attacks generate words matching a specific pattern (mask). This type of attack is particularly useful
when the password length or format is known.

A mask can be created using static characters, ranges of characters (e.g. [a-z] or [A-Z0-9]), or placeholders.

The following list shows some important placeholders:

|Placeholder   |	Meaning                                     |
|--------------|----------------------------------------------- | 
|`?l` 		   |	`lower-case ASCII letters (a-z)`            |
|`?u` 		   |	`upper-case ASCII letters (A-Z)`            |
|`?d` 		   |	`digits (0-9)`                              | 
|`?h` 		   |	`0123456789abcdef`                          |
|`?H` 		   |	`0123456789ABCDEF`                          |
|`?s` 		   |	`special characters`                        |
|`?a` 		   |	`All printable characters (?l?u?d?s)`       |
|`?b` 		   |	`0x00 - 0xff`                               |

**Examples:**

```bash
# Mask attacks
hashcat -a 3 -m 0 hash.txt ?l?l?l?d?d

hashcat -a 3 -m 1400 hash.txt Summer?d?d?d!

hashcat -a 3 -m 0 hash.txt ILFREIGHT?l?l?l?l?l20?1?d

hashcat -a 3 -m 0 hash.txt ?a?a?a?a?a?a?a?a
```

---

## Hashcat Optimization

A benchmark test measures your system's raw password cracking speed for different algorithms. This is done by running optimized cracking sessions, showing results in hashes per second (H/s). This information is useful if you want to optimize the cracking speed through certain settings. 

A benchmark test can be performed using the **-b** flag:

```bash
# Benchmark all supported hash types
hashcat -b

# Benchmark specific hash type (MD5)
hashcat -b -m 0
```

Hashcat has two main ways of optimizing speed:

- Optimized Kernels
    - The **-O** flag enables optimized kernels. This limits the password length, usually to 31 characters. If a password in the wordlists exceeds this limit, it will be skipped.
	
- Workload
    - The **-w** flag enables a specific workload profile (1 - 4). In other words, how aggressively Hashcat uses your hardware. The default profile is 2. If you plan on using your computer while cracking, set the profile to 1. If you plan on only running Hashcat, the workload profile can be set to 3. If you have a dedicated cracking rig, set the profile to 4.

**Examples:**

```bash
# Optimized kernels
hashcat -a 0 -m 1400 -O hash.txt rockyou.txt

# Workload profile
hashcat -a 0 -m 1400 -w 3 hash.txt rockyou.txt

# Insane
hashcat -a 0 -m 1400 -O -w 4 hash.txt rockyou.txt
```

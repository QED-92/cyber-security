# Hashcat

Password cracking is a useful skill for a penetration tester, red teamer, or even those on the defensive side of information security. During an assessment we will often retrieve a password hash that we must attempt to crack offline to proceed further towards our goal. 

Hashcat is a powerful open-source tool used for password cracking. Hashcat has extensive documentation and claims to be the world's fastest and most advanced password recovery utility. 

This document covers the basic usage of Hashcat, and is by no means an exhaustive guide.

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

## Encryption

Encryption is the process of converting data into a format in which the original content is not accessible. Unlike hashing, encryption is reversible, meaning that it's possible to decrypt the ciphertext and obtain the original data.

There are two types of encryption algorithms: 

- Symmetric encryption
    - Symmetric algorithms use a key to encrypt data. The same key is used to decrypt it. Anyone who has the key can decrypt the ciphertext and obtain the data.
	
- Asymmetric encryption
    - Asymmetric algorithms divide the key into two parts (public and private). The public key can be given to anyone who wishes to encrypt data and pass it securely to the owner. The owner then uses their private key to decrypt the data.

## Identifying Hashes

Most hashing algorithms produce hashes of constant length. The length of a particular hash can be used to map it to the hashing algorithm. For example, a hash of 32 characters in length can be either an **MD5** or **NTLM** hash.

Hashid is a Python tool, that can be used to detect various kinds of hashes. Simply pass the hash as an argument to the program:

```bash
pip install hashid
hashid '$apr1$71850310$gh9m4xcAn3MGxogwX/ztb.'
```

It's not always possible to identify the algorithm based on the obtained hash. The plaintext might undergo multiple encryption rounds and salting transformations, making it difficult to recover. The **hashid** tool uses regular expressions to make a **best-effort guess** regarding the type of hash. Oftentimes **hashid** will provide many possibilities for a given hash, leaving us with a certain amount of guesswork in order to identify the hash.

Hashcat provides an excellent reference, that maps hash modes to example hashes. This reference is very handy when determining the type of hash, and the associated **hash mode** required for hashcat to work:

- https://hashcat.net/wiki/doku.php?id=example_hashes

## Hashcat Overview
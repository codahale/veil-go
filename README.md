# veil

_Stupid crypto tricks._

**You should, under no circumstances, use this.**

## What is Veil?

Veil is an incredibly experimental hybrid cryptosystem for sending and receiving confidential,
authentic multi-recipient messages which are indistinguishable from random noise by an attacker.
Unlike e.g. GPG messages, Veil messages contain no metadata or format details which are not
encrypted. As a result, a global passive adversary would be unable to gain any information from a
Veil message beyond traffic analysis. Messages can be padded with random bytes to disguise their
true length, and fake recipients can be added to disguise their true number from other recipients.

## Algorithms & Constructions
 
Veil uses AES-128-CTR for confidentiality, HMAC-SHA-512/256 for authentication, X25519 and
HKDF-SHA-512/256 for key encapsulation, and SHA-512/256 for integrity.

* AES-128-CTR is well-studied and requires no padding. It is vulnerable to nonce misuse, but a 
  reliable source of random data is a design requirement for Veil.
* SHA-512/256 is well-studied, fast on 64-bit CPUs, has unbiased output, and is not vulnerable to
  length extension attacks.
* HMAC is very well-studied and, unlike polynomial authenticators like GHASH or Poly1305, its output
  is not biased if the underlying hash algorithm is not biased. It is also not subject to nonce
  misuse.
* X25519 is a [safe curve](https://safecurves.cr.yp.to) and provides ~128-bit security, which
  roughly maps to the security levels of the other algorithms and constructions.
* HKDF is well-studied, fast, and based on HMAC and SHA-512/256.
* Elligator2 allows us to map X25519 public keys to random strings, making ephemeral Diffie-Hellman
  indistinguishable from random noise. All Veil public keys are Elligator2 representations.

### Key Encapsulation

An ephemeral X25519 key pair is generated, an X25519 shared secret is calculated for the ephemeral
private key and the recipient's public key, and HKDF-SHA-512/256 is used to derive a 32-byte key.
The sender and recipient's public keys are concatenated and used as the salt for HKDF. The static
value `{0x76, 0x65, 0x69, 0x6C}` is used as the information input for HKDF. The plaintext is 
encrypted using the derived key and the following data encapsulation mechanism, and the ephemeral
public key and ciphertext are returned.

### Data Encapsulation

A 32-byte key is split into subkeys: the first 16 bytes as used as the AES key; the second 16 bytes
are used as the HMAC key. The plaintext is encrypted with AES-128-CTR using a random, 16-byte nonce.
HMAC-SHA-512/256 is used to hash the authenticated data, the nonce, the ciphertext, and the number
of bits of authenticated data encoded as a 64-bit unsigned big-endian value. The nonce, ciphertext,
and HMAC digest are concatenated and returned.

This is the same as the construction in
[draft-mcgrew-aead-aes-cbc-hmac-sha2-05](https://www.ietf.org/archive/id/draft-mcgrew-aead-aes-cbc-hmac-sha2-05.txt)
the [encrypt-then-authenticate
construction](https://github.com/google/tink/blob/master/java/src/main/java/com/google/crypto/tink/subtle/EncryptThenAuthenticate.java)
in Tink.

### Messages

A Veil message begins with a series of fixed-length encrypted headers, each of which contains a copy
of the 32-byte session key, the offset in bytes where the message begins, the length of the
plaintext message in bytes, and a SHA-512/256 digest of the plaintext message. Following the headers
is an encrypted packet containing the message plus an arbitrary number of random padding bytes,
using the full set of encrypted headers as authenticated data.

To decrypt a message, the recipient iterates through the message, searching for a decryptable header
using the shared secret between sender and recipient. When a header is successfully decrypted, the
session key is used to decrypt the encrypted message, the padding is removed, and the digest of the
recovered plaintext is compared to the digest contained in the header.

## What's the point

1. Veil messages can be read by all of the intended recipients. None of the recipients can modify
   the message or forge additional messages without being able to forge encrypted headers for the
   other recipients (i.e., break X25519) or find a message with the same SHA-512/256 digest (i.e. 
   break SHA2).
2. Veil messages are tamper-proof. If a single bit of the entire message is changed, all of the
   recipients will know.
3. Veil messages are indistinguishable from random noise, revealing no metadata about recipients'
   identities, number of recipients, etc.
4. Veil messages can be padded, obscuring a message's actual length.
5. The number of recipients in a Veil message can be obscured from recipients by adding blocks of 
   random noise instead of encrypted headers.

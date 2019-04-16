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
 
Veil uses XSalsa20 for confidentiality, HMAC-SHA-512/256 for authentication, and X25519 with 
HKDF-SHA-512/256 for key encapsulation.

* XSalsa20 is fast, well-studied, and requires no padding. It uses 24-byte nonces, which is a 
  suitable size for randomly generated nonces. It is vulnerable to nonce misuse, but a reliable 
  source of random data is a design requirement for Veil. Constant-time implementations are easy to
  implement without hardware support.
* SHA-512/256 is well-studied, fast on 64-bit CPUs, has unbiased output, and is not vulnerable to
  length extension attacks. SHA2 is constant-time.
* HMAC is very well-studied and, unlike polynomial authenticators like GHASH or Poly1305, its output
  is not biased if the underlying hash algorithm is not biased. It is also not subject to nonce
  misuse. HMAC is constant-time.
* HKDF is well-studied, fast, and based on HMAC and SHA-512/256. HKDF is constant time.
* X25519 is a [safe curve](https://safecurves.cr.yp.to) and provides ~128-bit security, which
  roughly maps to the security levels of the other algorithms and constructions. Constant-time 
  implementations are possible and certainly easier to make than other EC curves.
* Elligator2 allows us to map X25519 public keys to random strings, making ephemeral Diffie-Hellman
  indistinguishable from random noise. All Veil public keys are Elligator2 representations.
  Elligator2 is constant-time.

### Key Encapsulation

An ephemeral X25519 key pair is generated, an X25519 shared secret is calculated for the ephemeral
private key and the recipient's public key, and HKDF-SHA-512/256 is used to derive a 32-byte key.
The sender and recipient's public keys are concatenated and used as the salt for HKDF. The static
value `{0x76, 0x65, 0x69, 0x6C}` is used as the information input for HKDF. The plaintext is 
encrypted using the derived key and the following data encapsulation mechanism, and the ephemeral
public key and ciphertext are returned.

### Data Encapsulation

A 64-byte key is split into subkeys: the first 32 bytes as used as the XSalsa20 key; the second 32
bytes are used as the HMAC key. The plaintext is encrypted with XSalsa20 using a random, 24-byte
nonce. HMAC-SHA-512/256 is used to hash the authenticated data, the nonce, the ciphertext, the
number of bits of ciphertext and authenticated data encoded as 64-bit unsigned big-endian values.
The nonce, ciphertext, and HMAC digest are concatenated and returned.

This is similar to the construction in
[draft-mcgrew-aead-aes-cbc-hmac-sha2-05](https://www.ietf.org/archive/id/draft-mcgrew-aead-aes-cbc-hmac-sha2-05.txt),
the [encrypt-then-authenticate
construction](https://github.com/google/tink/blob/master/java/src/main/java/com/google/crypto/tink/subtle/EncryptThenAuthenticate.java)
in Tink. Besides the algorithm choices, the difference lies mostly in the inclusion of the length of
the ciphertext in the tag construction.

### Messages

A Veil message begins with a series of fixed-length encrypted headers, each of which contains a copy
of the 64-byte data encapsulation key, the offset in bytes where the message begins, and the length
of the plaintext message in bytes. Following the headers is an encrypted packet containing the
message plus an arbitrary number of random padding bytes, using the full set of encrypted headers as
authenticated data.

To decrypt a message, the recipient iterates through the message, searching for a decryptable header
using the shared secret between the ephemeral public key and recipient's private key. When a header
is successfully decrypted, the session key is used to decrypt the encrypted message, and the padding
is removed.

## What's the point

1. Veil messages can be read by all of the intended recipients. For anyone else, they are 
   indistinguishable from random noise.
2. Veil messages are tamper-proof. If a single bit of the entire message is changed, all of the
   recipients will know.
3. Veil messages are indistinguishable from random noise, revealing no metadata about recipients'
   identities, number of recipients, etc.
4. Veil messages can be padded, obscuring a message's actual length.
5. The number of recipients in a Veil message can be obscured from recipients by adding blocks of 
   random noise instead of encrypted headers.

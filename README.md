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
 
Veil uses XSalsa20 for confidentiality, HMAC-SHA-512/256 for integrity, Ed25519 for authenticity,
and X25519 with HKDF-SHA-512/256 for key agreement.

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
* Ed25519 uses a [safe curve](https://safecurves.cr.yp.to). Constant-time implementations are 
  possible and certainly easier to make than other EC curves.
* X25519 uses a [safe curve](https://safecurves.cr.yp.to) and provides ~128-bit security, which
  roughly maps to the security levels of the other algorithms and constructions. Constant-time 
  implementations are possible and certainly easier to make than other EC curves.
* Elligator2 allows us to map X25519 public keys to random strings, making ephemeral Diffie-Hellman
  indistinguishable from random noise. All Veil public keys are Elligator2 representations.
  Elligator2 is constant-time.

### Key Generation

Veil static keys are Ed25519 keys where the public key can be encoded as an Elligator2
representative. Ephemeral keys are X25519 keys where the public key can be encoded as an Elligator2
representative.

### Key Encapsulation

The recipient's Ed25519 public key is converted to an X25519 public key. An ephemeral X25519 key 
pair is generated, and an X25519 shared secret is calculated for the ephemeral private key and the
recipient's X25519 public key.

HKDF-SHA-512/256 is used to derive a 64-byte key, using the ephemeral key's Elligator2
representative as the salt and the static value `{0x76, 0x65, 0x69, 0x6C}` as the information 
parameter.

The plaintext is encrypted using the derived key and the following data encapsulation mechanism, and
the ephemeral public key's Elligator2 representative and the ciphertext are returned.

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
of the plaintext message in bytes. 

Following the headers is the plaintext, appended with random padding bytes, and prepended with an
Ed25519 signature of the encrypted headers, the plaintext, and the padding, all encrypted using the
data encapsulation key using the encrypted headers as authenticated data.

To decrypt a message, the recipient iterates through the message, searching for a decryptable header
using the shared secret between the ephemeral public key and recipient's private key. When a header
is successfully decrypted, the session key is used to decrypt the encrypted message, the signature
is verified, and the padding is removed.

## What's the point

1. Veil messages can be read by all of the intended recipients, but no recipient can modify the 
   message's content or metadata.
2. Veil messages are tamper-proof. If a single bit of the entire message is changed, all of the
   recipients will know.
3. Veil messages are indistinguishable from random noise, revealing no metadata about recipients'
   identities, number of recipients, etc.
4. Veil messages can be padded, obscuring a message's actual length.
5. The number of recipients in a Veil message can be obscured from recipients by adding blocks of 
   random noise instead of encrypted headers.
6. Veil messages are non-repudiable.

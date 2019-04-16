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

Veil uses XChaCha20Poly1305 for authenticated encryption, Ed25519 for authenticity, and
X25519 for key agreement.

* XChaCha20Poly1305 is fast, well-studied, and requires no padding. It uses 24-byte nonces, which is
  a suitable size for randomly generated nonces. It is vulnerable to nonce misuse, but a reliable 
  source of random data is already a design requirement for Veil. Constant-time implementations are
  easy to implement without hardware support.
* Ed25519 uses a [safe curve](https://safecurves.cr.yp.to). Constant-time implementations are 
  common and certainly easier to make than other EC curves.
* X25519 uses a [safe curve](https://safecurves.cr.yp.to) and provides ~128-bit security, which
  roughly maps to the security levels of the other algorithms and constructions. Constant-time 
  implementations are common and certainly easier to make than other EC curves.
* Elligator2 allows us to map X25519 public keys to random strings, making ephemeral Diffie-Hellman
  indistinguishable from random noise. All Veil public keys are Elligator2 representations.
  Elligator2 is constant-time.

### Key Generation

Veil static keys are Ed25519 keys.

### Data Encapsulation

Data is encapsulated using XChaCha20Poly1305, with the 24-byte random nonce prepended to the
ciphertext.

### Key Encapsulation

The recipient's Ed25519 public key is converted to an X25519 public key. An ephemeral X25519 key
pair compatible with Elligator2 representation is generated, and used with the recipient's converted
X25519 public key to generate a shared secret. The shared secret is used directly as the key for the
data encapsulation mechanism with the ephemeral public key's Elligator 2 representative as
authenticated data. The ephemeral public key's Elligator2 representative and the ciphertext are
returned.

### Messages

A Veil message begins with a series of fixed-length encrypted headers, each of which contains a copy
of the random 32-byte data encapsulation key, the offset in bytes where the message begins, and the
length of the plaintext message in bytes.

Following the headers is the plaintext, appended with random padding bytes, and prepended with an
Ed25519 signature of the encrypted headers, the plaintext, and the padding, all encrypted using the
data encapsulation key using the encrypted headers as authenticated data.

To decrypt a message, the recipient iterates through the message, searching for a decryptable header
using the shared secret between the ephemeral public key and recipient's private key. When a header
is successfully decrypted, the session key is used to decrypt the encrypted message, the signature
is verified, and the padding is removed.

## What's the point

1. Veil messages are confidential: no one can read the message without being a recipient.
2. Veil messages can be read by all of the intended recipients, but no recipient can modify the 
   message's content or metadata without possessing the sender's private key.
3. Veil messages are tamper-proof. If a single bit of the entire message is changed, all of the
   recipients will know.
4. Veil messages are indistinguishable from random noise, revealing no metadata about recipients'
   identities, number of recipients, etc.
5. Veil messages can be padded, obscuring a message's actual length.
6. The number of recipients in a Veil message can be obscured from recipients by adding blocks of 
   random noise instead of encrypted headers.
7. Veil messages are non-repudiable.

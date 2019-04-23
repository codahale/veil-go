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

Veil uses ChaCha20Poly1305 for authenticated encryption, X25519 for key agreement and
authentication, Elligator2 for indistinguishable public key encoding, and HKDF-SHA-256 for key
derivation.

* ChaCha20Poly1305 is fast, well-studied, and requires no padding. It is vulnerable to nonce misuse,
  but both keys and nonces are derived from random data, making collisions very improbable.
  Constant-time implementations are easy to implement without hardware support.
* X25519 uses a [safe curve](https://safecurves.cr.yp.to) and provides ~128-bit security, which
  roughly maps to the security levels of the other algorithms and constructions. Constant-time 
  implementations are common and certainly easier to make than other EC curves.
* Elligator2 allows us to map X25519 public keys to random strings, making ephemeral Diffie-Hellman
  indistinguishable from random noise. All Veil public keys are Elligator2 representations.
  Elligator2 is constant-time.
* HKDF-SHA-256 is fast, standardized, constant-time, and very well-studied.

### Key Encapsulation Mechanism (KEM)

Veil headers and messages are encrypted using a Key Encapsulation Mechanism:

1. An ephemeral X25519 key pair is generated.
2. The X25519 shared secret is calculated for the recipient's public key and the ephemeral secret 
   key.
3. The X25519 shared secret is calculated for the recipient's public key and the initiator's secret
   key.
4. The two shared secrets are concatenated and used as the initial keying material for 
   HKDF-SHA-256, with the initiator's public key, the ephemeral public key, and the recipient's 
   public key as the salt parameter and the authenticated data as the information parameter.
5. The first 32 bytes from the HKDF output are used as a ChaCha20Poly1305 key.
6. The next 12 bytes from the HKDF output as used as a ChaCha20Poly1305 nonce.
7. The plaintext is encrypted with ChaCha20Poly1305 using the derived key, the derived nonce, and
   the authenticated data.
8. The Elligator2 encoding of the ephemeral public key and the ChaCha20Poly1305 ciphertext and tag
   are returned.

As a One-Pass Unified Model `C(1e, 2s, ECC CDH)` key agreement scheme (per NIST SP 800-56A), this
KEM provides assurance that the message was encrypted by the holder of the sender's secret key.
X25519 mutability issues are mitigated by the inclusion of both the ephemeral public key and the
recipient's public key in the HKDF inputs. Deriving both the key and nonce from the ephemeral shared
secret eliminates the possibility of nonce misuse, allows for the usage of ChaCha20 vs XChaCha20,
and results in a shorter ciphertext by eliding the nonce. Finally, encoding the ephemeral public key
with Elligator2 ensures the final bytestring is indistinguishable from random noise.

### Messages

Encrypting a Veil message uses the following process:

1. An ephemeral X25519 key pair is generated.
2. A plaintext header is generated, containing the ephemeral secret key, the total length of 
   encrypted headers, and the length of the plaintext message bytes.
3. For each recipient, a copy of the header is encrypted using the initiator's secret key and the
   recipient's public key, and written as output. Fake recipients may be added by writing random
   data instead of an encrypted header.
4. The plaintext message has random padding bytes appended to it, and is encrypted using the 
   initiator's secret key, the ephemeral public key, and the encrypted headers as authenticated 
   data.
5. The encrypted headers and encrypted, padded message are returned.

To decrypt a message, the recipient iterates through the message, searching for a decryptable header
using the shared secret between the ephemeral public key and recipient's secret key. When a header
is successfully decrypted, the ephemeral secret key is used to decrypt the encrypted message, and
the padding is removed.

### Password-Based Encryption

To store safely store secret keys, Scrypt is used with a 32-byte random salt to derive a 
ChaCha20Poly1305 key and nonce. The secret key is encrypted with ChaCha20Poly1305, using the Scrypt
parameters as authenticated data.

## What's the point

1. Veil messages are confidential: no one can read the message without being a recipient.
2. Veil messages can be read by all of the intended recipients, but no recipient can modify the 
   message's content or metadata without possessing the sender's secret key.
3. Veil messages are tamper-proof. If a single bit of the entire message is changed, all of the
   recipients will know.
4. Veil messages are indistinguishable from random noise, revealing no metadata about recipients'
   identities, number of recipients, etc.
5. Veil messages can be padded, obscuring a message's actual length.
6. The number of recipients in a Veil message can be obscured from recipients by adding blocks of 
   random noise instead of encrypted headers.
7. Veil messages are non-repudiable.

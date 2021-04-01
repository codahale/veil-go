# veil

_Stupid crypto tricks._

WARNING: You should, under no circumstances, use this.

## What is Veil?

Veil is an incredibly experimental hybrid cryptosystem for sending and receiving confidential,
authentic multi-recipient messages which are indistinguishable from random noise by an attacker.
Unlike e.g. GPG messages, Veil messages contain no metadata or format details which are not
encrypted. As a result, a global passive adversary would be unable to gain any information from a
Veil message beyond traffic analysis. Messages can be padded with random bytes to disguise their
true length, and fake recipients can be added to disguise their true number from other recipients.
Further, Veil supports hierarchical key derivation, allowing for domain-specific and disposable
keys.

## Algorithms & Constructions

### Scoped Hashing

Veil uses scoped hashing for domain-specific derivation. For example, to derive a secret
ristretto255 scalar from a secret key, HMAC-SHA-512 is used with a static key of `veilsecretkey`.
Using purpose-specific hashing separates concerns and hardens the design against misuse.

### Child Key Derivation

Each participant in Veil has a secret key, which is a 64-byte random string. To derive a private key
from a secret key, the secret key is mapped to a ristretto255 scalar. A delta scalar is derived from
an opaque label value and added to the secret scalar to form a private key. The process is repeated
to derive a private key from another private key. To derive a public key from a public key, the
delta scalar is first multiplied by the curve's base point, then added to the public key point.

### Symmetric Key Ratcheting And Streaming AEADs

In order to encrypt arbitrarily large messages, Veil uses a streaming AEAD construction based on a
Signal-style HKDF ratchet. An initial 64-byte chain key is used to create an HKDF-SHA-512 instance,
and the first 64 bytes of its output are used to create a new chain key. The next 32 bytes of KDF
output are used to create a ChaCha20Poly1305 key, and the following 12 bytes are used to create a
nonce. To prevent attacker appending blocks to a message, the final block of a stream is keyed using
a different salt, thus permanently forking the chain.

### Key Agreement And Encapsulation

When sending a message, the sender generates an ephemeral key pair and calculates the ephemeral
shared secret between the recipient's public key and the ephemeral private key. They then calculate
the static shared secret between the recipient's public key and their own private key. The two
shared secret points are used as HKDF-SHA-512 initial keying material, with the ephemeral, sender's,
and recipient's public keys included as a salt. The sender creates a symmetric key and nonce from
the KDF output and encrypts the message with an AEAD. The sender transmits the ephemeral public key
and the ciphertext.

To receive a message, the receiver calculates the ephemeral shared secret between the ephemeral
public key and their own private key and the static shared secret between the recipient's public key
and their own private key. The HKDF-SHA-512 output is re-created, and the message is authenticated
and decrypted.

As a One-Pass Unified Model `C(1e, 2s, ECC CDH)` key agreement scheme (per NIST SP 800-56A), this
KEM provides assurance that the message was encrypted by the holder of the sender's private key. XDH
mutability issues are mitigated by the inclusion of the ephemeral public key and the recipient's
public key in the HKDF inputs. Deriving the key and nonce from the ephemeral shared secret
eliminates the possibility of nonce misuse, results in a shorter ciphertext by eliding the nonce,
and adds key-commitment with all public keys as openers.

### Digital Signatures

To make authenticated messages, Veil creates Schnorr signatures using the signer's private key. The
actual "message" signed is a SHA-512 hash of the message, and SHA-512 is used to derive ristretto255
scalars from the message and ephemeral public key. In place of a randomly generated ephemeral key
pair, Veil uses a key pair derived from the private key and the message value.

### Multi-Recipient Messages

A Veil message combines all of these primitives to provide multi-recipient messages.

First, the sender creates an ephemeral header key pair and creates a header block consisting of the
ephemeral header private key and the total length of all encrypted headers plus padding. For each
recipient, the sender encrypts a copy of the header using the described KEM and AEAD. Finally, the
sender adds optional random padding to the end of the encrypted headers.

Second, the sender uses the KEM mechanism to encrypt the message using the ephemeral header public
key. Instead of a single AEAD pass, the shared secret is used to begin a KDF key ratchet, and each
block of the input is encrypted using ChaCha20Poly1305 with a new ratchet key and nonce.

Finally, a signature is created of the SHA-512 hash of the plaintext and appended to the plaintext
inside the AEAD stream.

To decrypt a message, the recipient iterates through the message, searching for a decryptable header
using the shared secret between the ephemeral header public key and recipient's private key. When a
header is successfully decrypted, the ephemeral header private key and the sender's public key is
used to re-derive the shared secret, and the message is decrypted. The signature is verified against
an SHA-512 hash of the message, assuring authenticity.

### Passphrase-Based Encryption

To safely store secret keys, Argon2id is used with a 16-byte random salt to derive a
ChaCha20Poly1305 key and nonce. The secret key is encrypted with ChaCha20Poly1305.

## What's the point

1. Veil messages are confidential: no one can read the message without being a recipient.
2. Veil messages can be read by all the intended recipients, but no recipient can modify the
   message's content or metadata without possessing the sender's secret key.
3. Veil messages are tamper-proof. If a single bit of the entire message is changed, all the
   recipients will know.
4. Veil messages are non-repudiable: if the message is decryptable, it is guaranteed to have come
   from the possessor of the sender's secret key.
5. Veil messages are indistinguishable from random noise, revealing no metadata about recipients'
   identities, number of recipients, etc.
6. Veil messages can be padded, obscuring a message's actual length.
7. The number of recipients in a Veil message can be obscured from recipients by adding fake keys
   to the recipients list.
8. Veil messages can be arbitrarily big and both encrypted and decrypted in a single pass.
9. Veil keys can be derived arbitrarily for domain-specific or disposable use.

## License

Copyright © 2021 Coda Hale

Distributed under the Apache License 2.0.

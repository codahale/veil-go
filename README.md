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

## Algorithms & Constructions

### Key-Committing AEAD

Veil uses a simple wrapper AEAD for adding key commitment to existing AEAD constructions. It does
this by encrypting a message with an underlying AEAD, then using the same key to calculate an HMAC
of the resulting ciphertext. The HMAC is appended to the ciphertext, and compared before decrypting.

In particular, Veil uses AES-256-GCM+HMAC-SHA2-512/256. AES is very well-studied and well-supported
in hardware; GCM is fussy but fast; HMAC is as old as the hills and just as durable; SHA2-512/256 is
a good mix of fast and secure.

### Symmetric Key Ratcheting And Streaming AEADs

In order to encrypt arbitrarily large messages, Veil uses a streaming AEAD construction based on a
Signal-style HKDF ratchet. An initial 32-byte chain key is used to create an HKDF-SHA2-512/256
instance, and the first 32 bytes of its output are used to create a new chain key. The next 32 bytes
of KDF output are used to create an AES-256 key, and the following 12 bytes are used to create a GCM
nonce. To prevent attacker appending blocks to a message, the final block of a stream is keyed using
a different salt, thus permanently forking the chain.

### Key Agreement And Encapsulation

Veil uses ristretto255 for asymmetric cryptography. Each person has a ristretto255/XDH key pair and
shares their public key with each other. In place of encoded ristretto255 points, Veil encodes all
public keys using Elligator2, making them indistinguishable from noise.

When sending a message, the sender generates an ephemeral key pair and calculates the ephemeral
shared secret between the recipient's public key and the ephemeral secret key. They then calculate
the static shared secret between the recipient's public key and their own secret key. The two shared
secret points are used as HKDF-SHA2-512/256 initial keying material, with the ephemeral, sender's,
and recipient's public keys included as a salt. The sender creates a symmetric key and nonce from
the KDF output and encrypts the message with an AEAD. The sender transmits the ephemeral public key
and the ciphertext.

To receive a message, the receiver calculates the ephemeral shared secret between the ephemeral
public key and their own secret key and the static shared secret between the recipient's public key
and their own secret key. The HKDF-SHA2-512/256 output is re-created, and the message is
authenticated and decrypted.

As a One-Pass Unified Model `C(1e, 2s, ECC CDH)` key agreement scheme (per NIST SP 800-56A), this
KEM provides assurance that the message was encrypted by the holder of the sender's secret key. XDH
mutability issues are mitigated by the inclusion of the ephemeral public key and the recipient's
public key in the HKDF inputs. Deriving the key and nonce from the ephemeral shared secret
eliminates the possibility of nonce misuse, allows for the safe usage of GCM, and results in a
shorter ciphertext by eliding the nonce.

### Multi-Recipient Messages

A Veil message combines all of these primitives to provide multi-recipient messages.

First, the sender creates an ephemeral key pair and creates a header block consisting of the
ephemeral secret key and the total length of all encrypted headers plus padding. For each recipient,
the sender encrypts a copy of the header using the described KEM and AEAD. Finally, the sender adds
optional random padding to the end of the encrypted headers.

Second, the sender uses the KEM mechanism to encrypt the message using the ephemeral public key.
Instead of a single AEAD pass, the derived key is used to begin a KDF key ratchet, and each block of
the input is encrypted using AES-256-GCM+HMAC-SHA2-512/256 with a new ratchet key and nonce.

To decrypt a message, the recipient iterates through the message, searching for a decryptable header
using the shared secret between the ephemeral public key and recipient's secret key. When a header
is successfully decrypted, the ephemeral secret key and the sender's public key is used to re-derive
the shared secret, and the message is decrypted.

### Password-Based Encryption

To safely store secret keys, Argon2id is used with a 16-byte random salt to derive a AES-256 key and
GCM nonce. The secret key is encrypted with AES-256-GCM+HMAC-SHA2-512/256.

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

## License

Copyright © 2021 Coda Hale

Distributed under the Apache License 2.0.

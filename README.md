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

Veil uses just two distinct primitives:

* [STROBE](https://strobe.sourceforge.io) for confidentiality, authentication, and integrity.
* [ristretto255](https://ristretto.group) for key agreement and signing.

### STROBE Protocols

Veil includes STROBE protocols for the following capabilities:

* `veil.authenc.*`: authenticated encryption for message headers and secret keys
* `veil.authenc.stream`: streaming AEAD encryption with key ratcheting
* `veil.kdf.balloon`: balloon hashing key derivation for passphrase-based encryption
* `veil.kdf.kem.*`: key derivation for Veil's key encapsulation algorithm
* `veil.rng`: a CSPRNG seeded from the underlying host
* `veil.scaldf.*`: functions for deriving ristretto255 scalars from non-uniform or secret values
* `veil.schnorr`: fully deterministic Schnorr signatures over ristretto255
* `veil.skid`: safe identifiers for Veil secret keys

Full details and documentation can be found in the 
[`pkg/veil/internal`](https://github.com/codahale/veil/tree/main/pkg/veil/internal) directory.

### Child Key Derivation

Each participant in Veil has a secret key, which is a 64-byte random string. To derive a private key
from a secret key, the secret key is mapped to a ristretto255 scalar. A delta scalar is derived from
an opaque label value and added to the secret scalar to form a private key. The process is repeated
to derive a private key from another private key. To derive a public key from a public key, the
delta scalar is first multiplied by the curve's base element, then added to the public key element.

This is used iterative to provide hierarchical key derivation. Public keys are created using
hierarchical IDs like `/friends/alice`, in which the private key `/` is used to derive the private
key `friends`, which is in turn used to derive the private key `alice`.

### Multi-Recipient Messages

A Veil message combines all of these primitives to provide multi-recipient messages.

First, the sender creates an ephemeral header key pair and creates a header block consisting of the
ephemeral header private key and the total length of all encrypted headers plus padding. For each
recipient, the sender encrypts a copy of the header using `veil.kdf.kem.header` and
`veil.authenc.header`. Finally, the sender adds optional random padding to the end of the encrypted
headers.

Second, the sender uses `veil.schnorr` to create a signature of both the encrypted headers
(including any padding) and the plaintext.

Finally, the sender uses `veil.kdf.kem.message` and `veil.authenc.stream` to encrypt the message and
the signature using the ephemeral header public key.

To decrypt a message, the recipient iterates through the message, searching for a decryptable header
using the shared secret between the ephemeral header public key and recipient's private key. When a
header is successfully decrypted, the ephemeral header private key and the sender's public key is
used to re-derive the shared secret, and the message is decrypted. The signature is verified against
the encrypted headers and the plaintext, assuring authenticity.

### Passphrase-Based Encryption

To safely store secret keys, `veil.kdf.balloon` is used with a 32-byte random salt to derive a key.
The secret key is encrypted with `veil.authenc.secret-key`.

## What's the point

1. Veil uses a minimal number of cryptographic primitives in a clear, declarative fashion.
   ristretto255 uses a safe curve, has non-malleable encodings, and has no co-factor concerns.
   STROBE is built on the Keccak-f\[1600\] permutation, the core of SHA-3, which has seen
   significant scrutiny over the last decade.
2. Veil messages are confidential: no one can read the message without being a recipient.
3. Veil messages can be read by all the intended recipients, but no recipient can modify the
   message's content or metadata without possessing the sender's secret key.
4. Veil messages are tamper-proof. If a single bit of the entire message is changed, all the
   recipients will know.
5. Veil messages are non-repudiable: if the message is decryptable, it is guaranteed to have come
   from the possessor of the sender's secret key.
6. Veil messages are indistinguishable from random noise, revealing no metadata about recipients'
   identities, number of recipients, etc.
7. Veil messages can be padded, obscuring a message's actual length.
8. The number of recipients in a Veil message can be obscured from recipients by adding fake keys
   to the recipients list.
9. Veil messages can be arbitrarily big and both encrypted and decrypted in a single pass.
10. Veil keys can be derived arbitrarily for domain-specific or disposable use.

## License

Copyright © 2021 Coda Hale

Distributed under the Apache License 2.0.

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

## Design Criteria

### Cryptographic Minimalism

Veil uses just two distinct primitives:

* [STROBE](https://strobe.sourceforge.io) for confidentiality, authentication, and integrity.
* [ristretto255](https://ristretto.group) for key agreement and signing.

ristretto255 uses a safe curve, has non-malleable encodings, and has no co-factor concerns. STROBE
is built on the Keccak-f\[1600\] permutation, the core of SHA-3, which has seen significant scrutiny
over the last decade.

The underlying philosophy is that expressed
by [Adam Langley](https://www.imperialviolet.org/2016/05/16/agility.html):

> There's a lesson in all this: have one joint and keep it well oiled. … \[O\]ne needs to minimise
> complexity, concentrate all extensibility in a single place and _actively defend it_.

### Integrated Constructions

Because STROBE provides a wide range of capabilities, it's possible to build fully integrated
cryptographic constructions. Leveraging transcript consistency -- the fact that every operation
changes a STROBE protocol's state in a cryptographically secure manner -- makes for much simpler
protocols with guarantees that are easier to understand.

Instead of combining a hash function and a digital signature algorithm, we have a single digital
signature construction. Instead of combining a key exchange, a KDF, and an AEAD, we have a single
key encapsulation mechanism. This integration bakes in logical dependencies on sent and received
data in a feed-forward mechanism, which removes it from the attackable surface area of the protocol.

### Deterministic Components, `IND-CCA2` System

Veil is designed to be indistinguishable under adaptive chosen ciphertext attacks, since that's the
gold standard for modern cryptosystems. It avoids, however, the usual approach to `IND-CCA2` design,
which is to rub a nonce on everything. Nonces are required for `IND-CCA2` -- if ciphertexts are
deterministically mapped from plaintexts, an adversary trivially wins the guessing game by having
the challenger encrypt the same value twice, then offering to choose between the static ciphertext
and any other ciphertext -- but both accidental and adversarial nonce-misuse is a concern.

Instead, Veil composes deterministic components -- a KEM, a streaming AEAD, a digital signature --
around a single, probabilistic value: a symmetric data encryption key (DEK). As long as a sender can
manage 256 bits of unpredictability per message, Veil is `IND-CCA2` as a system.

Where challenge values are required -- an ephemeral scalar for Diffie-Hellman or Schorr -- they are
derived from both the unique message and the sender's private key, to preserve unforgability
guarantees.

#### Indistinguishable From Random Noise

Veil messages are entirely indistinguishable from random noise. They contain no plaintext metadata,
no plaintext ristretto255 elements, no plaintext framing or padding, and have entirely arbitrary
lengths. This makes them ideal for distribution via steganographic channels and very resistant to
traffic analysis.

## Algorithms & Constructions

### STROBE Protocols

Full details and documentation for all the Veil protocols can be found in the
[`pkg/veil/internal`](https://github.com/codahale/veil/tree/main/pkg/veil/internal) directory.

#### `veil.kem`

`veil.kem` implements an authenticated `C(1e, 2s, ECC DH)` key encapsulation mechanism over
ristretto255. It provides sender forward security (i.e. if the sender's private key is compromised,
the messages they sent remain confidential) as well as the novel property of sending no values in
cleartext. The ephemeral public key is encrypted with the static shared secret before sending.

#### `veil.pbenc`

`veil.pbenc` implements a memory-hard AEAD using Balloon Hashing, suitable for encrypting secret
keys.

#### `veil.scaldf.*`

`veil.scaldf.*` provides various algorithms for deriving ristretto255 scalars from secret or
non-uniform values. Veil uses them to derive private keys and label scalars.

#### `veil.schnorr`

`veil.schnorr` implements a fully integrated and deterministic Schnorr signature algorithm over
ristretto255, as described in
the [STROBE paper](https://strobe.sourceforge.io/papers/strobe-20170130.pdf). Instead of hashing the
message and signing the digest, it includes the message as sent/received cleartext.

#### `veil.stream`

`veil.stream` provides a streaming AEAD construction, with a streaming plaintext being encrypted in
a blockwise fashion, with key ratcheting after each block. Finalization metadata is used to prevent
truncation/appending attacks.

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

First, the sender generates a random DEK and creates a header block consisting of the DEK and the
total length of all encrypted headers plus padding. For each recipient, the sender encrypts a copy
of the header using `veil.kem`. Finally, the sender adds optional random padding to the end of the
encrypted headers.

Second, the sender uses `veil.schnorr` to create a signature of the plaintext with the encrypted
headers (including any padding) as associated data.

Finally, the sender uses `veil.stream` to encrypt the message and the signature using the message
key, again with the encrypted headers as associated data.

To decrypt a message, the recipient iterates through the message, searching for a decryptable
header. When a header is successfully decrypted, the DEK is recovered, and the message is decrypted.
The signature is verified against the encrypted headers and the plaintext, assuring authenticity.

Because Veil's KEM is authenticated, a message recipient can only decrypt the message if they have
the sender's public key. To send an anonymous message, the sender can include the public key with a
message.

## License

Copyright © 2021 Coda Hale

Distributed under the Apache License 2.0.

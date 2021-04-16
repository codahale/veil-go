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

ristretto255 [uses a safe curve, has non-malleable encodings, and has no co-factor
concerns](https://ristretto.group/why_ristretto.html). STROBE is built on the Keccak 𝑓-\[1600\]
permutation, the core of SHA-3, which has seen [significant scrutiny over the last
decade](https://keccak.team/third_party.html).

The underlying philosophy is that expressed by [Adam
Langley](https://www.imperialviolet.org/2016/05/16/agility.html):

> There's a lesson in all this: have one joint and keep it well oiled. … \[O\]ne needs to minimise
> complexity, concentrate all extensibility in a single place and _actively defend it_.

### Integrated Constructions

Because STROBE provides a wide range of capabilities, it's possible to build fully integrated
cryptographic constructions. Leveraging transcript consistency–the fact that every operation changes
a STROBE protocol's state in a cryptographically secure manner–makes for much simpler protocols with
guarantees that are easier to understand.

Instead of combining a hash function and a digital signature algorithm, we have a single digital
signature construction. Instead of combining a key exchange, a KDF, and an AEAD, we have a single
key encapsulation mechanism. This integration bakes in logical dependencies on sent and received
data in a feed-forward mechanism, which removes it from the attackable surface area of the protocol.

Further, the use of STROBE means all protocols which include `RECV_MAC` calls are [compactly
committing](https://eprint.iacr.org/2019/016.pdf).

### Deterministic Components, `IND-CCA2` System

Veil is designed to be indistinguishable under adaptive chosen ciphertext attacks, since that's the
gold standard for modern cryptosystems. It avoids, however, the usual approach to `IND-CCA2` design,
which is to rub a nonce on everything. Nonces are required for `IND-CCA2`–if ciphertexts are
deterministically mapped from plaintexts, an adversary trivially wins the guessing game by having
the challenger encrypt the same value twice, then offering to choose between the static ciphertext
and any other ciphertext–but both accidental and adversarial nonce-misuse is a concern.

Instead, Veil composes deterministic components–a KEM and a streaming AEAD–around a single,
probabilistic value: a symmetric data encryption key (DEK). As long as a sender can manage 256 bits
of unpredictability per message, Veil is `IND-CCA2` as a system, with keys long enough to provide
adequate security even in the multi-user model.

Where challenge values are required–an ephemeral scalar for Diffie-Hellman or Schorr–they are
derived from both the unique message and the sender's private key, to preserve unforgability
guarantees.

### Indistinguishable From Random Noise

Veil messages are entirely indistinguishable from random noise. They contain no plaintext metadata,
no plaintext ristretto255 elements, no plaintext framing or padding, and have entirely arbitrary
lengths. This makes them ideal for distribution via steganographic channels and very resistant to
traffic analysis.

## Algorithms & Constructions

### Hierarchical Key Derivation

Each participant in Veil has a secret key, which is a 64-byte random string. To derive a private key
from a secret key, the secret key is mapped to a ristretto255 scalar. A delta scalar is derived from
an opaque label value and added to the secret scalar to form a private key. The process is repeated
to derive a private key from another private key. To derive a public key from a public key, the
delta scalar is first multiplied by the curve's base element, then added to the public key element.

This is used iterative to provide hierarchical key derivation. Public keys are created using
hierarchical IDs like `/friends/alice`, in which the private key `/` is used to derive the private
key `friends`, which is in turn used to derive the private key `alice`.

### STROBE Protocols

Full details and documentation for all the Veil protocols can be found in the
[`pkg/veil/internal`](https://github.com/codahale/veil/tree/main/pkg/veil/internal) directory.

#### `veil.hpke`

`veil.hpke` implements multi-recipient hybrid public key encryption using `veil.kem`. Messages are
encrypted with a random DEK, and the DEK and a MAC of the ciphertext are encapsulated in footers
with `veil.kem`. Random padding can be prepended to the footers to obscure the actual message
length, and a `veil.schnorr` signature keyed with the DEK of the encrypted footers is appended to
the end.

To decrypt, readers seek backwards in the ciphertext, looking for a decryptable footer. Having found
one, they then seek to the beginning of the ciphertext, decrypt it, verify the encapsulated MAC,
hash the encrypted footers and any padding, and verify the signature.

This provides strong confidentiality and authenticity guarantees while still providing repudiability
(no recipient can prove a message's contents and origin without revealing their private key) and
forward security for senders (compromise of a sender's private key will not compromise past messages
they sent).

#### `veil.kem`

`veil.kem` implements an authenticated `C(1e, 2s, ECC DH)` key encapsulation mechanism over
ristretto255. It provides authentication, sender forward security (i.e. if the sender's private key
is compromised, the messages they sent remain confidential), as well as the novel property of
sending no values in cleartext: the ephemeral public key is encrypted with the static shared secret
before sending.

#### `veil.pbenc`

`veil.pbenc` implements a memory-hard AEAD using Balloon Hashing, suitable for encrypting secret
keys.

#### `veil.scaldf.*`

`veil.scaldf.*` provides various algorithms for deriving ristretto255 scalars from secret or
non-uniform values. Veil uses them to derive private keys and label scalars.

#### `veil.schnorr`

`veil.schnorr` implements a fully integrated and deterministic Schnorr signature algorithm over
ristretto255, as described in the [STROBE
paper](https://strobe.sourceforge.io/papers/strobe-20170130.pdf). Instead of hashing the message and
signing the digest, it includes the message as sent/received cleartext.

It optionally takes a secret key, allowing for signatures which are indistinguishable from random
noise and unverifiable without it.

## License

Copyright © 2021 Coda Hale

Distributed under the Apache License 2.0.

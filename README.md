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

Veil uses ChaCha20Poly1305 for authenticated encryption, ristretto255/XDH for key agreement and
authentication, Elligator2 for indistinguishable public key encoding, HKDF-SHA3-512 for key
derivation, and a TLS 1.3/STREAM-style construction for authenticated encryption of streaming data.

* ChaCha20Poly1305 is fast, well-studied, and requires no padding. It is vulnerable to nonce misuse,
  but all keys and nonces are derived from random data, making collisions very improbable.
  Constant-time implementations are easy to implement without hardware support.
* The [ristretto255](https://ristretto.group) group uses a
  [safe curve](https://safecurves.cr.yp.to) (Curve25519), has no curve cofactor, has non-malleable
  encodings, and provides ~128-bit security, which roughly maps to the security levels of the other
  algorithms and constructions. Constant-time implementations are common and certainly easier to
  make than other EC curves.
* Elligator2 allows us to map ristretto255/XDH public keys to random strings, making ephemeral
  Diffie-Hellman indistinguishable from random noise. Elligator2 is constant-time.
* HKDF-SHA3-512 is fast, standardized, constant-time, and very well-studied.
* STREAM is simple and provides strong security.

### Key Encapsulation Mechanism (KEM)

Veil messages are encrypted using a Key Encapsulation Mechanism:

1. An ephemeral key pair is generated.
2. The ephemeral shared secret is calculated for the recipient's public key and the ephemeral
   secret key.
3. The static shared secret is calculated for the recipient's public key and the sender's 
   secret key.
4. The two shared secrets are concatenated and used as the initial keying material for
   HKDF-SHA3-512, with the ephemeral public key's representative, the recipient's public key, and 
   the sender's public key as the salt parameter and the authenticated data as the information
   parameter.
5. The first 32 bytes from the HKDF output are used as a ChaCha20Poly1305 key.
6. The next 12 bytes from the HKDF output are used as a ChaCha20Poly1305 nonce.
7. The plaintext is encrypted with ChaCha20Poly1305 using the derived key, the derived nonce, and
   the authenticated data.
8. The ephemeral public key's Elligator2 representative and the ChaCha20Poly1305 ciphertext and tag
   are transmitted.

As a One-Pass Unified Model `C(1e, 2s, ECC CDH)` key agreement scheme (per NIST SP 800-56A), this
KEM provides assurance that the message was encrypted by the holder of the sender's secret key. XDH
mutability issues are mitigated by the inclusion of both the ephemeral public key's Elligator2
representative and the recipient's public key in the HKDF inputs. Deriving the key and nonce from
the ephemeral shared secret eliminates the possibility of nonce misuse, allows for the usage of
ChaCha20 vs XChaCha20, and results in a shorter ciphertext by eliding the nonce. Finally, encoding
the ephemeral public key with Elligator2 ensures the final bytestring is indistinguishable from
random noise.

### Streaming Encryption

To allow for both authenticated encryption _and_ arbitrarily-sized messages, Veil breaks up
plaintexts into blocks, which are encrypted with the derived key and a sequence of nonces. Veil uses
a nonce sequence similar to TLS 1.3, where an initial derived nonce is XORed with a counter to
provide random-looking nonces guaranteed to be unique for each block. To prevent ciphertext
modification, Veil borrows the finalization concept from Rogaway et al's STREAM construction, which
sets the last byte of the nonce to 0 if additional blocks are expected and 1 if the current block is
the final block.

### Messages

Encrypting a Veil message uses the following process:

1. An ephemeral key pair is generated.
2. A plaintext header is generated, containing the ephemeral secret key and the total length of
   encrypted headers.
3. For each recipient, a copy of the header is encrypted using the sender's secret key and the
   recipient's public key, and written as output.
4. The plaintext message is encrypted using the sender's secret key, the ephemeral public key, and 
   the encrypted headers as authenticated data, using STREAM to encrypt the plaintext in blocks.

To decrypt a message, the recipient iterates through the message, searching for a decryptable header
using the shared secret between the ephemeral public key and recipient's secret key. When a header
is successfully decrypted, the ephemeral secret key and the sender's public key is used to re-derive
the shared secret, and the message is decrypted.

### Password-Based Encryption

To safely store secret keys, Argon2id is used with a 16-byte random salt to derive a
ChaCha20Poly1305 key and nonce. The secret key is encrypted with ChaCha20Poly1305, using the
Argon2id parameters as authenticated data.

## What's the point

1. Veil messages are confidential: no one can read the message without being a recipient.
2. Veil messages can be read by all the intended recipients, but no recipient can modify the
   message's content or metadata without possessing the sender's secret key.
3. Veil messages are tamper-proof. If a single bit of the entire message is changed, all the
   recipients will know.
4. Veil messages are indistinguishable from random noise, revealing no metadata about recipients'
   identities, number of recipients, etc.
5. Veil messages can be padded, obscuring a message's actual length.
6. The number of recipients in a Veil message can be obscured from recipients by adding fake keys
   to the recipients list.
7. Veil messages are non-repudiable.
8. Veil messages can be arbitrarily big and both encrypted and decrypted in a single pass.

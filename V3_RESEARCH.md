# Cashu V3 / NutRoot Research

This note records the V3 research relevant to Spilman channels. It is
intentionally conceptual: NUT PR #421 is still open, and the referenced CDK
work does not yet implement NutRoot.

## Sources and Status

- Proposed NutRoot rules: [NUT PR #421](https://github.com/cashubtc/nuts/pull/421), reviewed at `4fbbc99972ddb6dca9e1e309b37b63058a9acd4e`.
- V3/BLS CDK work: [CDK PR #2194](https://github.com/cashubtc/cdk/pull/2194), pinned at `eb34616e88c6f50623ec37b94997c67257279693`.
- CDK NutRoot implementation tracking: [CDK issue #2433](https://github.com/cashubtc/cdk/issues/2433).

The NUT proposal can change. CDK's V3/BLS branch provides the BLS key and
issuance infrastructure, but does not yet provide NutRoot trees, script/key
path witnesses, NUMS handling, or spend-info transfer.

## Version Split

- V1 keysets use version byte `00`.
- V2 keysets use version byte `01`.
- V3/BLS keysets use version byte `02`.

V1/V2 keep their JSON-secret and P2PK condition model. V3 replaces this with
point secrets, NutRoot conditions, BIP-340 witnesses, and a transaction
transcript. V1/V2 channel support should remain unchanged; V3 needs a
separate construction selected by keyset version.

## V3 Proof Issuance

V3 has two independent curve systems:

- secp256k1 controls proof ownership and NutRoot spending conditions.
- BLS12-381 controls blind signatures from the mint.

For a V3 proof, `secret` is a compressed, 33-byte secp256k1 public key encoded
as 66 lowercase hex characters. It is either a bare owner key or a NutRoot
tweaked key.

For a bare key:

```text
secret = P
```

For a conditioned NutRoot output:

```text
secret = P = K + tG
t = tagged_hash("Cashu_NutrootTweak", ser33(K) || merkle_root) mod n
```

`K` is the secp256k1 internal key. The bytes of `P`, not its x-coordinate
alone, are submitted to the V3 BLS blind-signing scheme:

```text
x  = ser33(P)
Y  = hash_to_curve_G1(x)
B_ = rY
C_ = aB_
C  = r^-1 C_ = aY
```

Where:

- `r` is a nonzero BLS scalar chosen by the wallet.
- `a` is the mint's BLS signing scalar for the output denomination.
- `B_` is the blinded message sent to the mint.
- `C_` is the blinded signature returned by the mint.
- `C` is the unblinded proof signature.

The V3 `hash_to_curve_G1` is the specified RFC 9380 BLS12-381 hash-to-curve
suite with Cashu domain separation. It is not an ordinary SHA-256 digest.

The final proof is conceptually:

```text
(amount, output_keyset_id, P, C)
```

## No DLEQ in V3

V1/V2 use DLEQ proofs. V3 directly verifies BLS signatures with pairings.

For a blinded signature from the mint, with mint public key `A = a*g2`:

```text
e(C_, g2) == e(B_, A)
```

For the final proof:

```text
e(C, g2) == e(Y, A)
```

Thus V3 does not produce, store, or verify legacy DLEQ `e`, `s`, and `r`
fields. The proposal also defines batch pairing verification.

## V3 Transaction Transcript

Every V3 input authorizes one canonical transaction digest:

```text
SHA256("Cashu_Transaction_v1" || TLV transcript)
```

The transcript commits to each input proof's:

- amount;
- input proof keyset ID;
- secret;
- unblinded mint signature `C`.

It commits to each blinded-message output's:

- amount;
- requested output keyset ID;
- blinded BLS point `B_`.

It does not include input authorization witnesses/signatures, since those
sign the transcript and including them would be circular.

Inputs and outputs may use different keysets, so both kinds of keyset ID are
committed. In this Spilman implementation, however, a channel ID already
commits to one specific keyset ID. V3 channel derivations therefore do not
need to redundantly include that ID as an independent input, provided this
channel-ID invariant remains explicit and enforced.

V3 has no legacy `SIG_ALL` or `sigflag`. A funding proof is authorized by a
signature over this digest, using either its key path or its selected script
path.

## Recommended Spilman Funding Construction

The closest V3 equivalent to the V1/V2 funding policy is a script-only
NutRoot output. Use a NUMS-offset internal key:

```text
H = standard NutRoot NUMS point
K = H + uG
```

`u` must be unique per funding proof and appears in spend information. No one
knows the discrete logarithm of `H`; knowing `u` does not provide the key-path
scalar for `K`. This is essential: deriving `K` as a normal private scalar
from the shared channel secret would give both parties an immediate unilateral
key-path spend and would bypass the channel policy.

The funding tree should have two leaves:

```text
cooperative leaf:
  threshold, n = 2, keys = [Alice_blinded_key, Charlie_blinded_key]

refund leaf:
  after, n = 1, keys = [Alice_refund_blinded_key], time = expiry
```

The cooperative leaf implements 2-of-2 settlement before expiry. The `after`
leaf already combines the expiry and Alice authorization, so no separate
timelock leaf is required.

The funding secret is then the tweaked key `P` that commits to the two-leaf
tree. A cooperative spend discloses the threshold leaf, control block, and
both BIP-340 signatures. A refund spend discloses the `after` leaf, its
control block, and Alice's signature.

## Balance Updates and Settlement

The existing channel flow can remain structurally the same:

1. Both parties deterministically reconstruct the intended commitment outputs.
2. Alice signs the complete V3 transaction transcript.
3. Alice sends Charlie the cumulative balance and signature.
4. Charlie reconstructs the transcript and validates Alice's signature.
5. At settlement, Charlie signs the same transcript.
6. Both signatures are placed in every funding proof's cooperative witness.

All funding inputs can use the same Alice and Charlie signatures when they
share the same selected leaf keys and sign the same transcript.

## Commitment and Refund Outputs

Alice and Charlie commitment outputs need no tree in the normal case. Each is
a unique bare secp256k1 owner key:

```text
secret = owner_public_key
```

The owner spends it with a BIP-340 signature over the V3 transaction
transcript. This corresponds to the current unique stage-2 ownership keys.

The post-expiry loose refund output should likewise become a unique Alice bare
key. V3 has no unsigned arbitrary-string bearer secret: all V3 proof inputs
must authorize their transaction. A scalar can be passed as bearer spend info
when that is truly intended, but Alice's normal channel path should instead
retain or deterministically recover her owner scalar.

## Determinism and Recovery

The legacy JSON `Secret.nonce` is not a Schnorr signing nonce. It is a
deterministic uniqueness field. V3 has no JSON nonce; uniqueness comes from
the secp256k1 point that is the proof secret.

The channel can preserve its V2-style deterministic reconstruction. From
shared channel metadata, both parties can derive:

```text
channel parameters
  -> blinded participant leaf keys
  -> canonical cooperative and refund leaves
  -> Merkle root
  -> unique NUMS offset u
  -> K = H + uG
  -> secret P = K + tG
  -> Y = hash_to_curve_G1(ser33(P))
  -> BLS blinding scalar r
  -> B_ = rY
```

Consequently both parties can:

- reconstruct `P` and query its spent state through NUT-07;
- reconstruct `P` and `r`, recreate `B_`, and use NUT-09 restore;
- recover `C` from the returned `C_` with `r^-1 C_`.

The deterministic construction must fix and preserve:

- channel secret and channel ID;
- participant public keys;
- expiry;
- output amounts and canonical per-amount indices;
- exact leaf serialization and Merkle construction;
- exact output ordering;
- derivation/version identifier.

Generic V3 wallets must retain spend information such as an arbitrary tree,
random NUMS offsets, or receiver ephemerals because a seed alone cannot infer
them. That does not prevent this channel from reconstructing its data: its
tree is protocol-defined and its values can be derived from persisted channel
metadata. A bare wallet seed alone remains insufficient for complete channel
recovery, just as normal wallet restore and Spilman channel recovery are
distinct concerns today.

Use separate domain-separated derivations for NUMS offsets, secp256k1 owner
or leaf keys, BLS issuance blinding factors, and BIP-340 signing nonces. The
V3 BLS blinding scalar uses rejection sampling against the BLS scalar order;
secp256k1 scalar derivations use rejection sampling against the secp256k1
order.

## Alternative Funding Construction

A MuSig2/FROST aggregate internal key with only an expiry refund leaf would
make cooperative settlement a compact key-path spend. It also adds interactive
nonce handling, partial-signature exchange, aggregation recovery, and more
complexity around blinded participant keys. It is not the recommended first
V3 implementation.

A unilateral participant internal key is not acceptable: its holder can spend
through the key path immediately. A 2-of-2-only tree is also unacceptable,
because it removes Alice's expiry recovery path.

# PVAC-HFHE Seed Challenge — Technical Break Report

**Target:** Octra "HFHE Challenge", a wallet holding 500,000 OCT whose mnemonic was encrypted
with `pvac_hfhe_cpp` (pinned commit `e2835df34ebbc510d3f8c93062dc5bf5bc34d2dc`) and published as
`seed.ct` + `pk.bin` + `params.json`. Secret key `sk.bin` and plaintext withheld.

**Result:** the mnemonic is recoverable from public data only — no secret key, no LPN break, no
weak randomness. Root cause is an **unblinded commitment** that binds the per-layer secret `R`
without hiding it, which (because `R` is algebraically tied to the low-entropy plaintext through a
public quantity) becomes an offline plaintext-verification oracle.

---

## 1. Artifact structure

Parsing `seed.ct` with the project's own serializer (`pvac_artifact_serialize.hpp`) yields
**7 ciphertext objects**:

| cipher | layers | role |
|-------:|:------:|:-----|
| 0 | 2 (BASE, masked) | length cipher — `enc_value(79)` |
| 1..6 | 1 (BASE) | 15-byte data blocks of the mnemonic |

Total plaintext = 79 bytes = a 12-word BIP39 mnemonic. Every layer carries the standard LPN PRF
`ztag` (`prg_layer_ztag`, domain `"pvac.dom.ztag"`), so `ru_src()` is false on all layers — the
"native recrypt" path named in the commit title never engages. `parse_artifacts.cpp` prints this.

## 2. The decryption identity

`dec_values` (in `ops/decrypt.hpp`) reconstructs each slot as

```
acc = c0 + Σ_edges  sign(ch) · w · g^idx · R⁻¹        (per layer, R = prf_R(pk,sk,seed))
```

With `c0 = 0` for a fresh single BASE layer, define the **public** quantity

```
A_L = Σ_edges sign · w · g^idx    (mod p = 2¹²⁷ − 1)
```

computable entirely from the ciphertext edges (`w`, `idx`, `ch`) and `pk.powg_B`. Then

```
A_L = v · R_L
```

where `v` is the plaintext block and `R_L` the secret PRF output. The encryption
(`core::synth` in `ops/encrypt.hpp`) builds every edge weight as `R · (secret random coef)` so
that the signed, `g^idx`-weighted sum telescopes to `v·R`; the per-edge coefficients are fresh
CSPRNG randomness and never published, so no small subset of edges leaks `R`.

Crucially, the **data blocks carry no additive mask**: `enc_text` encrypts each 15-byte block with
a bare `enc_fp_depth → synth`, so `v` is the raw plaintext. Only the *length* cipher uses
`enc_value`, which adds a random mask `m` across two layers.

`A = v·R` with secret uniform `R` is information-theoretically hiding of `v` on its own: for any
`v' ≠ 0` there is a consistent `R' = A/v'`. The ciphertext leaks nothing about `v` — until a guess
of `v` can be tested.

## 3. The vulnerability: unblinded `R_com`

Each BASE layer stores a commitment to its `R` (from `compute_R_com_base`, `core/hash.hpp`):

```
R_com = SHA256( "pvac.dom.r_com" ‖ canon_tag ‖ ztag ‖ nonce_lo ‖ nonce_hi ‖ 1 ‖ R.lo ‖ R.hi )
```

Everything except `R` is public — `canon_tag` from `pk.bin`; `ztag`, `nonce` from the layer — and
there is **no blinding factor**. So `R_com` is a deterministic one-way image of `R` under public
context. Combined with `R = A · v⁻¹`, this is an offline oracle for `v`:

```
guess v  →  R = A · v⁻¹  →  SHA256(public ‖ R)  ==?  published R_com
```

The intended security assumed `R` is a high-entropy PRF output an attacker cannot enumerate — true
if you attack `R` directly. But an attacker enumerates `v` (low entropy) and *derives* `R`. Security
collapses from the 256 + 4096-bit key to the entropy of a 15-byte block.

**Asymmetry:** the sibling per-slot Pedersen commitments `PC = pedersen_commit(R⁻¹, ρ)`
(`compute_layer_PC`) *are* correctly blinded with a secret `ρ` derived from `sk.prf_k`. `R_com` is
not. That inconsistency is the defect. `oracle_poc.cpp` demonstrates the oracle firing on truth and
rejecting wrong guesses, using no secret key.

## 4. Attack surfaces eliminated

| Surface | Verdict | Evidence |
|---|---|---|
| Weak / seeded RNG | closed | `keygen` uses `getrandom`/`/dev/urandom`; `keygen_from_seed` (wallet-derived) is unused by the artifact generator |
| "Native recrypt" `R = 1/(a²+1)` (affine in `prf_k`, public coeffs) | closed | `ru_src()` false on every layer (`ztag` domains differ) |
| LPN weakness | closed | LPN samples never exposed; rows come from a secret AES key |
| R² small-subset leak (a prior bounty bug) | closed | patched; edge weights are `R·rand`; regression-tested |
| Pedersen `PC` commitments | closed | blinded with secret `ρ` |
| Direct key / `R` recovery | closed | no oracle for the key; 4352 secret bits |

The break is the `R_com` commitment specifically, not a weak primitive.

## 5. Exploitation

Since the plaintext is a space-separated BIP39 mnemonic, each 15-byte block spans 2–3 dictionary
words (~2³³ effective), not 2¹²⁷. The solver (`recover_mnemonic.cpp`):

1. Builds a trie of the 2048-word list and enumerates each **distinct** byte-prefix once
   (collapsing the many word-sequences that render to the same 15 bytes).
2. Uses **Montgomery batch inversion** so the hot loop is SHA-256-bound (~4M candidates/s, 4 cores)
   rather than modular-inversion-bound.
3. Verifies each 15-byte block against its `R_com`, keeps matches, and stitches blocks left to
   right. Every block converged to a single survivor.

Per-candidate cost:

```
R = A · v⁻¹ (mod 2¹²⁷−1);   accept iff SHA256(dom ‖ canon_tag ‖ ztag ‖ nonce ‖ 1 ‖ R.lo ‖ R.hi) == R_com
```

Block 0 dominates (~1.6×10⁹ distinct prefixes); interior blocks are similar; recovery completes in
roughly an hour on 4 cores and is trivially parallel / resumable.

## 6. Verification

Recovery is self-certifying and was cross-checked three independent ways:

* **Cryptographic:** all 6 blocks match their published `R_com` (256-bit equality each; false
  positive ≈ 2⁻²⁵⁶).
* **BIP39:** the result is a valid 12-word English mnemonic (checksum valid), 79 bytes — matching
  `params.json: plaintext_bytes = 79`.
* **Address:** Octra's derivation reproduces the funded address exactly:

```
seed   = PBKDF2-HMAC-SHA512(mnemonic, "mnemonic", 2048, 64)
master = HMAC-SHA512("Octra seed", seed)[:32]          # ed25519 private seed
pub    = Ed25519(master).public
addr   = "oct" + base58( SHA256(pub) )
       = oct6Y7jxx92V5nuUykotRqHj6xPz1JEiT3ZRswJ4Awvi9Zn   ✓
```

Recovered mnemonic (challenge retired, funds moved by Octra):

```
convince object outdoor cost pave will coffee student neck typical drama ensure
```

Note: a generic BIP39 wallet (BIP44 / secp256k1) shows a *different* address — Octra's derivation
is non-standard. `scripts/verify_address.py` reproduces the match.

## 7. Root cause and fix

`R_com` is **binding but not hiding**, and its committed value `R` is tied to a low-entropy
plaintext via the public `A`. Binding-without-hiding over guessable content is precisely a
verification oracle. Two independent fixes each close it:

1. **Blind the commitment:** `R_com = SHA256(R ‖ ρ)` with a secret per-layer `ρ` — exactly what the
   `PC` Pedersen commitments already do.
2. **Mask every block:** apply the additive random mask that the length cipher uses to *all* data
   blocks, so no published quantity equals `v·R` for a low-entropy `v`.

With either in place the scheme reduces to genuine LPN / key hardness, and this attack no longer
applies.

# pvac-hfhe-toolkit

Analysis and exploitation toolkit for the **Octra PVAC-HFHE seed challenges** — the bounty
series that encrypts a wallet mnemonic with the `pvac_hfhe_cpp` homomorphic-encryption library
and publishes only the public artifacts (`seed.ct`, `pk.bin`, `params.json`).

It reproduces the break of the 500,000 OCT "HFHE Challenge": recovering the encrypted mnemonic
from **public data only** — no secret key, no LPN break, no weak randomness — by exploiting an
**unblinded commitment** that turns the ciphertext into an offline plaintext-verification oracle.

> The original 500k OCT challenge has been retired by Octra and the funds moved. This toolkit is
> published as a reusable method for the announced follow-up challenges. See
> [`docs/WRITEUP.md`](docs/WRITEUP.md) for the full analysis.

## The bug in one screen

Every PVAC data block decrypts to a single field identity over `p = 2¹²⁷−1`:

```
A = Σ_edges sign · w · g^idx  (mod p)  =  v · R
```

* `A` is **public** — computed from the ciphertext edges and `pk.powg_B`.
* `v` is the 15-byte plaintext block, with **no additive mask** (only the length cipher is masked).
* `R` is a secret per-layer PRF output; recovering it normally needs the full 256 + 4096-bit key.

`A = v·R` with secret uniform `R` perfectly hides `v` — *unless a guess of `v` can be tested.*
Each layer publishes

```
R_com = SHA256("pvac.dom.r_com" ‖ canon_tag ‖ ztag ‖ nonce_lo ‖ nonce_hi ‖ 1 ‖ R.lo ‖ R.hi)
```

with **every input except `R` public and no blinding factor**. Since `R = A·v⁻¹`, any plaintext
guess is verifiable offline:

```
guess v  →  R = A·v⁻¹  →  SHA256(public ‖ R) == R_com ?
```

Security collapses from the key's entropy to the plaintext block's entropy. The plaintext is a
BIP39 mnemonic, so each 15-byte block is 2–3 dictionary words (~2³³) — a fast dictionary search.

The sibling Pedersen commitments (`PC`) in the *same* layer **are** blinded with a secret `ρ`.
That asymmetry is the defect. Fix: blind `R_com` (`SHA256(R ‖ ρ)`) **and** mask every block.

## Layout

```
src/parse_artifacts.cpp    Parse pk.bin + seed.ct; dump layers/edges; compute A per block.
src/oracle_poc.cpp         Minimal proof the R_com oracle fires on truth, rejects wrong guesses.
src/recover_mnemonic.cpp   Trie + batch-inversion staged solver; recovers the full mnemonic.
scripts/verify_address.py  Octra key derivation; check a mnemonic against a known address.
scripts/draft_tx.py        Build + sign an Octra transaction (dry-run unless --send).
docs/WRITEUP.md            Full technical report.
docs/bip39_english.txt     BIP39 English wordlist (2048 words).
```

## Build

Requires a C++17 compiler and a CPU with hardware AES (x86_64 `-maes`, or aarch64 crypto ext),
plus Python 3 with `pynacl` and `base58` for the scripts.

```bash
./setup.sh          # clones pvac_hfhe_cpp (pinned commit) + hfhe-challenge into ./vendor
make                # builds bin/parse_artifacts, bin/oracle_poc, bin/recover_mnemonic
pip install pynacl base58
```

## Usage

**1. Inspect the artifacts** — confirm structure (cipher count, layers, native flag, per-block `A`):

```bash
./bin/parse_artifacts vendor/hfhe-challenge
```

**2. Prove the oracle** — generates a fresh random key, encrypts a known block, then recovers it
using only public data (`A`, `ztag`, `nonce`, `R_com`); no secret key touched:

```bash
./bin/oracle_poc
```

**3. Recover a mnemonic** — end-to-end. `self` validates against a synthetic key; `real` runs the
challenge artifacts. Resumable via `RESUME=<checkpoint-prefix-file>`:

```bash
./bin/recover_mnemonic self 7 79            # self-test (encrypt+recover a random 79-byte phrase)
./bin/recover_mnemonic real vendor/hfhe-challenge
```

Each 15-byte block is confirmed by a 256-bit `R_com` match (false positive ≈ 2⁻²⁵⁶), so a
recovered phrase is self-certifying. Runtime is dominated by the first block (~10⁹ distinct
BIP39 prefixes, SHA-256-bound at ~4M/s on 4 cores).

**4. Verify + claim** (Octra uses a non-standard derivation, *not* BIP44 — a generic wallet shows
a different address):

```bash
python3 scripts/verify_address.py "convince object outdoor cost ..."   # derives + compares
python3 scripts/draft_tx.py --to <oct-addr> --amount 1                  # dry-run signed tx
```

## Method checklist for the next challenge

1. `parse_artifacts` → is it still 1 length cipher + N data blocks, `native = 0`?
2. Did `R_com` gain a blinding factor? (`compute_R_com_base` in `core/hash.hpp`)
3. Did data blocks gain the additive mask the length cipher already uses? (`enc_text` in `utils/text.hpp`)

If (2) or (3) is still missing → the `SHA256(pub ‖ A·v⁻¹) == R_com` attack applies. If both are
fixed → the scheme reduces to genuine LPN/key hardness and needs a different bug.

## License

MIT (this toolkit). The `pvac_hfhe_cpp` and `hfhe-challenge` dependencies are Octra's and are
cloned separately by `setup.sh` under their own licenses — not vendored here.

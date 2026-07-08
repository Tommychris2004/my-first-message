#!/usr/bin/env python3
"""
Draft (and optionally broadcast) an Octra transaction from the recovered wallet.

The winning condition is simply to submit ONE valid transaction from the funded
wallet. This script derives the key from the recovered mnemonic, fetches the
current nonce from the node, builds + signs the transaction in the octra_pre_client
format, and PRINTS it. It only broadcasts when you pass --send.

    python3 claim_tx.py --to <oct-address> --amount 1            # dry-run (prints signed tx)
    python3 claim_tx.py --to <oct-address> --amount 1 --send     # actually broadcast

NOTE ON SCHEMA: field names / endpoints follow the public octra_pre_client
convention (from/to_/amount/nonce/ou/timestamp/signature/public_key, amount in
micro-OCT = 1e6, POST /send-tx, nonce via GET /balance/<addr>). Confirm against
the current client before broadcasting; nothing here sends unless you ask it to.
"""
import argparse, base64, hashlib, hmac, json, sys, time, urllib.request
from nacl.signing import SigningKey

MNEMONIC = "convince object outdoor cost pave will coffee student neck typical drama ensure"
RPC      = "https://octra.network"
MU       = 1_000_000  # micro-OCT per OCT

def derive(mnemonic):
    seed   = hashlib.pbkdf2_hmac("sha512", mnemonic.encode(), b"mnemonic", 2048, 64)
    master = hmac.new(b"Octra seed", seed, hashlib.sha512).digest()[:32]
    sk     = SigningKey(master)
    pub    = sk.verify_key.encode()
    addr   = "oct" + base58_b58encode(hashlib.sha256(pub).digest())
    return sk, pub, addr

def base58_b58encode(b):
    import base58
    return base58.b58encode(b).decode()

def http_get(url):
    with urllib.request.urlopen(url, timeout=20) as r:
        return r.read().decode()

def http_post(url, obj):
    data = json.dumps(obj).encode()
    req = urllib.request.Request(url, data=data, headers={"Content-Type": "application/json"})
    with urllib.request.urlopen(req, timeout=30) as r:
        return r.read().decode()

def get_nonce(addr):
    # octra node: GET /balance/<addr> -> JSON {"balance":..,"nonce":N} or "bal nonce"
    raw = http_get(f"{RPC}/balance/{addr}")
    try:
        j = json.loads(raw); return int(j.get("nonce", 0)), j
    except Exception:
        parts = raw.split()
        return (int(parts[1]) if len(parts) > 1 else 0), raw

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--to", required=True, help="recipient oct address (or the funded address itself for a self-send)")
    ap.add_argument("--amount", type=float, default=1.0, help="amount in OCT")
    ap.add_argument("--message", default="", help="optional message field")
    ap.add_argument("--send", action="store_true", help="actually broadcast (otherwise dry-run)")
    a = ap.parse_args()

    sk, pub, addr = derive(MNEMONIC)
    print(f"from    : {addr}")
    print(f"pubkey  : {base64.b64encode(pub).decode()}")

    try:
        nonce, info = get_nonce(addr)
        print(f"node    : nonce={nonce}  info={info}")
    except Exception as e:
        nonce = None
        print(f"node    : could not fetch nonce ({e}); set it manually before --send", file=sys.stderr)

    tx = {
        "from": addr,
        "to_": a.to,
        "amount": str(int(round(a.amount * MU))),
        "nonce": (nonce + 1) if nonce is not None else 1,
        "ou": "1" if a.amount < 1000 else "3",
        "timestamp": time.time(),
    }
    if a.message:
        tx["message"] = a.message

    body = json.dumps(tx, separators=(",", ":"))
    sig  = base64.b64encode(sk.sign(body.encode()).signature).decode()
    tx["signature"]  = sig
    tx["public_key"] = base64.b64encode(pub).decode()

    print("\nsigned transaction:")
    print(json.dumps(tx, indent=2))

    if a.send:
        print("\nbroadcasting to", f"{RPC}/send-tx", "...")
        print(http_post(f"{RPC}/send-tx", tx))
    else:
        print("\n[dry-run] not broadcast. Re-run with --send to submit.")

if __name__ == "__main__":
    main()

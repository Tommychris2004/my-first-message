import sys, hashlib, hmac, base58
from nacl.signing import SigningKey

TARGET = "oct6Y7jxx92V5nuUykotRqHj6xPz1JEiT3ZRswJ4Awvi9Zn"

def derive(mnemonic, passphrase=""):
    seed = hashlib.pbkdf2_hmac("sha512", mnemonic.encode("utf-8"),
                               ("mnemonic"+passphrase).encode("utf-8"), 2048, 64)
    master = hmac.new(b"Octra seed", seed, hashlib.sha512).digest()[:32]
    sk = SigningKey(master)
    pub = sk.verify_key.encode()               # 32-byte ed25519 pubkey
    addr = "oct" + base58.b58encode(hashlib.sha256(pub).digest()).decode()
    return addr, pub.hex(), master.hex()

if __name__ == "__main__":
    m = " ".join(sys.argv[1:]) if len(sys.argv) > 1 else open("stage_survivors.txt").read().strip()
    addr, pub, priv = derive(m)
    print("mnemonic :", m)
    print("pubkey   :", pub)
    print("address  :", addr)
    print("target   :", TARGET)
    print("MATCH    :", addr == TARGET)

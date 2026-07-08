// PoC: recover a plaintext block from a single-layer PVAC data-block cipher
// using ONLY public data (pk + ciphertext), exploiting the unblinded R_com.
#include <pvac/pvac.hpp>
#include <cstdio>
#include <string>
#include <vector>
using namespace pvac;

// public value A_L = sum_e sgn * w * g^idx  for a given layer of a single-slot cipher
static Fp layerA(const PubKey& pk, const Cipher& C, uint32_t lid){
    Fp acc = fp_from_u64(0);
    for(const auto&e:C.E){
        if(e.layer_id!=lid) continue;
        Fp t=fp_mul(e.w[0], pk.powg_B[e.idx]);
        acc = (e.ch==SGN_P)? fp_add(acc,t): fp_sub(acc,t);
    }
    return acc;
}

int main(){
    Params prm; PubKey pk; SecKey sk;
    keygen(prm, pk, sk);                    // random secret key (as in the challenge)

    std::string msg = "zoo wrong ";        // <=15 bytes -> block[0] is exactly this padded
    auto cts = enc_text(pk, sk, msg);      // cts[0]=length, cts[1]=first 15-byte block
    const Cipher& blk = cts[1];
    printf("block layers=%zu edges=%zu slots=%zu\n", blk.L.size(), blk.E.size(), blk.slots);

    const Layer& L = blk.L[0];
    Fp A = layerA(pk, blk, 0);

    // ---- attacker side: knows pk (canon_tag), the cipher (A, ztag, nonce, R_com). NOT sk. ----
    // brute-force candidate 15-byte ASCII block; here we just confirm the oracle fires on truth
    // and rejects wrong guesses.
    auto make_v = [](const std::string& s){
        uint8_t b[15]={0}; for(size_t i=0;i<s.size()&&i<15;i++) b[i]=(uint8_t)s[i];
        return pack_15_bytes_to_fp(b, 15);
    };
    auto oracle = [&](const std::string& guess)->bool{
        Fp v = make_v(guess);
        if(!(v.lo||v.hi)) return false;
        Fp Rcand = fp_mul(A, fp_inv(v));
        auto rc = compute_R_com_base(pk.canon_tag, L.seed.ztag, L.seed.nonce.lo, L.seed.nonce.hi, {Rcand});
        return rc == L.R_com;
    };

    // The true first 15-byte block content:
    std::string truth = msg; truth.resize(15, '\0');
    printf("oracle(truth)   = %d\n", (int)oracle(truth));
    printf("oracle(wrong1)  = %d\n", (int)oracle("zoo wronx      "));
    printf("oracle(wrong2)  = %d\n", (int)oracle("hello world    "));

    // Also verify our A matches sk-based decryption (sanity, uses sk only to confirm math):
    Fp R_real = prf_R_slots(pk, sk, L.seed, 1)[0];
    Fp v_real = fp_mul(A, fp_inv(R_real));
    uint8_t out[15]; unpack_fp_to_15_bytes(v_real, out);
    printf("sk-decrypt block = '");
    for(int i=0;i<15;i++) putchar(out[i]?out[i]:'.');
    printf("'\n");
    return 0;
}

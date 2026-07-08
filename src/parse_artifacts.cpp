#include <pvac/pvac.hpp>
#include "pvac_artifact_serialize.hpp"
#include <cstdio>
#include <fstream>
#include <vector>
#include <string>

using namespace pvac;

static std::vector<uint8_t> readf(const std::string& p){
    std::ifstream in(p, std::ios::binary); in.seekg(0,std::ios::end);
    auto n=in.tellg(); in.seekg(0); std::vector<uint8_t> d(n); in.read((char*)d.data(),n); return d;
}
static constexpr std::array<uint8_t,16> MG={'O','C','T','R','A','-','H','F','H','E','-','S','E','E','D','1'};
static uint64_t tk(const std::vector<uint8_t>&in,size_t&p){uint64_t v=0;for(int i=0;i<8;i++)v|=(uint64_t)in[p++]<<(8*i);return v;}

int main(int argc,char**argv){
    std::string dir = argv[1];
    auto pkb = readf(dir+"/pk.bin");
    auto ctb = readf(dir+"/seed.ct");
    auto pk = pvac_ser::deserialize_pubkey(pkb.data(), pkb.size());
    printf("== PUBKEY ==\n");
    printf("canon_tag = %llu (0x%016llx)\n",(unsigned long long)pk.canon_tag,(unsigned long long)pk.canon_tag);
    printf("B=%d m_bits=%d n_bits=%d\n",pk.prm.B,pk.prm.m_bits,pk.prm.n_bits);
    printf("powg_B.size=%zu H.size=%zu ubk.perm.size=%zu\n",pk.powg_B.size(),pk.H.size(),pk.ubk.perm.size());
    printf("omega_B = {%016llx,%016llx}\n",(unsigned long long)pk.omega_B.lo,(unsigned long long)pk.omega_B.hi);
    // parse bundle
    size_t p=MG.size(); uint64_t count=tk(ctb,p);
    printf("\n== CIPHER BUNDLE == count=%llu total_bytes=%zu\n",(unsigned long long)count,ctb.size());
    for(uint64_t i=0;i<count;i++){
        uint64_t n=tk(ctb,p);
        Cipher C = pvac_ser::deserialize_cipher(ctb.data()+p, (size_t)n);
        p += n;
        printf("\n-- cipher[%llu] blob=%llu slots=%zu layers=%zu edges=%zu c0nz=%d\n",
            (unsigned long long)i,(unsigned long long)n,C.slots,C.L.size(),C.E.size(),
            (int)field::Op::nz(C.c0));
        for(size_t li=0; li<C.L.size(); ++li){
            const Layer&L=C.L[li];
            bool native = ru_src(pk, L);
            uint64_t zt_std = (L.rule==RRule::BASE)? prg_layer_ztag(pk.canon_tag,L.seed.nonce):0;
            printf("   L[%zu] rule=%s ztag=%016llx nonce=(%016llx,%016llx) PCn=%zu native=%d",
                li, L.rule==RRule::BASE?"BASE":"PROD",
                (unsigned long long)L.seed.ztag,(unsigned long long)L.seed.nonce.lo,(unsigned long long)L.seed.nonce.hi,
                L.PC.size(), (int)native);
            if(L.rule==RRule::BASE) printf(" ztag_matches_std=%d", (int)(L.seed.ztag==zt_std));
            else printf(" pa=%u pb=%u",L.pa,L.pb);
            printf("\n");
        }
        // per-layer A = sum sgn*w*g^idx  (== v*R for that layer), single slot only
        if(C.slots==1){
            std::vector<Fp> A(C.L.size(), fp_from_u64(0));
            std::vector<int> ecount(C.L.size(),0);
            for(const auto&e:C.E){
                Fp t=fp_mul(e.w[0], pk.powg_B[e.idx]);
                if(e.ch==SGN_P) A[e.layer_id]=fp_add(A[e.layer_id],t);
                else A[e.layer_id]=fp_sub(A[e.layer_id],t);
                ecount[e.layer_id]++;
            }
            for(size_t li=0; li<C.L.size(); ++li)
                printf("   A[L%zu]= {%016llx,%016llx} edges=%d\n", li,
                    (unsigned long long)A[li].lo,(unsigned long long)A[li].hi, ecount[li]);
        }
    }
    printf("\nconsumed=%zu of %zu\n",p,ctb.size());
    return 0;
}

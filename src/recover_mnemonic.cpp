// Parallel + batched staged trie recovery. Each block solved with a work-stealing
// frontier + batch inversion. Resumable per block via survivors files.
#include <pvac/pvac.hpp>
#include "pvac_artifact_serialize.hpp"
#include <cstdio>
#include <cstring>
#include <fstream>
#include <string>
#include <vector>
#include <array>
#include <atomic>
#include <mutex>
#include <thread>
#include <chrono>
#include <random>
using namespace pvac;

static std::vector<uint8_t> readf(const std::string&p){std::ifstream in(p,std::ios::binary);in.seekg(0,std::ios::end);auto n=in.tellg();in.seekg(0);std::vector<uint8_t>d(n);in.read((char*)d.data(),n);return d;}
static constexpr std::array<uint8_t,16> MG={'O','C','T','R','A','-','H','F','H','E','-','S','E','E','D','1'};
static uint64_t tk(const std::vector<uint8_t>&in,size_t&p){uint64_t v=0;for(int i=0;i<8;i++)v|=(uint64_t)in[p++]<<(8*i);return v;}
struct Blk{uint64_t canon,ztag,nlo,nhi;std::array<uint8_t,32>rcom;Fp A;int start,end;};
static std::vector<Blk> BLK; static int TOTAL;
static std::vector<std::array<int,26>> CH; static std::vector<char> ISW;
static int newnode(){CH.push_back({});CH.back().fill(-1);ISW.push_back(0);return (int)CH.size()-1;}
static void addword(const std::string&w){int n=0;for(char c:w){int i=c-'a';if(CH[n][i]<0)CH[n][i]=newnode();n=CH[n][i];}ISW[n]=1;}
static inline Fp packfp(const char*p,int len){uint64_t lo=0,hi=0;for(int i=0;i<len&&i<15;i++){uint64_t b=(uint8_t)p[i];int sh=i*8;if(sh<64)lo|=b<<sh;else hi|=b<<(sh-64);}return fp_from_words(lo,hi);}

// A "state" = byte string so far + trie node of in-progress token.
struct State{ std::string s; int node; };

static std::atomic<uint64_t> g_checks{0};

// Solve block b: from each input state (length==BLK[b].start), enumerate distinct byte
// extensions to length BLK[b].end, batch-verify block b, return surviving states
// (length==BLK[b].end, with end trie node). If b==last, require full word (ISW) at TOTAL.
struct Cand{ std::array<char,15> bytes; int node; };  // bytes = block b content (<=15), node = end node
static void flush(int b,int base,std::vector<Cand>&cand,const std::string&prefix,
                  std::vector<State>&out,std::mutex&omtx){
    size_t n=cand.size(); if(!n)return; const Blk&B=BLK[b]; int blen=B.end-B.start;
    std::vector<Fp> vs(n); for(size_t i=0;i<n;i++) vs[i]=packfp(cand[i].bytes.data(),blen);
    std::vector<Fp> pref(n); Fp acc=fp_from_u64(1); for(size_t i=0;i<n;i++){pref[i]=acc;acc=fp_mul(acc,vs[i]);}
    Fp inv=fp_inv(acc); std::vector<State> loc;
    for(size_t i=n;i-->0;){ Fp vinv=fp_mul(inv,pref[i]); inv=fp_mul(inv,vs[i]);
        if(!(vs[i].lo||vs[i].hi))continue; Fp R=fp_mul(B.A,vinv);
        auto rc=compute_R_com_base(B.canon,B.ztag,B.nlo,B.nhi,std::vector<Fp>{R});
        if(rc==B.rcom){ State st; st.s=prefix; st.s.append(cand[i].bytes.data(),blen); st.node=cand[i].node; loc.push_back(std::move(st)); } }
    g_checks.fetch_add(n,std::memory_order_relaxed); cand.clear();
    if(!loc.empty()){ std::lock_guard<std::mutex>lk(omtx); for(auto&x:loc) out.push_back(std::move(x)); }
}
// DFS from (pos,node) filling block b content into cbuf[0..], prefix fixed.
static const size_t BATCH=8192;
static void dfs(int b,int pos,int node,char*cbuf,std::vector<Cand>&cand,
                const std::string&prefix,std::vector<State>&out,std::mutex&omtx){
    if(pos==BLK[b].end){
        // for last block require complete word
        if(b==(int)BLK.size()-1 && !ISW[node]) return;
        Cand c; int blen=BLK[b].end-BLK[b].start; memcpy(c.bytes.data(),cbuf,blen); c.node=node; cand.push_back(c);
        if(cand.size()>=BATCH) flush(b,BLK[b].start,cand,prefix,out,omtx);
        return;
    }
    int rel=pos-BLK[b].start;
    const auto&ch=CH[node];
    for(int i=0;i<26;i++){ if(ch[i]<0)continue; cbuf[rel]=(char)('a'+i); dfs(b,pos+1,ch[i],cbuf,cand,prefix,out,omtx); }
    if(ISW[node] && pos<TOTAL){ cbuf[rel]=' '; dfs(b,pos+1,0,cbuf,cand,prefix,out,omtx); }
}

static std::vector<State> solve(int b,const std::vector<State>&in,unsigned NT){
    // Build a frontier of sub-roots to parallelize: expand states one char-level repeatedly
    // until frontier large enough or reached block end.
    struct Root{ std::string prefix; int pos; int node; };
    std::vector<Root> fr;
    for(auto&st:in) fr.push_back({st.s, BLK[b].start, st.node});
    // expand until >= 4*NT roots (or can't)
    while(fr.size()< (size_t)4*NT){
        std::vector<Root> nf; bool grew=false;
        for(auto&r:fr){ if(r.pos>=BLK[b].end){ nf.push_back(r); continue; }
            const auto&ch=CH[r.node];
            for(int i=0;i<26;i++){ if(ch[i]<0)continue; Root n=r; n.prefix.push_back((char)('a'+i)); n.pos++; n.node=ch[i]; nf.push_back(n); grew=true; }
            if(ISW[r.node] && r.pos<TOTAL){ Root n=r; n.prefix.push_back(' '); n.pos++; n.node=0; nf.push_back(n); grew=true; }
        }
        fr.swap(nf); if(!grew) break;
        if(fr.size()>200000) break;
    }
    std::vector<State> out; std::mutex omtx; std::atomic<size_t> next{0};
    std::vector<std::thread> th;
    for(unsigned t=0;t<NT;t++) th.emplace_back([&]{
        char cbuf[32]; std::vector<Cand> cand;
        for(;;){ size_t i=next.fetch_add(1); if(i>=fr.size())break; Root&r=fr[i];
            // fill cbuf with prefix's block-b bytes already present (prefix.size()-BLK[b].start)
            int have=(int)r.prefix.size()-BLK[b].start; for(int k=0;k<have;k++) cbuf[k]=r.prefix[BLK[b].start+k];
            std::string pfx=r.prefix.substr(0,BLK[b].start);
            dfs(b,r.pos,r.node,cbuf,cand,pfx,out,omtx);
            flush(b,BLK[b].start,cand,pfx,out,omtx);
        }
    });
    for(auto&x:th)x.join();
    return out;
}

int main(int argc,char**argv){
    std::string mode=argc>1?argv[1]:"real";
    std::vector<std::string> WL; { const char*wlf=getenv("WLFILE"); std::ifstream f(wlf?wlf:"docs/bip39_english.txt"); std::string w; while(f>>w)WL.push_back(w);}
    newnode(); for(auto&w:WL) addword(w);
    PubKey pk; std::vector<Cipher> cts; std::string truth;
    if(mode=="self"){ Params prm;SecKey sk;keygen(prm,pk,sk); int TL=argc>3?atoi(argv[3]):79; std::mt19937_64 rng(argc>2?atoll(argv[2]):12345);
        for(;;){std::string m;bool bad=false; while(true){const std::string&w=WL[rng()%WL.size()];size_t need=m.size()+(m.empty()?0:1)+w.size();
            if((int)need==TL){if(!m.empty())m+=' ';m+=w;break;} if((int)need<TL-3){if(!m.empty())m+=' ';m+=w;} else{size_t rem=TL-m.size()-(m.empty()?0:1);bool ok=false;for(auto&ww:WL)if(ww.size()==rem){if(!m.empty())m+=' ';m+=ww;ok=true;break;}if(ok)break;else{bad=true;break;}}}
            if(!bad&&(int)m.size()==TL){truth=m;break;}}
        fprintf(stderr,"self truth: '%s'\n",truth.c_str()); cts=enc_text(pk,sk,truth);
    } else { std::string dir=argc>2?argv[2]:"hfhe-challenge"; auto pkb=readf(dir+"/pk.bin"); pk=pvac_ser::deserialize_pubkey(pkb.data(),pkb.size());
        auto ctb=readf(dir+"/seed.ct"); size_t p=MG.size(); uint64_t cnt=tk(ctb,p); for(uint64_t i=0;i<cnt;i++){uint64_t n=tk(ctb,p);cts.push_back(pvac_ser::deserialize_cipher(ctb.data()+p,(size_t)n));p+=n;} }
    TOTAL=(mode=="self")?(int)truth.size():79;
    for(int i=1;i<(int)cts.size();++i){const Cipher&C=cts[i];const Layer&L=C.L[0];Fp A=fp_from_u64(0);
        for(const auto&e:C.E){Fp t=fp_mul(e.w[0],pk.powg_B[e.idx]);A=(e.ch==SGN_P)?fp_add(A,t):fp_sub(A,t);}
        Blk B;B.canon=pk.canon_tag;B.ztag=L.seed.ztag;B.nlo=L.seed.nonce.lo;B.nhi=L.seed.nonce.hi;B.rcom=L.R_com;B.A=A;B.start=15*(i-1);B.end=std::min(15*(i-1)+15,TOTAL);BLK.push_back(B);}
    fprintf(stderr,"TOTAL=%d blocks=%zu\n",TOTAL,BLK.size());
    unsigned NT=std::thread::hardware_concurrency(); if(!NT)NT=4;

    // optional: resume from a checkpoint prefix (any length ending at a block boundary)
    std::vector<State> cur; int startb=0;
    const char* rf=getenv("RESUME");
    if(!rf) rf=getenv("SEED0");
    if(rf){ std::ifstream f(rf); std::string s0; std::getline(f,s0);
        int len=(int)s0.size();
        // which block boundary does len match?
        int sb=-1; for(int b=0;b<(int)BLK.size();++b) if(BLK[b].end==len){ sb=b+1; break; }
        if(len==15 && sb<0) sb=1; // SEED0 raw 15-byte
        if(sb>=0){ int node=0,lastsp=-1; for(int k=0;k<len;k++) if(s0[k]==' ')lastsp=k; bool ok=true;
            for(int k=lastsp+1;k<len;k++){int ci=s0[k]-'a'; if(ci<0||ci>25||CH[node][ci]<0){ok=false;break;} node=CH[node][ci];}
            if(ok){ cur.push_back({s0,node}); startb=sb; fprintf(stderr,"resumed prefix(%d)='%s' -> start block %d\n",len,s0.c_str(),startb); } } }
    if(cur.empty()){ startb=0; cur.push_back({std::string(),0}); }

    for(int b=startb;b<(int)BLK.size();++b){
        auto t0=std::chrono::steady_clock::now();
        cur=solve(b,cur,NT);
        double el=std::chrono::duration<double>(std::chrono::steady_clock::now()-t0).count();
        fprintf(stderr,"block %d: survivors=%zu checks=%llu (%.1fs)\n",b,cur.size(),(unsigned long long)g_checks.load(),el);
        // persist survivors
        { std::ofstream o("stage_survivors.txt"); for(auto&st:cur) o<<st.s<<"\n"; }
        if(cur.empty()){ printf("NO MATCH at block %d\n",b); return 1; }
    }
    std::string ans; for(auto&st:cur) if((int)st.s.size()==TOTAL && ISW[st.node]) ans=st.s;
    if(!ans.empty()){ printf("RECOVERED: '%s'\n",ans.c_str()); if(mode=="self")printf("match=%d\n",ans==truth); return 0; }
    printf("survivors=%zu none complete\n",cur.size()); for(auto&st:cur) printf("  '%s'(%zu)\n",st.s.c_str(),st.s.size()); return 1;
}

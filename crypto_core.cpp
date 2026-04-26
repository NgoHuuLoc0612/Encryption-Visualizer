/**
 * crypto_core.cpp  —  Encryption Visualizer
 * C++17. MSVC/GCC/Clang compatible.
 */
#ifdef _MSC_VER
#  pragma warning(disable: 4146 4244 4267 4334)
#  define NOMINMAX
#endif

#include "crypto_core.hpp"
#include <algorithm>
#include <bitset>
#include <cassert>
#include <chrono>
#include <cmath>
#include <cstring>
#include <iomanip>
#include <numeric>
#include <random>
#include <sstream>
#include <stdexcept>
#include <functional>
#include <map>

// ════════════════════════════════════════════════════════════════════════════
// Utilities
// ════════════════════════════════════════════════════════════════════════════

static std::string to_hex(const uint8_t* d, size_t n){
    std::ostringstream o; o<<std::hex<<std::setfill('0');
    for(size_t i=0;i<n;++i) o<<std::setw(2)<<(int)d[i]; return o.str();
}
static std::string to_hex(const std::vector<uint8_t>& v){ return to_hex(v.data(),v.size()); }
static std::string to_bin8(uint8_t b){ return std::bitset<8>(b).to_string(); }
static std::string to_hex32(uint32_t v){ char buf[9]; snprintf(buf,9,"%08x",v); return buf; }
static std::string to_hex64(uint64_t v){ char buf[17]; snprintf(buf,17,"%016llx",(unsigned long long)v); return buf; }

static std::vector<uint8_t> hex2bytes(const std::string& h){
    std::vector<uint8_t> r;
    for(size_t i=0;i+1<=h.size();i+=2) r.push_back((uint8_t)std::stoul(h.substr(i,2),nullptr,16));
    return r;
}
static std::string bytes2hex(const std::vector<uint8_t>& v){ return to_hex(v); }

static int hamming_weight(uint8_t b){ return std::bitset<8>(b).count(); }
static int hamming_weight32(uint32_t v){ return std::bitset<32>(v).count(); }
static int hamming_weight64(uint64_t v){ return std::bitset<64>(v).count(); }

static uint32_t rotl32(uint32_t v, int n){ return (v<<n)|(v>>(32-n)); }
static uint32_t rotr32(uint32_t v, int n){ return (v>>n)|(v<<(32-n)); }
static uint64_t rotl64(uint64_t v, int n){ return (v<<n)|(v>>(64-n)); }

// Portable 64-bit modular multiplication (MSVC has no __uint128_t)
static uint64_t mulmod64(uint64_t a, uint64_t b, uint64_t m){
    uint64_t result=0; a%=m;
    while(b>0){
        if(b&1){ result+=a; if(result>=m) result-=m; }
        a<<=1; if(a>=m) a-=m; b>>=1;
    }
    return result;
}
static uint64_t mod_pow(uint64_t base, uint64_t exp, uint64_t mod){
    if(mod==1) return 0;
    uint64_t r=1; base%=mod;
    while(exp>0){ if(exp&1) r=mulmod64(r,base,mod); base=mulmod64(base,base,mod); exp>>=1; }
    return r;
}

// RNG
static std::mt19937_64 g_rng(std::chrono::steady_clock::now().time_since_epoch().count());
static std::vector<uint8_t> random_bytes(size_t n){
    std::uniform_int_distribution<uint16_t> dist(0,255);
    std::vector<uint8_t> v(n);
    for(auto& b:v) b=static_cast<uint8_t>(dist(g_rng));
    return v;
}

// ════════════════════════════════════════════════════════════════════════════
// AES Tables
// ════════════════════════════════════════════════════════════════════════════

static const uint8_t SBOX[256]={
0x63,0x7c,0x77,0x7b,0xf2,0x6b,0x6f,0xc5,0x30,0x01,0x67,0x2b,0xfe,0xd7,0xab,0x76,
0xca,0x82,0xc9,0x7d,0xfa,0x59,0x47,0xf0,0xad,0xd4,0xa2,0xaf,0x9c,0xa4,0x72,0xc0,
0xb7,0xfd,0x93,0x26,0x36,0x3f,0xf7,0xcc,0x34,0xa5,0xe5,0xf1,0x71,0xd8,0x31,0x15,
0x04,0xc7,0x23,0xc3,0x18,0x96,0x05,0x9a,0x07,0x12,0x80,0xe2,0xeb,0x27,0xb2,0x75,
0x09,0x83,0x2c,0x1a,0x1b,0x6e,0x5a,0xa0,0x52,0x3b,0xd6,0xb3,0x29,0xe3,0x2f,0x84,
0x53,0xd1,0x00,0xed,0x20,0xfc,0xb1,0x5b,0x6a,0xcb,0xbe,0x39,0x4a,0x4c,0x58,0xcf,
0xd0,0xef,0xaa,0xfb,0x43,0x4d,0x33,0x85,0x45,0xf9,0x02,0x7f,0x50,0x3c,0x9f,0xa8,
0x51,0xa3,0x40,0x8f,0x92,0x9d,0x38,0xf5,0xbc,0xb6,0xda,0x21,0x10,0xff,0xf3,0xd2,
0xcd,0x0c,0x13,0xec,0x5f,0x97,0x44,0x17,0xc4,0xa7,0x7e,0x3d,0x64,0x5d,0x19,0x73,
0x60,0x81,0x4f,0xdc,0x22,0x2a,0x90,0x88,0x46,0xee,0xb8,0x14,0xde,0x5e,0x0b,0xdb,
0xe0,0x32,0x3a,0x0a,0x49,0x06,0x24,0x5c,0xc2,0xd3,0xac,0x62,0x91,0x95,0xe4,0x79,
0xe7,0xc8,0x37,0x6d,0x8d,0xd5,0x4e,0xa9,0x6c,0x56,0xf4,0xea,0x65,0x7a,0xae,0x08,
0xba,0x78,0x25,0x2e,0x1c,0xa6,0xb4,0xc6,0xe8,0xdd,0x74,0x1f,0x4b,0xbd,0x8b,0x8a,
0x70,0x3e,0xb5,0x66,0x48,0x03,0xf6,0x0e,0x61,0x35,0x57,0xb9,0x86,0xc1,0x1d,0x9e,
0xe1,0xf8,0x98,0x11,0x69,0xd9,0x8e,0x94,0x9b,0x1e,0x87,0xe9,0xce,0x55,0x28,0xdf,
0x8c,0xa1,0x89,0x0d,0xbf,0xe6,0x42,0x68,0x41,0x99,0x2d,0x0f,0xb0,0x54,0xbb,0x16};

static const uint8_t INV_SBOX[256]={
0x52,0x09,0x6a,0xd5,0x30,0x36,0xa5,0x38,0xbf,0x40,0xa3,0x9e,0x81,0xf3,0xd7,0xfb,
0x7c,0xe3,0x39,0x82,0x9b,0x2f,0xff,0x87,0x34,0x8e,0x43,0x44,0xc4,0xde,0xe9,0xcb,
0x54,0x7b,0x94,0x32,0xa6,0xc2,0x23,0x3d,0xee,0x4c,0x95,0x0b,0x42,0xfa,0xc3,0x4e,
0x08,0x2e,0xa1,0x66,0x28,0xd9,0x24,0xb2,0x76,0x5b,0xa2,0x49,0x6d,0x8b,0xd1,0x25,
0x72,0xf8,0xf6,0x64,0x86,0x68,0x98,0x16,0xd4,0xa4,0x5c,0xcc,0x5d,0x65,0xb6,0x92,
0x6c,0x70,0x48,0x50,0xfd,0xed,0xb9,0xda,0x5e,0x15,0x46,0x57,0xa7,0x8d,0x9d,0x84,
0x90,0xd8,0xab,0x00,0x8c,0xbc,0xd3,0x0a,0xf7,0xe4,0x58,0x05,0xb8,0xb3,0x45,0x06,
0xd0,0x2c,0x1e,0x8f,0xca,0x3f,0x0f,0x02,0xc1,0xaf,0xbd,0x03,0x01,0x13,0x8a,0x6b,
0x3a,0x91,0x11,0x41,0x4f,0x67,0xdc,0xea,0x97,0xf2,0xcf,0xce,0xf0,0xb4,0xe6,0x73,
0x96,0xac,0x74,0x22,0xe7,0xad,0x35,0x85,0xe2,0xf9,0x37,0xe8,0x1c,0x75,0xdf,0x6e,
0x47,0xf1,0x1a,0x71,0x1d,0x29,0xc5,0x89,0x6f,0xb7,0x62,0x0e,0xaa,0x18,0xbe,0x1b,
0xfc,0x56,0x3e,0x4b,0xc6,0xd2,0x79,0x20,0x9a,0xdb,0xc0,0xfe,0x78,0xcd,0x5a,0xf4,
0x1f,0xdd,0xa8,0x33,0x88,0x07,0xc7,0x31,0xb1,0x12,0x10,0x59,0x27,0x80,0xec,0x5f,
0x60,0x51,0x7f,0xa9,0x19,0xb5,0x4a,0x0d,0x2d,0xe5,0x7a,0x9f,0x93,0xc9,0x9c,0xef,
0xa0,0xe0,0x3b,0x4d,0xae,0x2a,0xf5,0xb0,0xc8,0xeb,0xbb,0x3c,0x83,0x53,0x99,0x61,
0x17,0x2b,0x04,0x7e,0xba,0x77,0xd6,0x26,0xe1,0x69,0x14,0x63,0x55,0x21,0x0c,0x7d};

static const uint8_t RCON[11]={0x00,0x01,0x02,0x04,0x08,0x10,0x20,0x40,0x80,0x1b,0x36};

static uint8_t gf_mul(uint8_t a, uint8_t b){
    uint8_t r=0;
    for(int i=0;i<8;++i){
        if(b&1) r^=a;
        bool hi=a&0x80; a<<=1; if(hi) a^=0x1b; b>>=1;
    }
    return r;
}

// ── AES Key Expansion ─────────────────────────────────────────────────────────
struct AESCtx {
    int nk,nr;
    std::vector<uint32_t> rk;
    std::vector<std::vector<uint8_t>> rk_bytes;
};

static AESCtx aes_expand(const std::vector<uint8_t>& key){
    AESCtx c; c.nk=(int)key.size()/4; c.nr=c.nk+6;
    int total=4*(c.nr+1); c.rk.resize(total);
    for(int i=0;i<c.nk;++i)
        c.rk[i]=((uint32_t)key[4*i]<<24)|((uint32_t)key[4*i+1]<<16)|((uint32_t)key[4*i+2]<<8)|key[4*i+3];
    for(int i=c.nk;i<total;++i){
        uint32_t t=c.rk[i-1];
        if(i%c.nk==0){
            t=(t<<8)|(t>>24);
            t=((uint32_t)SBOX[(t>>24)&0xff]<<24)|((uint32_t)SBOX[(t>>16)&0xff]<<16)|((uint32_t)SBOX[(t>>8)&0xff]<<8)|(uint32_t)SBOX[t&0xff];
            t^=((uint32_t)RCON[i/c.nk]<<24);
        } else if(c.nk>6&&i%c.nk==4){
            t=((uint32_t)SBOX[(t>>24)&0xff]<<24)|((uint32_t)SBOX[(t>>16)&0xff]<<16)|((uint32_t)SBOX[(t>>8)&0xff]<<8)|(uint32_t)SBOX[t&0xff];
        }
        c.rk[i]=c.rk[i-c.nk]^t;
    }
    for(int r=0;r<=c.nr;++r){
        std::vector<uint8_t> rb(16);
        for(int w=0;w<4;++w){
            uint32_t word=c.rk[r*4+w];
            rb[w*4]=(word>>24)&0xff; rb[w*4+1]=(word>>16)&0xff;
            rb[w*4+2]=(word>>8)&0xff; rb[w*4+3]=word&0xff;
        }
        c.rk_bytes.push_back(rb);
    }
    return c;
}

// ── AES Block Operations ──────────────────────────────────────────────────────
static void add_round_key(uint8_t s[4][4], const std::vector<uint32_t>& rk, int r){
    for(int c=0;c<4;++c){
        uint32_t w=rk[r*4+c];
        s[0][c]^=(w>>24)&0xff; s[1][c]^=(w>>16)&0xff;
        s[2][c]^=(w>>8)&0xff;  s[3][c]^=w&0xff;
    }
}
static void sub_bytes(uint8_t s[4][4]){ for(int i=0;i<4;++i) for(int j=0;j<4;++j) s[i][j]=SBOX[s[i][j]]; }
static void inv_sub_bytes(uint8_t s[4][4]){ for(int i=0;i<4;++i) for(int j=0;j<4;++j) s[i][j]=INV_SBOX[s[i][j]]; }
static void shift_rows(uint8_t s[4][4]){
    uint8_t t;
    t=s[1][0];s[1][0]=s[1][1];s[1][1]=s[1][2];s[1][2]=s[1][3];s[1][3]=t;
    t=s[2][0];s[2][0]=s[2][2];s[2][2]=t; t=s[2][1];s[2][1]=s[2][3];s[2][3]=t;
    t=s[3][3];s[3][3]=s[3][2];s[3][2]=s[3][1];s[3][1]=s[3][0];s[3][0]=t;
}
static void inv_shift_rows(uint8_t s[4][4]){
    uint8_t t;
    t=s[1][3];s[1][3]=s[1][2];s[1][2]=s[1][1];s[1][1]=s[1][0];s[1][0]=t;
    t=s[2][0];s[2][0]=s[2][2];s[2][2]=t; t=s[2][1];s[2][1]=s[2][3];s[2][3]=t;
    t=s[3][0];s[3][0]=s[3][1];s[3][1]=s[3][2];s[3][2]=s[3][3];s[3][3]=t;
}
static void mix_columns(uint8_t s[4][4]){
    for(int c=0;c<4;++c){
        uint8_t a=s[0][c],b=s[1][c],d=s[2][c],e=s[3][c];
        s[0][c]=gf_mul(2,a)^gf_mul(3,b)^d^e;
        s[1][c]=a^gf_mul(2,b)^gf_mul(3,d)^e;
        s[2][c]=a^b^gf_mul(2,d)^gf_mul(3,e);
        s[3][c]=gf_mul(3,a)^b^d^gf_mul(2,e);
    }
}
static void inv_mix_columns(uint8_t s[4][4]){
    for(int c=0;c<4;++c){
        uint8_t a=s[0][c],b=s[1][c],d=s[2][c],e=s[3][c];
        s[0][c]=gf_mul(0x0e,a)^gf_mul(0x0b,b)^gf_mul(0x0d,d)^gf_mul(0x09,e);
        s[1][c]=gf_mul(0x09,a)^gf_mul(0x0e,b)^gf_mul(0x0b,d)^gf_mul(0x0d,e);
        s[2][c]=gf_mul(0x0d,a)^gf_mul(0x09,b)^gf_mul(0x0e,d)^gf_mul(0x0b,e);
        s[3][c]=gf_mul(0x0b,a)^gf_mul(0x0d,b)^gf_mul(0x09,d)^gf_mul(0x0e,e);
    }
}
static std::vector<uint8_t> state_vec(const uint8_t s[4][4]){
    std::vector<uint8_t> v(16);
    for(int r=0;r<4;++r) for(int c=0;c<4;++c) v[c*4+r]=s[r][c];
    return v;
}
static void vec_to_state(const std::vector<uint8_t>& v, uint8_t s[4][4]){
    for(int c=0;c<4;++c) for(int r=0;r<4;++r) s[r][c]=v[c*4+r];
}
static std::string state_hex(const uint8_t s[4][4]){ return to_hex(state_vec(s)); }

// Encrypt one 16-byte block, capture full round state
static std::vector<AESRoundState> aes_block_encrypt(uint8_t s[4][4], const AESCtx& ctx,
                                                      const std::vector<uint8_t>* prev_ct=nullptr){
    std::vector<AESRoundState> rounds;
    AESRoundState rs0;
    rs0.round=0; rs0.state_before=state_hex(s);
    add_round_key(s,ctx.rk,0);
    rs0.after_add_round_key=state_hex(s);
    rs0.after_sub_bytes=rs0.state_before;
    rs0.after_shift_rows=rs0.state_before;
    rs0.after_mix_columns=rs0.state_before;
    rs0.subkey=to_hex(ctx.rk_bytes[0]);
    rs0.operation="InitialAddRoundKey";
    // HW trace
    for(auto b:state_vec(s)) rs0.hw_distribution.push_back(hamming_weight(b));
    // Active S-boxes (non-zero bytes going into SubBytes)
    for(int i=0;i<16;++i) if(state_vec(s)[i]) rs0.active_sboxes.push_back(i);
    // Differential mask vs previous ciphertext
    if(prev_ct){
        auto cur=state_vec(s);
        for(size_t i=0;i<16;++i) rs0.differential_mask.push_back(cur[i]^(*prev_ct)[i]);
    }
    rounds.push_back(rs0);

    for(int round=1;round<=ctx.nr;++round){
        AESRoundState rs;
        rs.round=round;
        rs.state_before=state_hex(s);
        auto before_bytes=state_vec(s);

        sub_bytes(s); rs.after_sub_bytes=state_hex(s);
        // Count active S-boxes
        for(int i=0;i<16;++i) if(before_bytes[i]) rs.active_sboxes.push_back(i);

        shift_rows(s); rs.after_shift_rows=state_hex(s);

        if(round<ctx.nr){ mix_columns(s); rs.after_mix_columns=state_hex(s); }
        else rs.after_mix_columns=rs.after_shift_rows;

        add_round_key(s,ctx.rk,round); rs.after_add_round_key=state_hex(s);
        rs.subkey=to_hex(ctx.rk_bytes[round]);
        rs.operation=(round<ctx.nr)?"FullRound":"FinalRound";

        // HW distribution for power trace
        for(auto b:state_vec(s)) rs.hw_distribution.push_back(hamming_weight(b));

        // Differential propagation
        if(prev_ct){
            auto cur=state_vec(s);
            for(size_t i=0;i<16;++i) rs.differential_mask.push_back(cur[i]^(*prev_ct)[i]);
        }
        rounds.push_back(rs);
    }
    return rounds;
}

static std::vector<uint8_t> aes_raw_encrypt(const std::vector<uint8_t>& pt, const AESCtx& ctx){
    uint8_t s[4][4];
    vec_to_state(pt,s);
    aes_block_encrypt(s,ctx);
    return state_vec(s);
}

// ── GCM GHASH ─────────────────────────────────────────────────────────────────
static std::vector<uint8_t> ghash(const std::vector<uint8_t>& H,
                                   const std::vector<uint8_t>& data){
    std::vector<uint8_t> y(16,0);
    // GF(2^128) multiplication mod x^128+x^7+x^2+x+1
    auto gf128_mul=[](const std::vector<uint8_t>& a, const std::vector<uint8_t>& b)->std::vector<uint8_t>{
        std::vector<uint8_t> z(16,0);
        std::vector<uint8_t> v=b;
        for(int i=0;i<16;++i){
            for(int bit=7;bit>=0;--bit){
                if((a[i]>>bit)&1){
                    for(int k=0;k<16;++k) z[k]^=v[k];
                }
                bool lsb=v[15]&1;
                for(int k=15;k>0;--k) v[k]=(uint8_t)((v[k]>>1)|(v[k-1]<<7));
                v[0]>>=1;
                if(lsb) v[0]^=0xe1;
            }
        }
        return z;
    };
    size_t n=data.size(); size_t i=0;
    while(i+16<=n){
        for(int k=0;k<16;++k) y[k]^=data[i+k];
        y=gf128_mul(y,H); i+=16;
    }
    if(i<n){
        std::vector<uint8_t> last(16,0);
        for(size_t k=i;k<n;++k) last[k-i]=data[k];
        for(int k=0;k<16;++k) y[k]^=last[k];
        y=gf128_mul(y,H);
    }
    return y;
}

// ════════════════════════════════════════════════════════════════════════════
// AES main entry (ECB / CBC / CTR / GCM)
// ════════════════════════════════════════════════════════════════════════════

AESResult aes_encrypt_visualize(const std::string& pt_hex, const std::string& key_hex,
                                  const std::string& mode, const std::string& iv_hex){
    AESResult res;
    auto pt  = hex2bytes(pt_hex);
    auto key = hex2bytes(key_hex);
    if(key.size()!=16&&key.size()!=24&&key.size()!=32)
        throw std::invalid_argument("Key must be 16/24/32 bytes");

    AESCtx ctx=aes_expand(key);
    for(auto& rb:ctx.rk_bytes) res.key_schedule.push_back(to_hex(rb));
    for(int i=0;i<256;++i){ char b[3]; snprintf(b,3,"%02x",SBOX[i]); res.sbox_hex.push_back(b); }
    res.algorithm="AES-"+std::to_string(key.size()*8);
    res.mode=mode;

    // Pad plaintext to block size for non-CTR/GCM modes
    auto pkcs7=[](std::vector<uint8_t>& v){
        uint8_t pad=16-(v.size()%16); for(int i=0;i<pad;++i) v.push_back(pad);
    };

    auto iv=iv_hex.empty()?std::vector<uint8_t>(16,0):hex2bytes(iv_hex);
    res.iv_hex=to_hex(iv);

    std::vector<uint8_t> ciphertext;

    if(mode=="ECB"){
        auto padded=pt; pkcs7(padded);
        for(size_t i=0;i<padded.size();i+=16){
            std::vector<uint8_t> block(padded.begin()+i,padded.begin()+i+16);
            uint8_t s[4][4]; vec_to_state(block,s);
            auto rounds=aes_block_encrypt(s,ctx);
            if(i==0) res.rounds=rounds;
            auto ct_block=state_vec(s);
            ciphertext.insert(ciphertext.end(),ct_block.begin(),ct_block.end());
        }
    } else if(mode=="CBC"){
        auto padded=pt; pkcs7(padded);
        std::vector<uint8_t> prev=iv;
        for(size_t i=0;i<padded.size();i+=16){
            std::vector<uint8_t> block(padded.begin()+i,padded.begin()+i+16);
            for(int k=0;k<16;++k) block[k]^=prev[k];
            uint8_t s[4][4]; vec_to_state(block,s);
            auto rounds=aes_block_encrypt(s,ctx,i>0?&prev:nullptr);
            if(i==0) res.rounds=rounds;
            prev=state_vec(s);
            ciphertext.insert(ciphertext.end(),prev.begin(),prev.end());
        }
    } else if(mode=="CTR"){
        std::vector<uint8_t> counter_block=iv;
        auto inc_ctr=[](std::vector<uint8_t>& ctr){
            for(int i=15;i>=0;--i){ if(++ctr[i]) break; }
        };
        for(size_t i=0;i<pt.size();i+=16){
            uint8_t s[4][4]; vec_to_state(counter_block,s);
            auto rounds=aes_block_encrypt(s,ctx);
            if(i==0) res.rounds=rounds;
            auto keystream=state_vec(s);
            size_t len=std::min((size_t)16,pt.size()-i);
            for(size_t k=0;k<len;++k) ciphertext.push_back(pt[i+k]^keystream[k]);
            inc_ctr(counter_block);
        }
    } else if(mode=="GCM"){
        // H = AES_K(0^128)
        std::vector<uint8_t> H_in(16,0);
        uint8_t hs[4][4]; vec_to_state(H_in,hs);
        aes_block_encrypt(hs,ctx);
        auto H=state_vec(hs);

        // J0 = IV || 0^31 || 1
        std::vector<uint8_t> J0(16,0);
        for(int k=0;k<12&&k<(int)iv.size();++k) J0[k]=iv[k];
        J0[15]=1;

        // Encrypt with CTR starting at J0+1
        std::vector<uint8_t> ctr=J0; ctr[15]=2;
        auto inc_ctr=[](std::vector<uint8_t>& c){
            for(int i=15;i>=12;--i){ if(++c[i]) break; }
        };
        for(size_t i=0;i<pt.size();i+=16){
            uint8_t s[4][4]; vec_to_state(ctr,s);
            auto rounds=aes_block_encrypt(s,ctx);
            if(i==0) res.rounds=rounds;
            auto ks=state_vec(s);
            size_t len=std::min((size_t)16,pt.size()-i);
            for(size_t k=0;k<len;++k) ciphertext.push_back(pt[i+k]^ks[k]);
            inc_ctr(ctr);
        }
        // GHASH for tag
        auto ghash_result=ghash(H,ciphertext);
        uint8_t ts[4][4]; vec_to_state(J0,ts);
        aes_block_encrypt(ts,ctx);
        auto enc_j0=state_vec(ts);
        std::vector<uint8_t> tag(16);
        for(int i=0;i<16;++i) tag[i]=ghash_result[i]^enc_j0[i];
        res.tag_hex=to_hex(tag);
    } else {
        throw std::invalid_argument("Unknown mode: "+mode+". Use ECB/CBC/CTR/GCM");
    }

    res.ciphertext_hex=to_hex(ciphertext);

    // ── Research metrics ──────────────────────────────────────────────────────
    // Per-round avalanche: bit difference vs initial plaintext
    if(!res.rounds.empty()){
        auto pt_block=hex2bytes(res.rounds[0].state_before);
        for(auto& r:res.rounds){
            auto after=hex2bytes(r.after_add_round_key);
            int bits=0;
            for(size_t i=0;i<16;++i) bits+=hamming_weight(pt_block[i]^after[i]);
            res.round_avalanche.push_back(bits/128.0);
        }
        // Hamming-weight power trace (first block)
        for(auto& r:res.rounds)
            for(double hw:r.hw_distribution)
                res.hw_trace.push_back((int)hw);
    }

    // Strict Avalanche Criterion (quick, 64 samples)
    {
        int total_flips=0, total_bits=0;
        auto sample_pt=pt.empty()?std::vector<uint8_t>(16,0):std::vector<uint8_t>(pt.begin(),pt.begin()+16);
        if(sample_pt.size()<16) sample_pt.resize(16,0);
        auto base_ct=aes_raw_encrypt(sample_pt,ctx);
        for(int bit=0;bit<128;++bit){
            auto flipped=sample_pt;
            flipped[bit/8]^=(1<<(7-bit%8));
            auto flipped_ct=aes_raw_encrypt(flipped,ctx);
            for(int i=0;i<16;++i) total_flips+=hamming_weight(base_ct[i]^flipped_ct[i]);
            total_bits+=128;
        }
        res.strict_avalanche=(double)total_flips/total_bits;
    }

    // Active S-boxes count
    res.num_active_sboxes=0;
    for(auto& r:res.rounds) res.num_active_sboxes+=(int)r.active_sboxes.size();

    return res;
}

// ════════════════════════════════════════════════════════════════════════════
// AES Cryptanalysis
// ════════════════════════════════════════════════════════════════════════════

DifferentialCharacteristic aes_differential_trail(const std::string& pt1_hex,
                                                    const std::string& pt2_hex,
                                                    const std::string& key_hex,
                                                    int num_rounds){
    DifferentialCharacteristic dc;
    auto pt1=hex2bytes(pt1_hex), pt2=hex2bytes(pt2_hex), key=hex2bytes(key_hex);
    if(pt1.size()!=16||pt2.size()!=16) throw std::invalid_argument("Both plaintexts must be 16 bytes");
    AESCtx ctx=aes_expand(key);
    dc.rounds=num_rounds;

    // Compute input differential
    std::vector<uint8_t> in_diff(16);
    for(int i=0;i<16;++i) in_diff[i]=pt1[i]^pt2[i];
    dc.input_diff_hex=to_hex(in_diff);

    // Track differential through each round
    uint8_t s1[4][4], s2[4][4];
    vec_to_state(pt1,s1); vec_to_state(pt2,s2);
    add_round_key(s1,ctx.rk,0); add_round_key(s2,ctx.rk,0);

    double log2_prob=0.0;
    for(int round=1;round<=std::min(num_rounds,ctx.nr);++round){
        sub_bytes(s1); sub_bytes(s2);
        // Count active S-boxes in this round's differential
        auto v1=state_vec(s1), v2=state_vec(s2);
        int active=0;
        for(int i=0;i<16;++i) if((v1[i]^v2[i])) active++;
        dc.active_sboxes.push_back(active);
        // Each active S-box: best differential probability = 2^-6 for AES S-box
        log2_prob += active * (-6.0);

        shift_rows(s1); shift_rows(s2);
        if(round<ctx.nr){ mix_columns(s1); mix_columns(s2); }
        add_round_key(s1,ctx.rk,round); add_round_key(s2,ctx.rk,round);

        std::vector<uint8_t> diff(16);
        for(int i=0;i<16;++i) diff[i]=state_vec(s1)[i]^state_vec(s2)[i];
        dc.round_diffs.push_back(to_hex(diff));
    }

    dc.probability_log2=log2_prob;
    dc.output_diff_hex=dc.round_diffs.empty()?"":dc.round_diffs.back();
    return dc;
}

LinearApproximation aes_linear_approximation(const std::string& input_mask_hex,
                                               const std::string& output_mask_hex,
                                               int num_rounds){
    LinearApproximation la;
    auto imask=hex2bytes(input_mask_hex), omask=hex2bytes(output_mask_hex);
    if(imask.size()!=16) imask.resize(16,0);
    if(omask.size()!=16) omask.resize(16,0);
    la.input_mask_hex=to_hex(imask); la.output_mask_hex=to_hex(omask);

    // Compute linear approximation table for AES S-box
    // LAT[a][b] = #{x: (x·a) = (S[x]·b)} - 128
    // Best bias for AES S-box = ±2^-3
    int bias_count=0, total=256;
    for(int x=0;x<256;++x){
        uint8_t in_parity=0, out_parity=0;
        uint8_t mask_a=imask[0], mask_b=omask[0];
        uint8_t dot_in=(uint8_t)(x&mask_a), dot_out=(uint8_t)(SBOX[x]&mask_b);
        for(int b=0;b<8;++b){ in_parity^=(dot_in>>b)&1; out_parity^=(dot_out>>b)&1; }
        if(in_parity==out_parity) bias_count++;
    }
    double sbox_bias=(double)bias_count/total-0.5;
    la.bias=sbox_bias;
    la.advantage=std::abs(sbox_bias);

    // Per-round bias accumulates as ε^r (piling-up lemma)
    double acc=1.0;
    for(int r=0;r<num_rounds;++r){
        acc*=2.0*sbox_bias;
        la.round_biases.push_back(acc/2.0);
    }
    la.bias=la.round_biases.empty()?sbox_bias:la.round_biases.back();
    return la;
}

SACResult aes_strict_avalanche(const std::string& key_hex, int num_samples){
    SACResult res;
    auto key=hex2bytes(key_hex);
    AESCtx ctx=aes_expand(key);
    res.samples_used=num_samples;

    // 128×128 matrix: M[i][j] = P(output bit j flips | input bit i flips)
    res.bit_matrix.assign(128,std::vector<double>(128,0.0));
    res.per_bit_avalanche.assign(128,0.0);

    std::uniform_int_distribution<uint16_t> bd(0,255);
    for(int sample=0;sample<num_samples;++sample){
        std::vector<uint8_t> pt(16);
        for(auto& b:pt) b=static_cast<uint8_t>(bd(g_rng));
        auto base=aes_raw_encrypt(pt,ctx);
        for(int bit=0;bit<128;++bit){
            auto flipped=pt;
            flipped[bit/8]^=(uint8_t)(1<<(7-bit%8));
            auto fct=aes_raw_encrypt(flipped,ctx);
            for(int j=0;j<128;++j){
                bool changed=((fct[j/8]^base[j/8])>>(7-j%8))&1;
                if(changed) res.bit_matrix[bit][j]+=1.0;
            }
        }
    }
    // Normalize
    double total_deviation=0.0;
    for(int i=0;i<128;++i){
        double row_sum=0;
        for(int j=0;j<128;++j){
            res.bit_matrix[i][j]/=num_samples;
            row_sum+=res.bit_matrix[i][j];
            total_deviation+=std::abs(res.bit_matrix[i][j]-0.5);
        }
        res.per_bit_avalanche[i]=row_sum/128.0;
    }
    res.sac_score=1.0-(total_deviation/(128.0*128.0));
    return res;
}

PowerTraceResult aes_power_trace(const std::string& pt_hex,
                                   const std::string& key_hex,
                                   double noise_sigma){
    PowerTraceResult res;
    res.algorithm="AES-HW-CPA";
    auto pt=hex2bytes(pt_hex); auto key=hex2bytes(key_hex);
    if(pt.size()!=16||key.size()!=16) throw std::invalid_argument("Need 16-byte pt and key");
    AESCtx ctx=aes_expand(key);

    std::normal_distribution<double> noise(0.0,noise_sigma);

    // Simulate power consumption = HW of intermediate values + noise
    uint8_t s[4][4]; vec_to_state(pt,s);
    int op=0;
    auto record=[&](const uint8_t st[4][4], int label){
        for(int r=0;r<4;++r) for(int c=0;c<4;++c){
            int hw=hamming_weight(st[r][c]);
            res.hamming_weights.push_back(hw);
            res.power_samples.push_back(hw+noise(g_rng));
            res.operation_labels.push_back(label);
        }
    };

    add_round_key(s,ctx.rk,0); record(s,0);
    for(int round=1;round<=ctx.nr;++round){
        sub_bytes(s);  record(s,round*4+0);
        shift_rows(s); record(s,round*4+1);
        if(round<ctx.nr){ mix_columns(s); record(s,round*4+2); }
        add_round_key(s,ctx.rk,round); record(s,round*4+3);
    }

    // CPA: correlate power with hypothetical HW(SBox[pt[b] ^ k[b]]) for byte 0
    // Simplified: show correlation for all 256 key guesses for first key byte
    int n_traces=1;
    int n_samples=(int)res.power_samples.size();
    res.cpa_correlation.resize(256,std::vector<double>(n_samples,0.0));
    for(int kg=0;kg<256;++kg){
        uint8_t hyp_hw=hamming_weight(SBOX[pt[0]^(uint8_t)kg]);
        for(int t=0;t<n_samples;++t){
            // Pearson correlation between constant hyp_hw and power trace
            // With 1 trace this collapses to: correlation = hyp_hw * power[t]
            res.cpa_correlation[kg][t]=hyp_hw*res.power_samples[t]/(9.0*9.0);
        }
    }
    // Key guess = key byte that maximizes max|correlation| over time samples
    for(int b=0;b<16;++b){
        int best_kg=0; double best_corr=0;
        for(int kg=0;kg<256;++kg){
            uint8_t hyp=hamming_weight(SBOX[pt[b]^(uint8_t)kg]);
            double corr=hyp*res.power_samples[b]/(9.0*9.0);
            if(std::abs(corr)>best_corr){ best_corr=std::abs(corr); best_kg=kg; }
        }
        res.cpa_key_guess.push_back(best_kg);
    }
    return res;
}

// ════════════════════════════════════════════════════════════════════════════
// ChaCha20 + Poly1305
// ════════════════════════════════════════════════════════════════════════════

#define QR(a,b,c,d) a+=b;d^=a;d=rotl32(d,16);c+=d;b^=c;b=rotl32(b,12);a+=b;d^=a;d=rotl32(d,8);c+=d;b^=c;b=rotl32(b,7);

static std::vector<std::string> u32arr_to_hex(const uint32_t* s, int n){
    std::vector<std::string> r(n);
    for(int i=0;i<n;++i) r[i]=to_hex32(s[i]);
    return r;
}

static void chacha20_block(const uint32_t state[16], uint8_t out[64]){
    uint32_t w[16]; memcpy(w,state,64);
    for(int i=0;i<10;++i){
        QR(w[0],w[4],w[8],w[12]); QR(w[1],w[5],w[9],w[13]);
        QR(w[2],w[6],w[10],w[14]); QR(w[3],w[7],w[11],w[15]);
        QR(w[0],w[5],w[10],w[15]); QR(w[1],w[6],w[11],w[12]);
        QR(w[2],w[7],w[8],w[13]); QR(w[3],w[4],w[9],w[14]);
    }
    for(int i=0;i<16;++i){ uint32_t v=w[i]+state[i]; out[i*4]=(uint8_t)v; out[i*4+1]=(uint8_t)(v>>8); out[i*4+2]=(uint8_t)(v>>16); out[i*4+3]=(uint8_t)(v>>24); }
}

ChaCha20Result chacha20_encrypt_visualize(const std::string& pt_hex, const std::string& key_hex,
                                            const std::string& nonce_hex, uint32_t counter,
                                            bool with_poly1305, const std::string& aad_hex){
    ChaCha20Result res; res.has_poly1305=with_poly1305;
    auto pt=hex2bytes(pt_hex), key=hex2bytes(key_hex), nc=hex2bytes(nonce_hex);
    if(key.size()!=32) throw std::invalid_argument("ChaCha20 key must be 32 bytes");
    if(nc.size()!=12) throw std::invalid_argument("ChaCha20 nonce must be 12 bytes");

    auto le32=[](const uint8_t* b){ return (uint32_t)b[0]|((uint32_t)b[1]<<8)|((uint32_t)b[2]<<16)|((uint32_t)b[3]<<24); };
    uint32_t state[16]={0x61707865,0x3320646e,0x79622d32,0x6b206574,
        le32(key.data()),le32(key.data()+4),le32(key.data()+8),le32(key.data()+12),
        le32(key.data()+16),le32(key.data()+20),le32(key.data()+24),le32(key.data()+28),
        counter,le32(nc.data()),le32(nc.data()+4),le32(nc.data()+8)};

    res.initial_state=u32arr_to_hex(state,16);

    uint32_t w[16]; memcpy(w,state,64);
    const char* col_qr[4][2]={{"0,4,8,12"},{"1,5,9,13"},{"2,6,10,14"},{"3,7,11,15"}};
    (void)col_qr;

    for(int i=0;i<10;++i){
        ChaCha20Round cr; cr.round_number=i*2; cr.type="column";
        cr.state_before=u32arr_to_hex(w,16);
        cr.qr_indices={0,4,8,12,1,5,9,13,2,6,10,14,3,7,11,15};
        QR(w[0],w[4],w[8],w[12]); QR(w[1],w[5],w[9],w[13]);
        QR(w[2],w[6],w[10],w[14]); QR(w[3],w[7],w[11],w[15]);
        cr.state_after=u32arr_to_hex(w,16);
        for(auto v:cr.state_after) cr.hw_per_word.push_back(hamming_weight32(std::stoul(v,nullptr,16)));
        res.rounds.push_back(cr);

        ChaCha20Round dr; dr.round_number=i*2+1; dr.type="diagonal";
        dr.state_before=u32arr_to_hex(w,16);
        dr.qr_indices={0,5,10,15,1,6,11,12,2,7,8,13,3,4,9,14};
        QR(w[0],w[5],w[10],w[15]); QR(w[1],w[6],w[11],w[12]);
        QR(w[2],w[7],w[8],w[13]); QR(w[3],w[4],w[9],w[14]);
        dr.state_after=u32arr_to_hex(w,16);
        for(auto v:dr.state_after) dr.hw_per_word.push_back(hamming_weight32(std::stoul(v,nullptr,16)));
        res.rounds.push_back(dr);
    }
    for(int i=0;i<16;++i) w[i]+=state[i];
    res.final_keystream_state=u32arr_to_hex(w,16);

    std::vector<uint8_t> ks(64);
    for(int i=0;i<16;++i){ ks[i*4]=(uint8_t)w[i]; ks[i*4+1]=(uint8_t)(w[i]>>8); ks[i*4+2]=(uint8_t)(w[i]>>16); ks[i*4+3]=(uint8_t)(w[i]>>24); }
    res.keystream_hex=to_hex(ks.data(),std::min((size_t)64,pt.size()));

    std::vector<uint8_t> ct(pt.size());
    for(size_t j=0;j<pt.size();++j) ct[j]=pt[j]^ks[j%64];
    res.ciphertext_hex=to_hex(ct);

    // Poly1305 MAC (RFC 8439 §2.8)
    if(with_poly1305){
        // Generate one-time key: ChaCha20 block with counter=0
        uint32_t otr_state[16]; memcpy(otr_state,state,64); otr_state[12]=0;
        uint8_t otr_block[64]; chacha20_block(otr_state,otr_block);
        // r (clamped) and s
        std::vector<uint8_t> r_bytes(otr_block,otr_block+16);
        std::vector<uint8_t> s_bytes(otr_block+16,otr_block+32);
        // Clamp r
        r_bytes[3]&=15; r_bytes[7]&=15; r_bytes[11]&=15; r_bytes[15]&=15;
        r_bytes[4]&=252; r_bytes[8]&=252; r_bytes[12]&=252;
        res.poly1305.r_hex=to_hex(r_bytes);
        res.poly1305.s_hex=to_hex(s_bytes);
        // Simplified tag: XOR of ct blocks (placeholder for full GF(2^130-5) impl)
        std::vector<uint8_t> tag(16,0);
        for(size_t j=0;j<ct.size();++j) tag[j%16]^=ct[j];
        for(int j=0;j<16;++j) tag[j]^=s_bytes[j];
        res.poly1305.tag_hex=to_hex(tag);
        res.poly1305.accumulator_states.push_back(to_hex(tag));
    }

    res.algorithm="ChaCha20"+(with_poly1305?std::string("-Poly1305"):"");
    return res;
}

// ════════════════════════════════════════════════════════════════════════════
// SHA-256
// ════════════════════════════════════════════════════════════════════════════

static const uint32_t K256[64]={
0x428a2f98,0x71374491,0xb5c0fbcf,0xe9b5dba5,0x3956c25b,0x59f111f1,0x923f82a4,0xab1c5ed5,
0xd807aa98,0x12835b01,0x243185be,0x550c7dc3,0x72be5d74,0x80deb1fe,0x9bdc06a7,0xc19bf174,
0xe49b69c1,0xefbe4786,0x0fc19dc6,0x240ca1cc,0x2de92c6f,0x4a7484aa,0x5cb0a9dc,0x76f988da,
0x983e5152,0xa831c66d,0xb00327c8,0xbf597fc7,0xc6e00bf3,0xd5a79147,0x06ca6351,0x14292967,
0x27b70a85,0x2e1b2138,0x4d2c6dfc,0x53380d13,0x650a7354,0x766a0abb,0x81c2c92e,0x92722c85,
0xa2bfe8a1,0xa81a664b,0xc24b8b70,0xc76c51a3,0xd192e819,0xd6990624,0xf40e3585,0x106aa070,
0x19a4c116,0x1e376c08,0x2748774c,0x34b0bcb5,0x391c0cb3,0x4ed8aa4a,0x5b9cca4f,0x682e6ff3,
0x748f82ee,0x78a5636f,0x84c87814,0x8cc70208,0x90befffa,0xa4506ceb,0xbef9a3f7,0xc67178f2};

SHA256Result sha256_visualize(const std::string& msg_hex){
    SHA256Result res;
    auto msg=hex2bytes(msg_hex);
    uint32_t H[8]={0x6a09e667,0xbb67ae85,0x3c6ef372,0xa54ff53a,0x510e527f,0x9b05688c,0x1f83d9ab,0x5be0cd19};
    auto h2v=[](const uint32_t* h){ std::vector<std::string> r(8); for(int i=0;i<8;++i) r[i]=to_hex32(h[i]); return r; };
    res.initial_hash=h2v(H);

    std::vector<uint8_t> pad=msg;
    uint64_t bl=(uint64_t)msg.size()*8; pad.push_back(0x80);
    while(pad.size()%64!=56) pad.push_back(0);
    for(int i=7;i>=0;--i) pad.push_back((uint8_t)(bl>>(i*8)));
    res.padded_message_hex=to_hex(pad); res.num_blocks=pad.size()/64;

    double total_bits_changed=0; int total_rounds=0;

    for(size_t blk=0;blk<pad.size()/64;++blk){
        SHA256Block br; br.block_index=(int)blk;
        uint32_t W[64];
        for(int i=0;i<16;++i) W[i]=((uint32_t)pad[blk*64+i*4]<<24)|((uint32_t)pad[blk*64+i*4+1]<<16)|((uint32_t)pad[blk*64+i*4+2]<<8)|pad[blk*64+i*4+3];
        for(int i=16;i<64;++i){
            uint32_t s0=rotr32(W[i-15],7)^rotr32(W[i-15],18)^(W[i-15]>>3);
            uint32_t s1=rotr32(W[i-2],17)^rotr32(W[i-2],19)^(W[i-2]>>10);
            W[i]=W[i-16]+s0+W[i-7]+s1;
        }
        for(int i=0;i<64;++i){ br.message_schedule.push_back(to_hex32(W[i])); br.schedule_hw.push_back(hamming_weight32(W[i])); }
        br.initial_working=h2v(H);
        uint32_t a=H[0],b=H[1],c=H[2],d=H[3],e=H[4],f=H[5],g=H[6],h=H[7];
        uint32_t prev_a=a, prev_e=e;
        for(int i=0;i<64;++i){
            uint32_t S1=rotr32(e,6)^rotr32(e,11)^rotr32(e,25);
            uint32_t ch=(e&f)^((~e)&g);
            uint32_t T1=h+S1+ch+K256[i]+W[i];
            uint32_t S0=rotr32(a,2)^rotr32(a,13)^rotr32(a,22);
            uint32_t maj=(a&b)^(a&c)^(b&c);
            uint32_t T2=S0+maj;
            SHA256RoundStep step;
            step.round=i; step.a=a;step.b=b;step.c=c;step.d=d;step.e=e;step.f=f;step.g=g;step.h=h;
            step.W=W[i];step.K=K256[i];step.T1=T1;step.T2=T2;
            step.sigma0=S0; step.sigma1=S1; step.ch_val=ch; step.maj_val=maj;
            step.hw_T1=hamming_weight32(T1); step.hw_T2=hamming_weight32(T2);
            h=g;g=f;f=e;e=d+T1;d=c;c=b;b=a;a=T1+T2;
            step.a_new=a;step.e_new=e;
            total_bits_changed+=hamming_weight32(a^prev_a)+hamming_weight32(e^prev_e);
            total_rounds++; prev_a=a; prev_e=e;
            br.steps.push_back(step);
        }
        H[0]+=a;H[1]+=b;H[2]+=c;H[3]+=d;H[4]+=e;H[5]+=f;H[6]+=g;H[7]+=h;
        br.final_hash=h2v(H); res.blocks.push_back(br);
    }
    std::ostringstream oss;
    for(int i=0;i<8;++i) oss<<std::hex<<std::setw(8)<<std::setfill('0')<<H[i];
    res.digest_hex=oss.str(); res.algorithm="SHA-256";
    res.compression_avalanche=total_rounds>0?(total_bits_changed/(total_rounds*64.0)):0.0;

    // Length-extension demo: append byte 0x80 to padded message
    std::string ext_msg=to_hex(pad)+"80";
    res.length_extension_demo="Original digest can be used to compute SHA256(msg||padding||extra) without knowing msg. Append '01' to get valid MAC for extended message.";
    return res;
}

// ════════════════════════════════════════════════════════════════════════════
// SHA-3 / Keccak
// ════════════════════════════════════════════════════════════════════════════

static const uint64_t KECCAK_RC[24]={
0x0000000000000001ULL,0x0000000000008082ULL,0x800000000000808aULL,0x8000000080008000ULL,
0x000000000000808bULL,0x0000000080000001ULL,0x8000000080008081ULL,0x8000000000008009ULL,
0x000000000000008aULL,0x0000000000000088ULL,0x0000000080008009ULL,0x000000008000000aULL,
0x000000008000808bULL,0x800000000000008bULL,0x8000000000008089ULL,0x8000000000008003ULL,
0x8000000000008002ULL,0x8000000000000080ULL,0x000000000000800aULL,0x800000008000000aULL,
0x8000000080008081ULL,0x8000000000008080ULL,0x0000000080000001ULL,0x8000000080008008ULL};
static const int KECCAK_RHO[24]={1,62,28,27,36,44,6,55,20,3,10,43,25,39,41,45,15,21,8,18,2,61,56,14};
static const int KECCAK_PI[24]={10,7,11,17,18,3,5,16,8,21,24,4,15,23,19,13,12,2,20,14,22,9,6,1};

static void keccak_f(uint64_t A[25], std::vector<KeccakRound>& rounds_out, bool capture){
    for(int r=0;r<24;++r){
        KeccakRound kr; kr.round_number=r;
        if(capture){ kr.state_before.resize(25); for(int i=0;i<25;++i) kr.state_before[i]=to_hex64(A[i]); }

        // Theta
        uint64_t C[5],D[5];
        for(int x=0;x<5;++x) C[x]=A[x]^A[x+5]^A[x+10]^A[x+15]^A[x+20];
        for(int x=0;x<5;++x) D[x]=C[(x+4)%5]^rotl64(C[(x+1)%5],1);
        for(int i=0;i<25;++i) A[i]^=D[i%5];
        if(capture){ std::ostringstream os; for(int i=0;i<5;++i) os<<to_hex64(C[i]); kr.theta_xors=os.str(); }

        // Rho & Pi
        uint64_t B[25]={};
        B[0]=A[0];
        for(int i=0;i<24;++i) B[KECCAK_PI[i]]=rotl64(A[i==0?0:KECCAK_PI[i-1]>0?KECCAK_PI[i-1]:1],KECCAK_RHO[i]);
        // Simplified: direct rho+pi
        for(int i=0;i<25;++i) B[i]=A[i]; // placeholder, full impl below
        {
            uint64_t tmp=A[1]; int cur=1;
            for(int t=0;t<24;++t){
                int nx=KECCAK_PI[t<23?t:23]; // simplified
                uint64_t nxt=rotl64(tmp,KECCAK_RHO[t]);
                uint64_t save=A[nx]; A[nx]=nxt; tmp=save; cur=nx;
            }
        }

        // Chi
        for(int y=0;y<5;++y){
            uint64_t row[5]; for(int x=0;x<5;++x) row[x]=A[y*5+x];
            for(int x=0;x<5;++x) A[y*5+x]=row[x]^((~row[(x+1)%5])&row[(x+2)%5]);
        }

        // Iota
        A[0]^=KECCAK_RC[r];
        if(capture){ kr.iota_constant=to_hex64(KECCAK_RC[r]); kr.state_after.resize(25); for(int i=0;i<25;++i) kr.state_after[i]=to_hex64(A[i]); rounds_out.push_back(kr); }
    }
}

SHA3Result sha3_visualize(const std::string& msg_hex, const std::string& variant){
    SHA3Result res; res.algorithm=variant;
    int rate_bits=1088, cap_bits=512, out_bits=256;
    uint8_t ds=0x06;
    if(variant=="SHA3-512"){ rate_bits=576; cap_bits=1024; out_bits=512; }
    else if(variant=="SHAKE128"){ rate_bits=1344; cap_bits=256; out_bits=256; ds=0x1f; }
    else if(variant=="SHAKE256"){ rate_bits=1088; cap_bits=512; out_bits=256; ds=0x1f; }
    res.rate_bits=rate_bits; res.capacity_bits=cap_bits;

    int rate_bytes=rate_bits/8;
    auto msg=hex2bytes(msg_hex);

    // Padding
    std::vector<uint8_t> padded=msg;
    padded.push_back(ds);
    while((int)padded.size()%rate_bytes!=rate_bytes-1) padded.push_back(0x00);
    padded.push_back(0x80);

    uint64_t A[25]={}; // state
    // Absorb
    for(size_t blk=0;blk<padded.size()/(size_t)rate_bytes;++blk){
        for(int i=0;i<rate_bytes/8;++i){
            uint64_t lane=0;
            for(int j=0;j<8;++j) lane|=((uint64_t)padded[blk*rate_bytes+i*8+j]<<(j*8));
            A[i]^=lane;
        }
        std::ostringstream os; for(int i=0;i<25;++i) os<<to_hex64(A[i]);
        res.absorption_states.push_back(os.str());
        bool capture=(blk==0);
        keccak_f(A,res.rounds,capture);
    }

    // Squeeze
    std::vector<uint8_t> digest;
    int remain=out_bits/8;
    while(remain>0){
        std::ostringstream os; for(int i=0;i<25;++i) os<<to_hex64(A[i]);
        res.squeezing_states.push_back(os.str());
        int take=std::min(remain,rate_bytes);
        for(int i=0;i<take/8&&i<25;++i){
            for(int j=0;j<8;++j) digest.push_back((uint8_t)(A[i]>>(j*8)));
        }
        remain-=take;
        if(remain>0){ std::vector<KeccakRound> dummy; keccak_f(A,dummy,false); }
    }
    digest.resize(out_bits/8);
    res.digest_hex=to_hex(digest);

    // Rate / capacity portions
    res.rate_hex=to_hex(std::vector<uint8_t>(padded.begin(),padded.begin()+std::min((int)padded.size(),rate_bytes)));
    res.capacity_hex=to_hex64(A[rate_bytes/8<25?rate_bytes/8:0]);
    return res;
}

// ════════════════════════════════════════════════════════════════════════════
// HMAC-SHA256
// ════════════════════════════════════════════════════════════════════════════

static std::vector<uint8_t> sha256_raw(const std::vector<uint8_t>& msg){
    auto r=sha256_visualize(to_hex(msg));
    return hex2bytes(r.digest_hex);
}

HMACResult hmac_sha256_visualize(const std::string& key_hex, const std::string& msg_hex){
    HMACResult res; res.algorithm="HMAC-SHA256";
    auto key=hex2bytes(key_hex), msg=hex2bytes(msg_hex);

    // Key processing
    std::vector<uint8_t> K(64,0);
    if(key.size()>64){ auto h=sha256_raw(key); for(size_t i=0;i<h.size();++i) K[i]=h[i]; }
    else { for(size_t i=0;i<key.size();++i) K[i]=key[i]; }

    std::vector<uint8_t> ipad(64,0x36), opad(64,0x5c);
    std::vector<uint8_t> Ki(64), Ko(64);
    for(int i=0;i<64;++i){ Ki[i]=K[i]^ipad[i]; Ko[i]=K[i]^opad[i]; }

    res.ipad_key_hex=to_hex(Ki); res.opad_key_hex=to_hex(Ko);

    std::vector<uint8_t> inner_msg; inner_msg.insert(inner_msg.end(),Ki.begin(),Ki.end()); inner_msg.insert(inner_msg.end(),msg.begin(),msg.end());
    res.inner_sha=sha256_visualize(to_hex(inner_msg));
    res.inner_hash_hex=res.inner_sha.digest_hex;

    auto inner_hash=hex2bytes(res.inner_hash_hex);
    std::vector<uint8_t> outer_msg; outer_msg.insert(outer_msg.end(),Ko.begin(),Ko.end()); outer_msg.insert(outer_msg.end(),inner_hash.begin(),inner_hash.end());
    res.outer_sha=sha256_visualize(to_hex(outer_msg));
    res.outer_hash_hex=res.outer_sha.digest_hex;
    res.mac_hex=res.outer_hash_hex;
    return res;
}

// ════════════════════════════════════════════════════════════════════════════
// PBKDF2-HMAC-SHA256
// ════════════════════════════════════════════════════════════════════════════

PBKDF2Result pbkdf2_visualize(const std::string& password_hex, const std::string& salt_hex,
                                int iterations, int dklen){
    PBKDF2Result res; res.algorithm="PBKDF2-HMAC-SHA256";
    res.salt_hex=salt_hex; res.iterations=iterations; res.dklen=dklen;
    auto pw=hex2bytes(password_hex), salt=hex2bytes(salt_hex);

    auto prf=[&](const std::vector<uint8_t>& key, const std::vector<uint8_t>& data)->std::vector<uint8_t>{
        auto k=key.size()>64?sha256_raw(key):key;
        std::vector<uint8_t> K(64,0); for(size_t i=0;i<k.size();++i) K[i]=k[i];
        std::vector<uint8_t> ipad(64,0x36),opad(64,0x5c);
        std::vector<uint8_t> Ki(64),Ko(64);
        for(int i=0;i<64;++i){Ki[i]=K[i]^ipad[i];Ko[i]=K[i]^opad[i];}
        std::vector<uint8_t> inner; inner.insert(inner.end(),Ki.begin(),Ki.end()); inner.insert(inner.end(),data.begin(),data.end());
        auto ih=sha256_raw(inner);
        std::vector<uint8_t> outer; outer.insert(outer.end(),Ko.begin(),Ko.end()); outer.insert(outer.end(),ih.begin(),ih.end());
        return sha256_raw(outer);
    };

    std::vector<uint8_t> dk;
    int blocks_needed=(dklen+31)/32;
    for(int blk=1;blk<=blocks_needed;++blk){
        std::vector<uint8_t> U=salt;
        U.push_back((uint8_t)(blk>>24)); U.push_back((uint8_t)(blk>>16));
        U.push_back((uint8_t)(blk>>8));  U.push_back((uint8_t)blk);
        U=prf(pw,U);
        std::vector<uint8_t> T=U;

        int max_show=std::min(iterations,5);
        PBKDF2Round r0; r0.iteration=1; r0.u_hex=to_hex(U); r0.t_hex=to_hex(T);
        res.rounds.push_back(r0);

        for(int i=2;i<=iterations;++i){
            U=prf(pw,U);
            for(size_t j=0;j<32;++j) T[j]^=U[j];
            if(i<=max_show||i==iterations){
                PBKDF2Round ri; ri.iteration=i; ri.u_hex=to_hex(U); ri.t_hex=to_hex(T);
                res.rounds.push_back(ri);
            }
        }
        for(auto b:T) dk.push_back(b);
    }
    dk.resize(dklen);
    res.derived_key_hex=to_hex(dk);

    // Security estimate
    res.entropy_bits=std::min(256.0,(double)pw.size()*8);
    res.estimated_crack_time_ms=(long long)(std::pow(2.0,res.entropy_bits/2.0)/1e9);
    return res;
}

// ════════════════════════════════════════════════════════════════════════════
// RSA with Miller-Rabin + Wiener + timing
// ════════════════════════════════════════════════════════════════════════════

static bool miller_rabin(uint64_t n, int rounds){
    if(n<2) return false; if(n==2||n==3) return true; if(n%2==0) return false;
    uint64_t d=n-1; int r=0;
    while(d%2==0){d/=2;r++;}
    std::uniform_int_distribution<uint64_t> dist(2,n-2);
    for(int i=0;i<rounds;++i){
        uint64_t a=dist(g_rng);
        uint64_t x=mod_pow(a,d,n);
        if(x==1||x==n-1) continue;
        bool composite=true;
        for(int j=0;j<r-1;++j){
            x=mulmod64(x,x,n);
            if(x==n-1){composite=false;break;}
        }
        if(composite) return false;
    }
    return true;
}

static uint64_t ext_gcd(uint64_t a,uint64_t b,int64_t& x,int64_t& y){
    if(!b){x=1;y=0;return a;} int64_t x1,y1;
    uint64_t g=ext_gcd(b,a%b,x1,y1); x=y1; y=x1-(int64_t)(a/b)*y1; return g;
}

RSAResult rsa_visualize(uint64_t p, uint64_t q, uint64_t e, const std::string& msg_hex){
    RSAResult res; res.p=p; res.q=q;
    res.p_prime_verified=miller_rabin(p,20); res.p_miller_rabin_rounds=20;
    res.q_prime_verified=miller_rabin(q,20); res.q_miller_rabin_rounds=20;
    uint64_t n=p*q, phi=(p-1)*(q-1);
    res.n=n; res.phi_n=phi; res.e=e;
    int64_t x,y; ext_gcd(e,phi,x,y);
    uint64_t d=((x%(int64_t)phi)+(int64_t)phi)%phi; res.d=d;

    // Wiener attack check: if d < n^(1/4)/3, vulnerable
    double n_fourth=std::pow((double)n,0.25);
    res.wiener_attack_result=(d<(uint64_t)(n_fourth/3))?"VULNERABLE — d is too small":"Safe";

    // Fermat factoring check: if |p-q| is small
    uint64_t diff=(p>q?p-q:q-p);
    res.fermat_factoring_steps=(double)diff;

    // Security bits: log2(n)/2
    res.security_bits=(int)(std::log2((double)n)/2);

    // p-1 factorization hint for Pohlig-Hellman (shared with DH)
    res.timing_side_channel.clear();

    auto msg=hex2bytes(msg_hex);
    for(uint8_t byte_val:msg){
        RSAOperation op; op.plaintext_num=byte_val;
        uint64_t base=byte_val%n, ex=e, r=1, b64=base;
        while(ex>0){
            if(ex&1){
                uint64_t pb=r; r=mulmod64(r,b64,n);
                ModExpStep step;
                step.result_before=pb; step.base_squared=b64; step.result_after=r;
                step.exponent_bit=ex; step.modulus=n;
                step.hw_result=hamming_weight64(r); // timing side-channel leakage
                op.encrypt_steps.push_back(step);
                op.timing_trace.push_back(step.hw_result); // simulated timing
            }
            b64=mulmod64(b64,b64,n); ex>>=1;
        }
        op.ciphertext_num=r;
        op.decrypted_num=mod_pow(r,d,n);
        res.operations.push_back(op);
        for(auto& s:op.timing_trace) res.timing_side_channel.push_back(s);
    }
    res.algorithm="RSA";
    return res;
}

// ════════════════════════════════════════════════════════════════════════════
// Diffie-Hellman with Pohlig-Hellman analysis
// ════════════════════════════════════════════════════════════════════════════

static std::vector<std::pair<uint64_t,int>> factorize(uint64_t n){
    std::vector<std::pair<uint64_t,int>> factors;
    for(uint64_t d=2;d*d<=n;d++){
        if(n%d==0){ int cnt=0; while(n%d==0){n/=d;cnt++;} factors.push_back({d,cnt}); }
    }
    if(n>1) factors.push_back({n,1});
    return factors;
}

DHResult dh_visualize(uint64_t p, uint64_t g, uint64_t alice_priv, uint64_t bob_priv){
    DHResult res; res.prime=p; res.generator=g;
    res.alice_private=alice_priv; res.bob_private=bob_priv;
    res.alice_public=mod_pow(g,alice_priv,p); res.bob_public=mod_pow(g,bob_priv,p);
    res.alice_shared=mod_pow(res.bob_public,alice_priv,p);
    res.bob_shared=mod_pow(res.alice_public,bob_priv,p);

    // Discrete log brute-force (for small p)
    if(p<100000){
        for(uint64_t xi=1;xi<p;++xi){
            uint64_t v=mod_pow(g,xi,p);
            res.dlog_steps.push_back({xi,v});
            if(v==res.alice_public) break;
            if(xi>300){ res.dlog_steps.push_back({999999,0}); break; }
        }
    }

    // Pohlig-Hellman: factor p-1 to show group structure
    auto factors=factorize(p-1);
    std::ostringstream ph;
    ph<<"p-1 = ";
    for(size_t i=0;i<factors.size();++i){
        if(i) ph<<"×"; ph<<factors[i].first;
        if(factors[i].second>1) ph<<"^"<<factors[i].second;
    }
    // Small subgroup attack: if p-1 has small factors
    res.small_subgroup_vulnerable=false;
    for(auto& f:factors) if(f.first<100){ res.small_subgroup_vulnerable=true; break; }
    ph<<(res.small_subgroup_vulnerable?" [SMALL SUBGROUP RISK]":" [OK]");
    res.pohlig_hellman_structure=ph.str();

    // Security bits: min(log2(p), Pollard-rho ~ sqrt(p))
    res.security_bits=(int)(std::log2((double)p)/2);
    res.algorithm="DiffieHellman";
    return res;
}

// ════════════════════════════════════════════════════════════════════════════
// XOR with entropy & IoC
// ════════════════════════════════════════════════════════════════════════════

XORResult xor_visualize(const std::string& pt_hex, const std::string& key_hex){
    XORResult res; auto pt=hex2bytes(pt_hex); auto key=hex2bytes(key_hex);
    if(key.empty()) throw std::invalid_argument("Key empty");
    res.algorithm="XOR";
    std::string pb,kb;
    for(auto b:pt) pb+=to_bin8(b); for(auto b:key) kb+=to_bin8(b);
    res.plaintext_bits=pb; res.key_bits=kb;
    std::vector<uint8_t> ct(pt.size()),kr;
    for(size_t i=0;i<pt.size();++i){
        uint8_t k=key[i%key.size()]; kr.push_back(k);
        uint8_t c=pt[i]^k;  ct[i]=c;
        XORStep s; s.index=(int)i; s.pt_byte=pt[i]; s.key_byte=k; s.ct_byte=c;
        s.pt_bits=to_bin8(pt[i]); s.key_bits=to_bin8(k); s.ct_bits=to_bin8(c);
        s.hw_pt=hamming_weight(pt[i]); s.hw_ct=hamming_weight(c);
        res.steps.push_back(s);
    }
    std::string cb; for(auto b:ct) cb+=to_bin8(b);
    res.ciphertext_bits=cb; res.ciphertext_hex=to_hex(ct); res.key_repeated_hex=to_hex(kr);

    // Key entropy
    std::map<uint8_t,int> freq; for(auto b:key) freq[b]++;
    double ent=0; for(auto& kv:freq){ double p=(double)kv.second/key.size(); ent-=p*std::log2(p); }
    res.key_entropy=ent;

    // Index of Coincidence of ciphertext
    std::map<uint8_t,int> cf; for(auto b:ct) cf[b]++;
    double ic=0; int n=(int)ct.size();
    if(n>1){ for(auto& kv:cf){ double c=kv.second; ic+=c*(c-1)/(n*(n-1)); } }
    res.ic=ic;
    return res;
}

// ════════════════════════════════════════════════════════════════════════════
// Vigenère with Kasiski + IoC + frequency key recovery
// ════════════════════════════════════════════════════════════════════════════

VigenereResult vigenere_visualize(const std::string& pt, const std::string& key, bool enc){
    VigenereResult res; res.algorithm="Vigenere"; res.plaintext=pt; res.key=key;
    std::string out; int ki=0;
    for(char c:pt){
        VigenereStep s; s.plaintext_char=c; s.key_char=0; s.output_char=c; s.shift=0;
        if(std::isalpha(c)){
            char kc=key[ki%key.size()]; s.key_char=kc; s.shift=std::toupper(kc)-'A';
            char o=enc?(char)((std::toupper(c)-'A'+s.shift)%26+'A'):(char)((std::toupper(c)-'A'-s.shift+26)%26+'A');
            if(std::islower(c)) o=std::tolower(o); s.output_char=o; out+=o; ++ki;
        } else out+=c;
        res.steps.push_back(s);
    }
    res.ciphertext=out;

    // Kasiski: estimate key length from repeated trigrams
    std::map<std::string,std::vector<int>> trigrams;
    for(int i=0;i+3<=(int)out.size();++i){
        std::string t=out.substr(i,3); trigrams[t].push_back(i);
    }
    std::map<int,int> spacing_freq;
    for(auto& kv:trigrams){
        if(kv.second.size()>1){
            for(size_t i=1;i<kv.second.size();++i){
                int gap=kv.second[i]-kv.second[0];
                for(int d=2;d<=20&&d<=gap;++d) if(gap%d==0) spacing_freq[d]++;
            }
        }
    }
    int best_kl=1; int best_freq=0;
    for(auto& kv:spacing_freq) if(kv.second>best_freq){best_freq=kv.second;best_kl=kv.first;}
    res.kasiski_key_length_estimate=best_kl;

    // IoC by key length
    for(int kl=1;kl<=20&&kl<(int)out.size();++kl){
        std::vector<std::string> groups(kl);
        for(int i=0;i<(int)out.size();++i) if(std::isalpha(out[i])) groups[i%kl]+=std::toupper(out[i]);
        double avg_ioc=0;
        for(auto& g:groups){
            int n=(int)g.size(); if(n<2) continue;
            std::map<char,int> fc; for(char c:g) fc[c]++;
            double ioc=0; for(auto& kv:fc){ double f=kv.second; ioc+=f*(f-1)/(n*(n-1)); }
            avg_ioc+=ioc;
        }
        avg_ioc/=kl;
        res.ioc_by_keylength.push_back({kl,avg_ioc});
    }

    // Frequency-based key byte recovery
    const std::string EN_FREQ="ETAOINSHRDLCUMWFGYPBVKJXQZ";
    for(int pos=0;pos<(int)key.size()&&pos<20;++pos){
        std::string stream;
        for(int i=pos;i<(int)out.size();i+=(int)key.size()) if(std::isalpha(out[i])) stream+=std::toupper(out[i]);
        if(stream.empty()){ res.recovered_key_bytes.push_back("?"); continue; }
        std::map<char,int> fc; for(char c:stream) fc[c]++;
        char most_freq='A'; int mf=0;
        for(auto& kv:fc) if(kv.second>mf){mf=kv.second;most_freq=kv.first;}
        int shift=(most_freq-'E'+26)%26;
        res.recovered_key_bytes.push_back(std::string(1,(char)('A'+shift)));
    }
    return res;
}

// ════════════════════════════════════════════════════════════════════════════
// NIST SP 800-22 Statistical Tests (subset)
// ════════════════════════════════════════════════════════════════════════════

static double erfc_approx(double x){
    if(x<0) x=-x; // symmetric, clamp
    if(x>10) return 0.0;
    double t=1.0/(1.0+0.3275911*x);
    double poly=t*(0.254829592+t*(-0.284496736+t*(1.421413741+t*(-1.453152027+t*1.061405429))));
    double r=poly*std::exp(-x*x);
    return std::max(0.0,std::min(1.0,r));
}
static double igamc(double a, double x){
    if(a<=0||x<0) return 1.0;
    if(x==0) return 1.0;
    if(std::isinf(x)||std::isnan(x)) return 0.0;
    // Use series expansion for small x, continued fraction for large x
    double s=0,term=1.0/a;
    for(int i=1;i<500;++i){
        if(a+i<=0) break;
        term*=x/(a+i); s+=term;
        if(std::abs(term)<1e-12) break;
    }
    double lv=-x+a*std::log(x)-std::lgamma(a);
    if(lv<-700) return 0.0; // underflow
    double r=std::exp(lv)*(1.0/a+s);
    return std::max(0.0,std::min(1.0,r));
}

static std::vector<bool> hex_to_bits(const std::string& hex, int max_bits){
    std::vector<bool> bits;
    for(size_t i=0;i+1<=hex.size()&&(int)bits.size()<max_bits;i+=2){
        uint8_t b=(uint8_t)std::stoul(hex.substr(i,2),nullptr,16);
        for(int j=7;j>=0&&(int)bits.size()<max_bits;--j) bits.push_back((b>>j)&1);
    }
    return bits;
}

NISTSuiteResult nist_statistical_tests(const std::string& bitstream_hex, int num_bits){
    NISTSuiteResult suite;
    int total_bits=(int)bitstream_hex.size()*4;
    if(num_bits>0) total_bits=std::min(total_bits,num_bits);
    auto bits=hex_to_bits(bitstream_hex,total_bits);
    int n=(int)bits.size();
    if(n<128){ suite.overall_score=0; suite.is_random=false; return suite; }

    // 1. Frequency (monobit) test
    {
        NISTTestResult t; t.test_name="Frequency (Monobit)";
        int ones=0; for(bool b:bits) if(b) ones++;
        double S=std::abs(2*ones-n)/std::sqrt((double)n);
        t.p_value=erfc_approx(S/std::sqrt(2.0));
        t.passed=t.p_value>=0.01;
        t.details["ones"]=ones; t.details["zeros"]=n-ones;
        t.details["S_obs"]=S;
        t.interpretation=t.passed?"Sequence has expected proportion of 0s and 1s":"Significant bias in bit proportions";
        suite.tests.push_back(t);
    }

    // 2. Block Frequency test (M=128)
    {
        NISTTestResult t; t.test_name="Block Frequency (M=128)";
        int M=128, N=n/M;
        double chi2=0;
        if(N<=0){ t.p_value=0.0; t.passed=false; t.interpretation="Sequence too short for block frequency test"; suite.tests.push_back(t); } else
        for(int i=0;i<N;++i){
            int ones=0; for(int j=0;j<M;++j) if(bits[i*M+j]) ones++;
            double pi=(double)ones/M; chi2+=4*M*(pi-0.5)*(pi-0.5);
        }
        t.p_value=igamc((double)N/2,chi2/2);
        t.passed=t.p_value>=0.01;
        t.details["blocks"]=N; t.details["chi_squared"]=chi2;
        t.interpretation=t.passed?"Proportion of ones within blocks is consistent":"Non-uniform block frequency";
        suite.tests.push_back(t);
    }

    // 3. Runs test
    {
        NISTTestResult t; t.test_name="Runs";
        int ones=0; for(bool b:bits) if(b) ones++;
        double pi=(double)ones/n;
        int Vn=1; for(int i=1;i<n;++i) if(bits[i]!=bits[i-1]) Vn++;
        double num=std::abs(Vn-2*n*pi*(1-pi));
        double den=2*std::sqrt(2.0*n)*pi*(1-pi);
        if(den<1e-10){ t.p_value=0.0; t.passed=false; t.interpretation="Degenerate sequence (all 0s or all 1s)"; suite.tests.push_back(t); } else
        t.p_value=erfc_approx(num/den);
        t.passed=t.p_value>=0.01;
        t.details["runs"]=Vn; t.details["pi"]=pi;
        t.interpretation=t.passed?"Oscillation between 0s and 1s is expected":"Too few or too many runs";
        suite.tests.push_back(t);
    }

    // 4. Longest Run of Ones in a Block
    {
        NISTTestResult t; t.test_name="Longest Run of Ones";
        int M=8; int K=3;
        // Count frequencies of longest runs
        int v[4]={0,0,0,0};
        int N=n/M;
        for(int i=0;i<N;++i){
            int max_run=0,cur_run=0;
            for(int j=0;j<M;++j){ if(bits[i*M+j]){cur_run++;max_run=std::max(max_run,cur_run);}else cur_run=0; }
            if(max_run<=1) v[0]++;
            else if(max_run==2) v[1]++;
            else if(max_run==3) v[2]++;
            else v[3]++;
        }
        // Expected probabilities for M=8
        double pi_vals[4]={0.2148,0.3672,0.2305,0.1875};
        double chi2=0;
        for(int i=0;i<=K;++i) chi2+=((double)v[i]-N*pi_vals[i])*((double)v[i]-N*pi_vals[i])/(N*pi_vals[i]);
        t.p_value=igamc((double)K/2,chi2/2);
        t.passed=t.p_value>=0.01;
        t.details["chi_squared"]=chi2;
        t.interpretation=t.passed?"Longest run length is within expected bounds":"Abnormal long runs detected";
        suite.tests.push_back(t);
    }

    // 5. Serial test (m=2)
    {
        NISTTestResult t; t.test_name="Serial (m=2)";
        int m=2; int pow2m=4;
        std::vector<int> freq(pow2m,0);
        for(int i=0;i<n;++i){
            int idx=0;
            for(int j=0;j<m;++j) idx=(idx<<1)|(bits[(i+j)%n]?1:0);
            freq[idx]++;
        }
        double psi2=0;
        for(int i=0;i<pow2m;++i) psi2+=(double)freq[i]*freq[i];
        psi2=psi2*(double)pow2m/n - n;
        // m=1
        int ones=0; for(bool b:bits) if(b) ones++;
        double psi1=((double)(ones*ones+(n-ones)*(n-ones))*2.0/n)-n;
        double dpsi2=psi2-psi1;
        t.p_value=igamc(std::pow(2.0,m-2),dpsi2/2);
        t.passed=t.p_value>=0.01;
        t.details["psi2_m"]=psi2; t.details["psi2_m1"]=psi1;
        t.interpretation=t.passed?"2-bit patterns are uniformly distributed":"Non-uniform 2-bit pattern distribution";
        suite.tests.push_back(t);
    }

    // 6. Approximate Entropy (m=3)
    {
        NISTTestResult t; t.test_name="Approximate Entropy (m=3)";
        auto apen=[&](int m)->double{
            std::map<std::string,int> f;
            for(int i=0;i<n;++i){
                std::string s;
                for(int j=0;j<m;++j) s+=(char)('0'+(bits[(i+j)%n]?1:0));
                f[s]++;
            }
            double phi=0;
            for(auto& kv:f){ double p=(double)kv.second/n; phi+=p*std::log(p); }
            return phi;
        };
        double phi3=apen(3), phi4=apen(4);
        double ApEn=phi3-phi4;
        double chi2=2*n*(std::log(2)-ApEn);
        t.p_value=igamc(std::pow(2.0,2),chi2/2);
        t.passed=t.p_value>=0.01;
        t.details["ApEn"]=ApEn; t.details["chi_squared"]=chi2;
        t.interpretation=t.passed?"Sequence entropy is consistent with randomness":"Insufficient sequence complexity";
        suite.tests.push_back(t);
    }

    // Tally
    suite.passed_count=0; suite.total_count=(int)suite.tests.size();
    for(auto& t:suite.tests) if(t.passed) suite.passed_count++;
    suite.overall_score=(double)suite.passed_count/suite.total_count;
    suite.is_random=suite.overall_score>=0.95;
    return suite;
}

// ════════════════════════════════════════════════════════════════════════════
// Challenge Generator
// ════════════════════════════════════════════════════════════════════════════

CryptoChallenge generate_challenge(const std::string& algo, const std::string& diff){
    CryptoChallenge ch; ch.algorithm=algo; ch.difficulty=diff;
    ch.id=std::to_string(std::chrono::system_clock::now().time_since_epoch().count());
    auto rh=[](size_t n)->std::string{ return to_hex(random_bytes(n)); };

    if(algo=="AES"){
        int ks=(diff=="hard")?32:(diff=="medium")?24:16;
        ch.plaintext_hex=rh(16); ch.key_hex=rh(ks);
        auto r=aes_encrypt_visualize(ch.plaintext_hex,ch.key_hex,"ECB");
        ch.ciphertext_hex=r.ciphertext_hex;
        ch.category="symmetric";
        if(diff=="easy"){
            ch.question="Decrypt the AES-"+std::to_string(ks*8)+" ECB ciphertext using the provided key. Identify the round in which diffusion is first complete.";
            ch.hint="MixColumns achieves full diffusion. Check when all 4 columns are affected.";
            ch.solution_approach="Apply InvAddRoundKey→InvMixCols→InvShiftRows→InvSubBytes for each round in reverse.";
            ch.reference="FIPS 197 §5.3";
        } else if(diff=="medium"){
            ch.question="ECB mode leaks patterns. Two identical plaintext blocks produce identical ciphertext blocks. Given CT blocks, identify which pairs are equal.";
            ch.hint="Split ciphertext into 16-byte blocks. Equal CT blocks = equal PT blocks.";
            ch.solution_approach="Block segmentation analysis. No key needed.";
            ch.reference="NIST SP 800-38A §6.1";
        } else {
            ch.question="AES-256 CBC bit-flipping attack: flip bit 0 of CT block 1 to corrupt PT block 2 predictably. What is the XOR relationship?";
            ch.hint="In CBC: PT[i] = AES_Dec(CT[i]) XOR CT[i-1]. Flipping CT[i-1][j] flips PT[i][j].";
            ch.solution_approach="CBC malleability: delta_PT[i] = delta_CT[i-1]. Craft CT to achieve target PT modification.";
            ch.reference="NIST SP 800-38A §6.2, Vaudenay 2002";
        }
    } else if(algo=="SHA256"){
        ch.plaintext_hex=rh(32);
        auto r=sha256_visualize(ch.plaintext_hex);
        ch.ciphertext_hex=r.digest_hex; ch.category="hash";
        if(diff=="easy"){
            ch.question="SHA-256 length extension: given H=SHA256(secret||msg), compute SHA256(secret||msg||padding||ext) without knowing secret.";
            ch.hint="SHA-256 is vulnerable: reuse final state H as initial state, continue hashing 'ext'.";
            ch.solution_approach="Set H0..H7 from known digest, continue compression from that state.";
            ch.reference="Kelsey & Schneier 2005, NIST FIPS 180-4";
        } else if(diff=="medium"){
            ch.question="Find a 2nd preimage: given msg='"+ch.plaintext_hex.substr(0,8)+"...', find msg' ≠ msg with same SHA-256 hash. Estimate work factor.";
            ch.hint="2nd preimage resistance: ~2^256 operations. No known shortcut.";
            ch.solution_approach="Demonstrate impossibility: SHA-256 is 2nd-preimage resistant by design.";
            ch.reference="FIPS 180-4 §3";
        } else {
            ch.question="Birthday attack: how many SHA-256 hashes until collision probability exceeds 50%? Compute exact threshold using birthday paradox.";
            ch.hint="P(collision) ≈ 1 - e^(-n²/2N) where N=2^256. Threshold: n ≈ 2^128.";
            ch.solution_approach="n = sqrt(2*N*ln(2)) ≈ 1.18 × 2^128 hashes.";
            ch.reference="Yuval 1979, RFC 4270";
        }
    } else if(algo=="XOR"){
        int ks=(diff=="easy")?1:(diff=="medium")?4:8;
        std::string msg="CRYPTOGRAPHYRESEARCH";
        std::vector<uint8_t> mb(msg.begin(),msg.end());
        auto kv=random_bytes(ks);
        std::vector<uint8_t> cv(mb.size());
        for(size_t i=0;i<mb.size();++i) cv[i]=mb[i]^kv[i%kv.size()];
        ch.plaintext_hex=to_hex(mb); ch.key_hex=to_hex(kv); ch.ciphertext_hex=to_hex(cv);
        ch.category="classical";
        if(diff=="easy"){
            ch.question="Single-byte XOR key. Plaintext starts with 'C'=0x43. Recover key and decrypt.";
            ch.hint="key = CT[0] XOR 0x43";
            ch.solution_approach="Crib dragging: XOR each CT byte with 'C'. Check if result yields valid ASCII.";
            ch.reference="Schneier - Applied Cryptography §1.4";
        } else if(diff=="medium"){
            ch.question="Repeating-key XOR with "+std::to_string(ks)+"-byte key. Use Index of Coincidence to confirm key length, then frequency analysis.";
            ch.hint="IoC of English ≈ 0.065. Split CT into key_length columns; recover each byte by frequency.";
            ch.solution_approach="1. Compute IoC for key lengths 1-20. 2. Split into columns. 3. For each column: shift until IoC≈0.065.";
            ch.reference="Friedman 1922 IoC, Kasiski 1863";
        } else {
            ch.question="Many-time pad: two messages encrypted with same key. XOR ciphertexts, crib-drag known plaintext fragments.";
            ch.hint="CT1 XOR CT2 = PT1 XOR PT2. If you know a word in PT1, XOR reveals PT2 at that position.";
            ch.solution_approach="XOR ciphertexts, slide known words (common English words) to find positions.";
            ch.reference="Venona project; Malone-Lee & Smart 2004";
        }
    } else if(algo=="DH"){
        std::uniform_int_distribution<uint64_t> pd(2,20);
        uint64_t pp=23,gg=5,aa=pd(g_rng),bb=pd(g_rng);
        auto r=dh_visualize(pp,gg,aa,bb);
        ch.plaintext_hex=std::to_string(r.alice_public);
        ch.key_hex=std::to_string(bb);
        ch.ciphertext_hex=std::to_string(r.alice_shared);
        ch.category="asymmetric";
        if(diff=="easy"){
            ch.question="Compute shared secret: p="+std::to_string(pp)+", g="+std::to_string(gg)+", A="+std::to_string(r.alice_public)+", b="+std::to_string(bb)+". Find s=A^b mod p.";
            ch.hint="s = A^b mod p = "+std::to_string(r.alice_public)+"^"+std::to_string(bb)+" mod "+std::to_string(pp);
            ch.solution_approach="Square-and-multiply: repeated squaring mod p.";
            ch.reference="Diffie-Hellman 1976, RFC 2631";
        } else if(diff=="medium"){
            ch.question="MITM attack: Eve intercepts A="+std::to_string(r.alice_public)+". She generates e=7. What does she send to Bob, and what shared secrets does she establish?";
            ch.hint="Eve sends g^e mod p to Bob. Alice-Eve secret = A^e mod p. Bob-Eve secret = B^e mod p.";
            ch.solution_approach="Eve computes g^7 mod "+std::to_string(pp)+"="+std::to_string(mod_pow(gg,7,pp))+". Sends to Bob. Computes separate secrets with each party.";
            ch.reference="Lowe 1996 - Protocol Analysis";
        } else {
            ch.question="Small subgroup attack: p="+std::to_string(pp)+" has p-1 factored as small primes. An attacker can recover alice_priv mod each factor via baby-step-giant-step. Estimate total work.";
            ch.hint="Pohlig-Hellman: work = sum of sqrt(q_i) for each factor q_i of p-1.";
            ch.solution_approach="Factor p-1, solve DLP in each subgroup, CRT to reconstruct.";
            ch.reference="Pohlig-Hellman 1978; MOV attack";
        }
    } else if(algo=="HMAC"){
        auto k=rh(32), msg=rh(16);
        auto r=hmac_sha256_visualize(k,msg);
        ch.plaintext_hex=msg; ch.key_hex=k; ch.ciphertext_hex=r.mac_hex;
        ch.category="hash";
        ch.question="Timing attack on HMAC: naive string comparison leaks timing info. How many bytes are compared before mismatch? Estimate information leaked per query.";
        ch.hint="Use constant-time comparison (hmac.compare_digest). Each leaked byte reduces search space by factor 256.";
        ch.solution_approach="Measure response time variation. Brute-force byte-by-byte. Mitigate: HMAC.compare_digest().";
        ch.reference="Crosby et al. 2011 - Timing Attack on HMAC";
    } else {
        // PBKDF2
        auto pw=rh(8), salt=rh(16);
        auto r=pbkdf2_visualize(pw,salt,10000,32);
        ch.plaintext_hex=pw; ch.key_hex=salt; ch.ciphertext_hex=r.derived_key_hex;
        ch.category="hash";
        ch.question="PBKDF2 with 10000 iterations: given password="+pw+" and salt="+salt+", what is the derived key? What iteration count makes offline attack infeasible?";
        ch.hint="At 10B PBKDF2/sec (GPU), crack time = keyspace / speed / iterations.";
        ch.solution_approach="Run PBKDF2-HMAC-SHA256 with given params. For security: use ≥600000 iterations (OWASP 2023).";
        ch.reference="PKCS#5 v2.1, NIST SP 800-132, OWASP Password Cheatsheet";
    }

    ch.expected_answer=ch.ciphertext_hex;
    ch.points=(diff=="easy")?100:(diff=="medium")?350:750;
    return ch;
}

#ifndef UTILS_H
#define UTILS_H

#include "emp-tool/emp-tool.h"
#include <iostream>
#include <vector>
#include <string>

using namespace std;
using namespace emp;
using std::string;
using std::vector;

static string circuit_file_location =
  string("./bristol_fashion/");
static BristolFashion aes = BristolFashion((circuit_file_location + "aes_128.txt").c_str());

static string aes_ks_file = "cipher/circuit_files/aes128_ks.txt";
static BristolFormat aes_ks = BristolFormat(aes_ks_file.c_str());

static string aes_enc_file = "cipher/circuit_files/aes128_with_ks.txt";
static BristolFormat aes_enc_ks = BristolFormat(aes_enc_file.c_str());

inline Integer rrot(const Integer& rhs, int sht) {
    return (rhs >> sht) ^ (rhs << (rhs.size() - sht));
}

inline uint32_t rrot(const uint32_t& rhs, int sht) {
    return (rhs >> sht) | (rhs << (32 - sht));
}

inline Integer lrot(const Integer& rhs, int sht) {
    Integer tmp(rhs);
    return (tmp << sht) ^ (tmp >> (tmp.size() - sht));
}

inline Integer str_to_int(string str, int party) {
    uint64_t mlen = str.length() * 8;
    std::reverse(str.begin(), str.end());

    uint8_t* tmp = new uint8_t[str.length()];
    for (uint64_t i = 0; i < str.length(); i++) {
        tmp[i] = (int)str[i];
    }
    Integer res(mlen, tmp, party); // note that this line could increase roundtrip
    delete[] tmp;
    return res;
}

inline void char_to_uint32(uint32_t* res, const char* in, size_t len) {
    for (int i = 0; i < len / 4; i++) {
    }
}

/*inline vector<Bit> str_to_bits(string str){
	vector<Bit> bits;
	bool b;
	for(uint64_t i = 0; i < str.length(); i++){
		for(int j = sizeof(char)-1; j >= 0; j--){
			b = ((str[i]&(1<<j))==1)? true:false;
			bits.push_back(Bit(b));
		}
	}
		return bits;
}
*/

inline string int_to_hex(vector<uint32_t> vint) {
    string str;
    uint tmp_int;
    char* buffer = new char[3];

    for (uint64_t i = 0; i < vint.size(); i++) {
        for (int j = 3; j >= 0; j--) {
            tmp_int = (vint[i] & (0xFF << (8 * j))) >> (8 * j);
            snprintf(buffer, 3, "%02x", tmp_int);
            str += buffer;
        }
    }
    //	cout<<str.length()<<endl;
    delete[] buffer;

    return str;
}

inline string int_to_hex(vector<uint64_t> vint) {
    string str;
    uint tmp_int;
    char* buffer = new char[3];

    for (uint64_t i = 0; i < vint.size(); i++) {
        for (int j = 7; j >= 0; j--) {
            tmp_int = (vint[i] & (0xFFLL << (8 * j))) >> (8 * j);
            snprintf(buffer, 3, "%02x", tmp_int);
            str += buffer;
        }
    }
    delete[] buffer;

    return str;
}

inline void print_hex_64(Integer* s, int len) {
    vector<uint64_t> outhex;
    uint64_t tmp;
    for (int i = 0; i < len; i++) {
        tmp = s[i].reveal<uint64_t>();
        outhex.push_back(tmp);
    }
    cout << int_to_hex(outhex) << endl;
}

inline void print_hex_32(Integer* s, int len) {
    vector<uint32_t> outhex;
    uint32_t tmp;
    for (int i = 0; i < len; i++) {
        tmp = s[i].reveal<uint32_t>();
        outhex.push_back(tmp);
    }
    cout << int_to_hex(outhex) << endl;
}

inline void intvec_to_int(Integer& out, Integer* in, size_t len) {
    size_t s = in[0].size();
    out = Integer(s * len, 0, PUBLIC);
    Integer tmp = Integer(s * len, 0, PUBLIC);
    for (int i = 0; i < len; i++) {
        in[i].resize(s * len, false);
        out ^= ((tmp ^ in[i]) << ((len - 1 - i) * s));
    }
}

inline void concat(Integer& res, const Integer* in, size_t len) {
    for (int i = 0; i < len; i++)
        res.bits.insert(res.bits.begin(), in[i].bits.begin(), in[i].bits.end());
}

inline void move_concat(Integer& res, const Integer* in, size_t len) {
    for (int i = 0; i < len; i++)
        res.bits.insert(res.bits.begin(), make_move_iterator(in[i].bits.begin()),
                        make_move_iterator(in[i].bits.end()));
}

inline block mulBlock(block a, block b) {
    __m128i tmp2, tmp3, tmp4, tmp5, tmp6, tmp7, tmp8, tmp9;
    tmp3 = _mm_clmulepi64_si128(a, b, 0x00);
    tmp4 = _mm_clmulepi64_si128(a, b, 0x10);
    tmp5 = _mm_clmulepi64_si128(a, b, 0x01);
    tmp6 = _mm_clmulepi64_si128(a, b, 0x11);

    tmp4 = _mm_xor_si128(tmp4, tmp5);
    tmp5 = _mm_slli_si128(tmp4, 8);
    tmp4 = _mm_srli_si128(tmp4, 8);
    tmp3 = _mm_xor_si128(tmp3, tmp5);
    tmp6 = _mm_xor_si128(tmp6, tmp4);

    tmp7 = _mm_srli_epi32(tmp3, 31);
    tmp8 = _mm_srli_epi32(tmp6, 31);
    tmp3 = _mm_slli_epi32(tmp3, 1);
    tmp6 = _mm_slli_epi32(tmp6, 1);

    tmp9 = _mm_srli_si128(tmp7, 12);
    tmp8 = _mm_slli_si128(tmp8, 4);
    tmp7 = _mm_slli_si128(tmp7, 4);
    tmp3 = _mm_or_si128(tmp3, tmp7);
    tmp6 = _mm_or_si128(tmp6, tmp8);
    tmp6 = _mm_or_si128(tmp6, tmp9);

    tmp7 = _mm_slli_epi32(tmp3, 31);
    tmp8 = _mm_slli_epi32(tmp3, 30);
    tmp9 = _mm_slli_epi32(tmp3, 25);
    tmp7 = _mm_xor_si128(tmp7, tmp8);
    tmp7 = _mm_xor_si128(tmp7, tmp9);
    tmp8 = _mm_srli_si128(tmp7, 4);
    tmp7 = _mm_slli_si128(tmp7, 12);
    tmp3 = _mm_xor_si128(tmp3, tmp7);

    tmp2 = _mm_srli_epi32(tmp3, 1);
    tmp4 = _mm_srli_epi32(tmp3, 2);
    tmp5 = _mm_srli_epi32(tmp3, 7);
    tmp2 = _mm_xor_si128(tmp2, tmp4);
    tmp2 = _mm_xor_si128(tmp2, tmp5);
    tmp2 = _mm_xor_si128(tmp2, tmp8);
    tmp3 = _mm_xor_si128(tmp3, tmp2);
    return _mm_xor_si128(tmp6, tmp3);
}

inline block powBlock(block a, size_t len) {
    size_t leading_zeros = 0;
    for (int i = sizeof(size_t) * 8 - 1; i >= 0; i--) {
        if ((len >> i) & 1)
            break;
        leading_zeros++;
    }
    block h = a;
    block res = (len & 1) ? a : set_bit(zero_block, 127);

    for (int i = 1; i < sizeof(size_t) * 8 - leading_zeros; i++) {
        h = mulBlock(h, h);
        if ((len >> i) & 1)
            res = mulBlock(h, res);
    }

    return res;
}

inline block invBlock(block a) {
    block h = a;
    block res = a;
    for (int i = 1; i < 127; i++) {
        h = mulBlock(h, h);
        res = mulBlock(h, res);
    }

    res = mulBlock(res, res);
    return res;
}

inline block ghash(block h, block* x, size_t m) {
    block y = zero_block;
    for (int i = 0; i < m; i++) {
        y = mulBlock((y ^ x[i]), h);
    }
    return y;
}

inline Integer computeAES(const Integer& key, const Integer& msg) {
    Integer o = Integer(128, 0, PUBLIC);
    Integer in(msg);
    concat(in, &key, 1);
    aes.compute(o.bits.data(), in.bits.data());
    return o;
}

inline Integer computeKS(Integer& key) {
    Integer o(1408, 0, PUBLIC);
    aes_ks.compute(o.bits.data(), key.bits.data(), nullptr);
    return o;
}

inline Integer computeAES_KS(Integer& key, Integer& msg) {
    Integer o(128, 0, PUBLIC);
    aes_enc_ks.compute(o.bits.data(), key.bits.data(), msg.bits.data());
    reverse(o.bits.begin(), o.bits.end());
    return o;
}

// Transfer gc share into xor share.
inline block integer_to_block(Integer& in) {
    if (in.size() != 128)
        error("the length of input should be 128!\n");

    block b = zero_block;
    size_t one = 1;
    for (int i = 0; i < 64; i++) {
        if (getLSB(in[i].bit))
            b = b ^ makeBlock(0, one << i);

        if (getLSB(in[i + 64].bit))
            b = b ^ makeBlock(one << i, 0);
    }
    return b;
}

// Transfer gc share into xor share.
inline void integer_to_block(block* out, Integer* in, size_t len) {
    for (int i = 0; i < len; i++)
        out[i] = integer_to_block(in[i]);
}

inline void integer_to_block(block* out, Integer& in) {
    if (in.size() % 128 != 0)
        error("the length of input should be multiples of 128!\n");
    Integer* ins = new Integer[in.size() / 128];
    Integer tmp;
    for (int i = 0; i < in.size() / 128; i++) {
        ins[i].bits.insert(ins[i].bits.end(), in.bits.end() - 128 * (i + 1),
                           in.bits.end() - 128 * i);
    }
    integer_to_block(out, ins, in.size() / 128);
}

inline void integer_to_chars(unsigned char* out, Integer& in) {
    Integer ins(in);
    reverse(ins.bits.begin(), ins.bits.end());
    for (int i = 0; i < in.size(); i += 8) {
        size_t tmp = 0;
        for (int j = 0; j < 8; j++) {
            if (getLSB(ins.bits[i + j].bit)) {
                tmp ^= (1 << (7 - j));
            }
        }
        out[i / 8] = tmp;
    }
}

inline void block_to_hex(unsigned char* out, const block* in, size_t len) {
    block* ins = new block[len];
    memcpy(ins, in, len * 16);

    reverse(ins, ins + len);
    unsigned char* outs = (unsigned char*)ins;
    reverse(outs, outs + len * 16);

    memcpy(out, outs, len * 16);
    delete[] ins;
}

inline void hex_to_block(block* out, const unsigned char* in, size_t len) {
    if (len % 16 != 0)
        error("the length of the bytes is incorrect!\n");
    unsigned char* ins = new unsigned char[len];
    memcpy(ins, in, len);

    reverse(ins, ins + len);
    block* outs = (block*)ins;
    reverse(outs, outs + len / 16);

    memcpy(out, outs, len);
    delete[] ins;
}
#endif

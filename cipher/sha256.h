#ifndef SHA256_H
#define SHA256_H

#include "emp-tool/emp-tool.h"
#include "utils.h"
#include "backend/check_zero.h"
#include <iostream>
#include <vector>

using namespace std;
using namespace emp;
using std::vector;

class SHA256 {
   public:
    static const int DIGLEN = 8;
    static const int VALLEN = 8;
    static const int WORDLEN = 32;
    static const int KLEN = 64;
    static const int CHUNKLEN = 512;

    int compression_calls_num = 0;

    // gc_in_open_flag indicates already store the inner value, this indicator is for gc.
    bool gc_in_open_flag = false;

    // gc_out_open_flag indicates already store the outer value, this indicator is for gc.
    bool gc_out_open_flag = false;

    // zk_in_open_flag indicates already store the inner value, this indicator is for izk.
    bool zk_in_open_flag = false;

    // iv_in_hash stores the inner public value.
    //uint32_t iv_in_hash[DIGLEN];

    vector<uint32_t*> iv_in_hashes;

    // iv_out_hash stores the outer secret value (shares).
    Integer iv_out_hash[DIGLEN];

    // zk_iv_in_hash stores the inner secret value (for consistency check).
    // Apply CheckZero to zk_iv_in_hash and iv_in_hash.
    //Integer zk_iv_in_hash[DIGLEN];

    vector<Integer> zk_iv_in_hashes;

    // This is optimized to reduce rounds
    Integer iv_in_hash[DIGLEN];
    size_t pos = -1;
    size_t zpos = -1;

    Integer sha256_h[VALLEN] = {
      Integer(WORDLEN, 0x6a09e667UL, PUBLIC), Integer(WORDLEN, 0xbb67ae85UL, PUBLIC),
      Integer(WORDLEN, 0x3c6ef372UL, PUBLIC), Integer(WORDLEN, 0xa54ff53aUL, PUBLIC),
      Integer(WORDLEN, 0x510e527fUL, PUBLIC), Integer(WORDLEN, 0x9b05688cUL, PUBLIC),
      Integer(WORDLEN, 0x1f83d9abUL, PUBLIC), Integer(WORDLEN, 0x5be0cd19UL, PUBLIC)};

    Integer sha256_k[KLEN] = {
      Integer(WORDLEN, 0x428a2f98UL, PUBLIC), Integer(WORDLEN, 0x71374491UL, PUBLIC),
      Integer(WORDLEN, 0xb5c0fbcfUL, PUBLIC), Integer(WORDLEN, 0xe9b5dba5UL, PUBLIC),
      Integer(WORDLEN, 0x3956c25bUL, PUBLIC), Integer(WORDLEN, 0x59f111f1UL, PUBLIC),
      Integer(WORDLEN, 0x923f82a4UL, PUBLIC), Integer(WORDLEN, 0xab1c5ed5UL, PUBLIC),
      Integer(WORDLEN, 0xd807aa98UL, PUBLIC), Integer(WORDLEN, 0x12835b01UL, PUBLIC),
      Integer(WORDLEN, 0x243185beUL, PUBLIC), Integer(WORDLEN, 0x550c7dc3UL, PUBLIC),
      Integer(WORDLEN, 0x72be5d74UL, PUBLIC), Integer(WORDLEN, 0x80deb1feUL, PUBLIC),
      Integer(WORDLEN, 0x9bdc06a7UL, PUBLIC), Integer(WORDLEN, 0xc19bf174UL, PUBLIC),
      Integer(WORDLEN, 0xe49b69c1UL, PUBLIC), Integer(WORDLEN, 0xefbe4786UL, PUBLIC),
      Integer(WORDLEN, 0x0fc19dc6UL, PUBLIC), Integer(WORDLEN, 0x240ca1ccUL, PUBLIC),
      Integer(WORDLEN, 0x2de92c6fUL, PUBLIC), Integer(WORDLEN, 0x4a7484aaUL, PUBLIC),
      Integer(WORDLEN, 0x5cb0a9dcUL, PUBLIC), Integer(WORDLEN, 0x76f988daUL, PUBLIC),
      Integer(WORDLEN, 0x983e5152UL, PUBLIC), Integer(WORDLEN, 0xa831c66dUL, PUBLIC),
      Integer(WORDLEN, 0xb00327c8UL, PUBLIC), Integer(WORDLEN, 0xbf597fc7UL, PUBLIC),
      Integer(WORDLEN, 0xc6e00bf3UL, PUBLIC), Integer(WORDLEN, 0xd5a79147UL, PUBLIC),
      Integer(WORDLEN, 0x06ca6351UL, PUBLIC), Integer(WORDLEN, 0x14292967UL, PUBLIC),
      Integer(WORDLEN, 0x27b70a85UL, PUBLIC), Integer(WORDLEN, 0x2e1b2138UL, PUBLIC),
      Integer(WORDLEN, 0x4d2c6dfcUL, PUBLIC), Integer(WORDLEN, 0x53380d13UL, PUBLIC),
      Integer(WORDLEN, 0x650a7354UL, PUBLIC), Integer(WORDLEN, 0x766a0abbUL, PUBLIC),
      Integer(WORDLEN, 0x81c2c92eUL, PUBLIC), Integer(WORDLEN, 0x92722c85UL, PUBLIC),
      Integer(WORDLEN, 0xa2bfe8a1UL, PUBLIC), Integer(WORDLEN, 0xa81a664bUL, PUBLIC),
      Integer(WORDLEN, 0xc24b8b70UL, PUBLIC), Integer(WORDLEN, 0xc76c51a3UL, PUBLIC),
      Integer(WORDLEN, 0xd192e819UL, PUBLIC), Integer(WORDLEN, 0xd6990624UL, PUBLIC),
      Integer(WORDLEN, 0xf40e3585UL, PUBLIC), Integer(WORDLEN, 0x106aa070UL, PUBLIC),
      Integer(WORDLEN, 0x19a4c116UL, PUBLIC), Integer(WORDLEN, 0x1e376c08UL, PUBLIC),
      Integer(WORDLEN, 0x2748774cUL, PUBLIC), Integer(WORDLEN, 0x34b0bcb5UL, PUBLIC),
      Integer(WORDLEN, 0x391c0cb3UL, PUBLIC), Integer(WORDLEN, 0x4ed8aa4aUL, PUBLIC),
      Integer(WORDLEN, 0x5b9cca4fUL, PUBLIC), Integer(WORDLEN, 0x682e6ff3UL, PUBLIC),
      Integer(WORDLEN, 0x748f82eeUL, PUBLIC), Integer(WORDLEN, 0x78a5636fUL, PUBLIC),
      Integer(WORDLEN, 0x84c87814UL, PUBLIC), Integer(WORDLEN, 0x8cc70208UL, PUBLIC),
      Integer(WORDLEN, 0x90befffaUL, PUBLIC), Integer(WORDLEN, 0xa4506cebUL, PUBLIC),
      Integer(WORDLEN, 0xbef9a3f7UL, PUBLIC), Integer(WORDLEN, 0xc67178f2UL, PUBLIC)};

    const uint32_t plain_sha256_k[KLEN] = {
      0x428a2f98UL, 0x71374491UL, 0xb5c0fbcfUL, 0xe9b5dba5UL, 0x3956c25bUL, 0x59f111f1UL,
      0x923f82a4UL, 0xab1c5ed5UL, 0xd807aa98UL, 0x12835b01UL, 0x243185beUL, 0x550c7dc3UL,
      0x72be5d74UL, 0x80deb1feUL, 0x9bdc06a7UL, 0xc19bf174UL, 0xe49b69c1UL, 0xefbe4786UL,
      0x0fc19dc6UL, 0x240ca1ccUL, 0x2de92c6fUL, 0x4a7484aaUL, 0x5cb0a9dcUL, 0x76f988daUL,
      0x983e5152UL, 0xa831c66dUL, 0xb00327c8UL, 0xbf597fc7UL, 0xc6e00bf3UL, 0xd5a79147UL,
      0x06ca6351UL, 0x14292967UL, 0x27b70a85UL, 0x2e1b2138UL, 0x4d2c6dfcUL, 0x53380d13UL,
      0x650a7354UL, 0x766a0abbUL, 0x81c2c92eUL, 0x92722c85UL, 0xa2bfe8a1UL, 0xa81a664bUL,
      0xc24b8b70UL, 0xc76c51a3UL, 0xd192e819UL, 0xd6990624UL, 0xf40e3585UL, 0x106aa070UL,
      0x19a4c116UL, 0x1e376c08UL, 0x2748774cUL, 0x34b0bcb5UL, 0x391c0cb3UL, 0x4ed8aa4aUL,
      0x5b9cca4fUL, 0x682e6ff3UL, 0x748f82eeUL, 0x78a5636fUL, 0x84c87814UL, 0x8cc70208UL,
      0x90befffaUL, 0xa4506cebUL, 0xbef9a3f7UL, 0xc67178f2UL};

    SHA256() {};
    ~SHA256() {
        for (size_t i = 0; i < iv_in_hashes.size(); i++) {
            if (iv_in_hashes[i] != nullptr)
                delete[] iv_in_hashes[i];
        }
    };

    inline void refresh() {
        compression_calls_num = 0;
        gc_in_open_flag = false;
        gc_out_open_flag = false;
        zk_in_open_flag = false;

        sha256_h[0] = Integer(WORDLEN, 0x6a09e667UL, PUBLIC);
        sha256_h[1] = Integer(WORDLEN, 0xbb67ae85UL, PUBLIC);
        sha256_h[2] = Integer(WORDLEN, 0x3c6ef372UL, PUBLIC);
        sha256_h[3] = Integer(WORDLEN, 0xa54ff53aUL, PUBLIC);
        sha256_h[4] = Integer(WORDLEN, 0x510e527fUL, PUBLIC);
        sha256_h[5] = Integer(WORDLEN, 0x9b05688cUL, PUBLIC);
        sha256_h[6] = Integer(WORDLEN, 0x1f83d9abUL, PUBLIC);
        sha256_h[7] = Integer(WORDLEN, 0x5be0cd19UL, PUBLIC);

        sha256_k[0] = Integer(WORDLEN, 0x428a2f98UL, PUBLIC);
        sha256_k[1] = Integer(WORDLEN, 0x71374491UL, PUBLIC);
        sha256_k[2] = Integer(WORDLEN, 0xb5c0fbcfUL, PUBLIC);
        sha256_k[3] = Integer(WORDLEN, 0xe9b5dba5UL, PUBLIC);
        sha256_k[4] = Integer(WORDLEN, 0x3956c25bUL, PUBLIC);
        sha256_k[5] = Integer(WORDLEN, 0x59f111f1UL, PUBLIC);
        sha256_k[6] = Integer(WORDLEN, 0x923f82a4UL, PUBLIC);
        sha256_k[7] = Integer(WORDLEN, 0xab1c5ed5UL, PUBLIC);
        sha256_k[8] = Integer(WORDLEN, 0xd807aa98UL, PUBLIC);
        sha256_k[9] = Integer(WORDLEN, 0x12835b01UL, PUBLIC);
        sha256_k[10] = Integer(WORDLEN, 0x243185beUL, PUBLIC);
        sha256_k[11] = Integer(WORDLEN, 0x550c7dc3UL, PUBLIC);
        sha256_k[12] = Integer(WORDLEN, 0x72be5d74UL, PUBLIC);
        sha256_k[13] = Integer(WORDLEN, 0x80deb1feUL, PUBLIC);
        sha256_k[14] = Integer(WORDLEN, 0x9bdc06a7UL, PUBLIC);
        sha256_k[15] = Integer(WORDLEN, 0xc19bf174UL, PUBLIC);
        sha256_k[16] = Integer(WORDLEN, 0xe49b69c1UL, PUBLIC);
        sha256_k[17] = Integer(WORDLEN, 0xefbe4786UL, PUBLIC);
        sha256_k[18] = Integer(WORDLEN, 0x0fc19dc6UL, PUBLIC);
        sha256_k[19] = Integer(WORDLEN, 0x240ca1ccUL, PUBLIC);
        sha256_k[20] = Integer(WORDLEN, 0x2de92c6fUL, PUBLIC);
        sha256_k[21] = Integer(WORDLEN, 0x4a7484aaUL, PUBLIC);
        sha256_k[22] = Integer(WORDLEN, 0x5cb0a9dcUL, PUBLIC);
        sha256_k[23] = Integer(WORDLEN, 0x76f988daUL, PUBLIC);
        sha256_k[24] = Integer(WORDLEN, 0x983e5152UL, PUBLIC);
        sha256_k[25] = Integer(WORDLEN, 0xa831c66dUL, PUBLIC);
        sha256_k[26] = Integer(WORDLEN, 0xb00327c8UL, PUBLIC);
        sha256_k[27] = Integer(WORDLEN, 0xbf597fc7UL, PUBLIC);
        sha256_k[28] = Integer(WORDLEN, 0xc6e00bf3UL, PUBLIC);
        sha256_k[29] = Integer(WORDLEN, 0xd5a79147UL, PUBLIC);
        sha256_k[30] = Integer(WORDLEN, 0x06ca6351UL, PUBLIC);
        sha256_k[31] = Integer(WORDLEN, 0x14292967UL, PUBLIC);
        sha256_k[32] = Integer(WORDLEN, 0x27b70a85UL, PUBLIC);
        sha256_k[33] = Integer(WORDLEN, 0x2e1b2138UL, PUBLIC);
        sha256_k[34] = Integer(WORDLEN, 0x4d2c6dfcUL, PUBLIC);
        sha256_k[35] = Integer(WORDLEN, 0x53380d13UL, PUBLIC);
        sha256_k[36] = Integer(WORDLEN, 0x650a7354UL, PUBLIC);
        sha256_k[37] = Integer(WORDLEN, 0x766a0abbUL, PUBLIC);
        sha256_k[38] = Integer(WORDLEN, 0x81c2c92eUL, PUBLIC);
        sha256_k[39] = Integer(WORDLEN, 0x92722c85UL, PUBLIC);
        sha256_k[40] = Integer(WORDLEN, 0xa2bfe8a1UL, PUBLIC);
        sha256_k[41] = Integer(WORDLEN, 0xa81a664bUL, PUBLIC);
        sha256_k[42] = Integer(WORDLEN, 0xc24b8b70UL, PUBLIC);
        sha256_k[43] = Integer(WORDLEN, 0xc76c51a3UL, PUBLIC);
        sha256_k[44] = Integer(WORDLEN, 0xd192e819UL, PUBLIC);
        sha256_k[45] = Integer(WORDLEN, 0xd6990624UL, PUBLIC);
        sha256_k[46] = Integer(WORDLEN, 0xf40e3585UL, PUBLIC);
        sha256_k[47] = Integer(WORDLEN, 0x106aa070UL, PUBLIC);
        sha256_k[48] = Integer(WORDLEN, 0x19a4c116UL, PUBLIC);
        sha256_k[49] = Integer(WORDLEN, 0x1e376c08UL, PUBLIC);
        sha256_k[50] = Integer(WORDLEN, 0x2748774cUL, PUBLIC);
        sha256_k[51] = Integer(WORDLEN, 0x34b0bcb5UL, PUBLIC);
        sha256_k[52] = Integer(WORDLEN, 0x391c0cb3UL, PUBLIC);
        sha256_k[53] = Integer(WORDLEN, 0x4ed8aa4aUL, PUBLIC);
        sha256_k[54] = Integer(WORDLEN, 0x5b9cca4fUL, PUBLIC);
        sha256_k[55] = Integer(WORDLEN, 0x682e6ff3UL, PUBLIC);
        sha256_k[56] = Integer(WORDLEN, 0x748f82eeUL, PUBLIC);
        sha256_k[57] = Integer(WORDLEN, 0x78a5636fUL, PUBLIC);
        sha256_k[58] = Integer(WORDLEN, 0x84c87814UL, PUBLIC);
        sha256_k[59] = Integer(WORDLEN, 0x8cc70208UL, PUBLIC);
        sha256_k[60] = Integer(WORDLEN, 0x90befffaUL, PUBLIC);
        sha256_k[61] = Integer(WORDLEN, 0xa4506cebUL, PUBLIC);
        sha256_k[62] = Integer(WORDLEN, 0xbef9a3f7UL, PUBLIC);
        sha256_k[63] = Integer(WORDLEN, 0xc67178f2UL, PUBLIC);
    }

    inline void padding(Integer& padded_input, const Integer input) {
        uint64_t L = input.size();

        long long K = (uint64_t)CHUNKLEN - 65 - L;
        while (K < 0) {
            K += CHUNKLEN;
        }

        Integer ONE(1, 1, PUBLIC);
        Integer INTK(K, 0, PUBLIC);
        Integer INTL(64, L, PUBLIC);

        padded_input = input;
        concat(padded_input, &ONE, 1);
        concat(padded_input, &INTK, 1);
        concat(padded_input, &INTL, 1);
    }

    // reuse_out_hash_flag indicates to reuse outer value as an optimization.
    void update(Integer* dig, const Integer padded_input, bool reuse_out_hash_flag = false) {
        uint64_t padded_len = padded_input.size();
        assert(padded_len % CHUNKLEN == 0);
        vector<Integer> input_data;
        size_t input_data_size = padded_len / WORDLEN;
        input_data.resize(input_data_size);

        for (size_t i = 0; i < input_data_size; i++) {
            extract_integer(input_data[i], padded_input, i * WORDLEN, WORDLEN);
        }

        uint64_t num_chunk = padded_len / CHUNKLEN;
        for (int i = 0; i < VALLEN; i++)
            dig[i] = sha256_h[i];

        Integer* tmp_block = new Integer[CHUNKLEN / WORDLEN]; //CHUNKLEN/WORDLEN=16
        for (int j = 0; j < CHUNKLEN / WORDLEN; j++) {
            tmp_block[j] = input_data[j];
        }

        // check if the out_flag opened or not. If opened, will use the outer value (shares) as an optimization. Otherwise, it is the normal hash function.
        if (reuse_out_hash_flag == true) {
            if (gc_out_open_flag == false) {
                chunk_compress(dig, tmp_block);

                for (int i = 0; i < DIGLEN; i++)
                    iv_out_hash[i] = dig[i];
                gc_out_open_flag = true;
            } else {
                for (int i = 0; i < DIGLEN; i++)
                    dig[i] = iv_out_hash[i];
            }
        } else {
            chunk_compress(dig, tmp_block);
        }

        for (uint64_t i = 1; i < num_chunk; i++) {
            for (int j = 0; j < CHUNKLEN / WORDLEN; j++) {
                tmp_block[j] = input_data[j + i * CHUNKLEN / WORDLEN];
            }
            chunk_compress(dig, tmp_block);
        }
        delete[] tmp_block;
    }

    void opt_update(uint32_t* plain_dig,
                    const Integer sec_input,
                    unsigned char* pub_input,
                    size_t pub_len,
                    bool reuse_in_hash_flag = false,
                    bool zk_flag = false) {
        uint64_t len = sec_input.size();
        assert(len == CHUNKLEN);
        vector<Integer> input_data;
        size_t input_data_size = len / WORDLEN;
        input_data.resize(input_data_size);
        for (size_t i = 0; i < input_data_size; i++) {
            extract_integer(input_data[i], sec_input, i * WORDLEN, WORDLEN);
        }

        // enable the reuse optimization, reuse opened value and store it in iv_in_hash.
        if (reuse_in_hash_flag == true) {
            // not enable zk
            if (!zk_flag) {
                // if iv_in_hash is empty, compute the gc shares, open it and store the value in iv_in_hash.
                if (gc_in_open_flag == false) {
                    Integer* dig = new Integer[VALLEN];
                    for (int i = 0; i < VALLEN; i++)
                        dig[i] = sha256_h[i];
                    chunk_compress(dig, input_data.data());
                    Integer tmpInt;
                    reverse_concat(tmpInt, dig, VALLEN);
                    tmpInt.reveal<uint32_t>((uint32_t*)plain_dig, PUBLIC);

                    iv_in_hashes.push_back(nullptr);
                    iv_in_hashes.back() = new uint32_t[DIGLEN];
                    memcpy(iv_in_hashes.back(), plain_dig, DIGLEN * sizeof(uint32_t));

                    gc_in_open_flag = true;
                    pos++;

                    delete[] dig;

                } else {
                    //if iv_in_hash is stored,reuse it.
                    memcpy(plain_dig, iv_in_hashes[pos], DIGLEN * sizeof(uint32_t));
                    // memcpy(plain_dig, iv_in_hash, DIGLEN * sizeof(uint32_t));
                }
            } else {
                // enable zk.
                // iv_in_hash already exists in this setting. In the zk setting, we should first compute the compression function (zk shares) and check consistency.
                // Only compute and check once.
                if (zk_in_open_flag == false) {
                    Integer* dig = new Integer[VALLEN];
                    for (int i = 0; i < VALLEN; i++)
                        dig[i] = sha256_h[i];
                    chunk_compress(dig, input_data.data());

                    Integer zk_iv_in_hash;
                    concat(zk_iv_in_hash, dig, DIGLEN);
                    zk_iv_in_hashes.push_back(zk_iv_in_hash);

                    zk_in_open_flag = true;
                    zpos++;

                    delete[] dig;
                }
                // reuse the stored value anyway.
                memcpy(plain_dig, iv_in_hashes[zpos], DIGLEN * sizeof(uint32_t));
            }
        } else {
            // Do not enable the reuse optimization, but still open the inner hash as an optimization.
            Integer* dig = new Integer[VALLEN];
            for (int i = 0; i < VALLEN; i++)
                dig[i] = sha256_h[i];

            chunk_compress(dig, input_data.data());
            Integer tmpInt;
            reverse_concat(tmpInt, dig, VALLEN);
            tmpInt.reveal<uint32_t>((uint32_t*)plain_dig, PUBLIC);

            delete[] dig;
        }

        // compute the following part in plain, not in mpc.
        unsigned char* data = new unsigned char[KLEN];
        uint64_t datalen = 0, bitlen = 512;

        for (size_t i = 0; i < pub_len; i++) {
            data[datalen] = pub_input[i];
            datalen++;
            if (datalen == 64) {
                plain_chunk_compress(plain_dig, data);
                bitlen += 512;
                datalen = 0;
            }
        }

        size_t i = datalen;

        if (datalen < 56) {
            data[i++] = 0x80;
            while (i < 56)
                data[i++] = 0x00;
        } else {
            data[i++] = 0x80;
            while (i < 64)
                data[i++] = 0x00;
            plain_chunk_compress(plain_dig, data);
            memset(data, 0, 56);
        }

        bitlen += datalen * 8; /* must be 64 bits */
        data[63] = bitlen;
        data[62] = bitlen >> 8;
        data[61] = bitlen >> 16;
        data[60] = bitlen >> 24;
        data[59] = bitlen >> 32;
        data[58] = bitlen >> 40;
        data[57] = bitlen >> 48;
        data[56] = bitlen >> 56;
        plain_chunk_compress(plain_dig, data);

        delete[] data;
    }

    void opt_rounds_update(Integer* dig,
                           const Integer padded_input,
                           bool reuse_in_hash_flag = false) {
        uint64_t padded_len = padded_input.size();
        assert(padded_len % CHUNKLEN == 0);
        vector<Integer> input_data;
        size_t input_data_size = padded_len / WORDLEN;
        input_data.resize(input_data_size);
        for (size_t i = 0; i < input_data_size; i++) {
            extract_integer(input_data[i], padded_input, i * WORDLEN, WORDLEN);
        }

        uint64_t num_chunk = padded_len / CHUNKLEN;
        for (int i = 0; i < VALLEN; i++)
            dig[i] = sha256_h[i];

        Integer* tmp_block = new Integer[CHUNKLEN / WORDLEN]; //CHUNKLEN/WORDLEN=16
        for (int j = 0; j < CHUNKLEN / WORDLEN; j++) {
            tmp_block[j] = input_data[j];
        }

        if (reuse_in_hash_flag == true) {
            if (gc_in_open_flag == false) {
                chunk_compress(dig, tmp_block);

                for (int i = 0; i < DIGLEN; i++)
                    iv_in_hash[i] = dig[i];
                gc_in_open_flag = true;
            } else {
                for (int i = 0; i < DIGLEN; i++)
                    dig[i] = iv_in_hash[i];
            }
        } else {
            chunk_compress(dig, tmp_block);
        }

        for (uint64_t i = 1; i < num_chunk; i++) {
            for (int j = 0; j < CHUNKLEN / WORDLEN; j++) {
                tmp_block[j] = input_data[j + i * CHUNKLEN / WORDLEN];
            }
            chunk_compress(dig, tmp_block);
        }
        delete[] tmp_block;
    }

    void chunk_compress(Integer* input_h, Integer* chunk) {
        compression_calls_num++;
        Integer* w = new Integer[KLEN];
        for (int i = 0; i < CHUNKLEN / WORDLEN; i++) //initiate w
            w[i] = chunk[i];
        for (int i = 16; i < KLEN; i++) {
            Integer s0 = rrot(w[i - 15], 7) ^ rrot(w[i - 15], 18) ^ (w[i - 15] >> 3);
            Integer s1 = rrot(w[i - 2], 17) ^ rrot(w[i - 2], 19) ^ (w[i - 2] >> 10);
            w[i] = w[i - 16] + s0 + w[i - 7] + s1;
        }

        Integer a = input_h[0], b = input_h[1], c = input_h[2], d = input_h[3], e = input_h[4],
                f = input_h[5], g = input_h[6],
                h = input_h[7]; //working variables

        Integer S1, ch, temp1, S0, maj, temp2;

        for (int i = 0; i < KLEN; i++) { //compression function main loop
            S1 = rrot(e, 6) ^ rrot(e, 11) ^ rrot(e, 25);
            ch = (e & (f ^ g)) ^ g;
            temp1 = h + sha256_k[i] + S1 + ch + w[i]; //22009 AND
            S0 = rrot(a, 2) ^ rrot(a, 13) ^ rrot(a, 22);
            maj = ((a ^ b) & (a ^ c)) ^ a;
            temp2 = S0 + maj;

            h = g;
            g = f;
            f = e;
            e = d + temp1;
            d = c;
            c = b;
            b = a;
            a = temp1 + temp2;
        }

        input_h[0] = a + input_h[0];
        input_h[1] = b + input_h[1];
        input_h[2] = c + input_h[2];
        input_h[3] = d + input_h[3];
        input_h[4] = e + input_h[4];
        input_h[5] = f + input_h[5];
        input_h[6] = g + input_h[6];
        input_h[7] = h + input_h[7];

        delete[] w;
    }

    void plain_chunk_compress(uint32_t* input_h, unsigned char* chunk) {
        uint32_t* w = new uint32_t[KLEN];
        for (int i = 0, j = 0; i < 16; i++, j += 4) //initiate w
            w[i] =
              (chunk[j] << 24) | (chunk[j + 1] << 16) | (chunk[j + 2] << 8) | chunk[j + 3];

        for (int i = 16; i < KLEN; i++) {
            uint32_t s0 = rrot(w[i - 15], 7) ^ rrot(w[i - 15], 18) ^ (w[i - 15] >> 3);
            uint32_t s1 = rrot(w[i - 2], 17) ^ rrot(w[i - 2], 19) ^ (w[i - 2] >> 10);
            w[i] = w[i - 16] + s0 + w[i - 7] + s1;
        }

        uint32_t a = input_h[0], b = input_h[1], c = input_h[2], d = input_h[3],
                 e = input_h[4], f = input_h[5], g = input_h[6],
                 h = input_h[7]; //working variables

        uint32_t S1, ch, temp1, S0, maj, temp2;

        for (int i = 0; i < KLEN; i++) { //compression function main loop
            S1 = rrot(e, 6) ^ rrot(e, 11) ^ rrot(e, 25);
            ch = (e & (f ^ g)) ^ g;
            temp1 = h + plain_sha256_k[i] + S1 + ch + w[i];
            S0 = rrot(a, 2) ^ rrot(a, 13) ^ rrot(a, 22);
            maj = ((a ^ b) & (a ^ c)) ^ a;
            temp2 = S0 + maj;

            h = g;
            g = f;
            f = e;
            e = d + temp1;
            d = c;
            c = b;
            b = a;
            a = temp1 + temp2;
        }

        input_h[0] = a + input_h[0];
        input_h[1] = b + input_h[1];
        input_h[2] = c + input_h[2];
        input_h[3] = d + input_h[3];
        input_h[4] = e + input_h[4];
        input_h[5] = f + input_h[5];
        input_h[6] = g + input_h[6];
        input_h[7] = h + input_h[7];
        delete[] w;
    }

    inline void digest(Integer* res, Integer input, bool reuse_out_hash_flag = false) {
        Integer padded_input;
        padding(padded_input, input);
        update(res, padded_input, reuse_out_hash_flag);
    }

    inline void opt_digest(uint32_t* res,
                           const Integer sec_input,
                           unsigned char* pub_input,
                           size_t pub_len,
                           bool reuse_in_hash_flag = false,
                           bool zk_flag = false) {
        opt_update(res, sec_input, pub_input, pub_len, reuse_in_hash_flag, zk_flag);
    }

    inline void opt_rounds_digest(Integer* res,
                                  Integer input,
                                  bool reuse_in_hash_flag = false) {
        Integer padded_input;
        padding(padded_input, input);
        opt_rounds_update(res, padded_input, reuse_in_hash_flag);
    }

    inline size_t compression_calls() { return compression_calls_num; }

    template <typename IO>
    inline void sha256_check(int party) {
        uint32_t* tmp = new uint32_t[DIGLEN];
        for (size_t i = 0; i < iv_in_hashes.size(); i++) {
            memcpy(tmp, iv_in_hashes[i], DIGLEN * sizeof(uint32_t));
            reverse(tmp, tmp + DIGLEN);
            check_zero<IO>(zk_iv_in_hashes[i], tmp, DIGLEN, party);
        }
        delete[] tmp;
    }
};

class SHA256Offline {
   public:
    static const int DIGLEN = 8;
    static const int VALLEN = 8;
    static const int WORDLEN = 32;
    static const int KLEN = 64;
    static const int CHUNKLEN = 512;

    int compression_calls_num = 0;

    // gc_in_open_flag indicates already store the inner value, this indicator is for gc.
    bool gc_in_open_flag = false;

    // gc_out_open_flag indicates already store the outer value, this indicator is for gc.
    bool gc_out_open_flag = false;

    // iv_out_hash stores the outer secret value (shares).
    Integer iv_out_hash[DIGLEN];

    // This is optimized to reduce rounds
    Integer iv_in_hash[DIGLEN];

    Integer sha256_h[VALLEN] = {
      Integer(WORDLEN, 0x6a09e667UL, PUBLIC), Integer(WORDLEN, 0xbb67ae85UL, PUBLIC),
      Integer(WORDLEN, 0x3c6ef372UL, PUBLIC), Integer(WORDLEN, 0xa54ff53aUL, PUBLIC),
      Integer(WORDLEN, 0x510e527fUL, PUBLIC), Integer(WORDLEN, 0x9b05688cUL, PUBLIC),
      Integer(WORDLEN, 0x1f83d9abUL, PUBLIC), Integer(WORDLEN, 0x5be0cd19UL, PUBLIC)};

    Integer sha256_k[KLEN] = {
      Integer(WORDLEN, 0x428a2f98UL, PUBLIC), Integer(WORDLEN, 0x71374491UL, PUBLIC),
      Integer(WORDLEN, 0xb5c0fbcfUL, PUBLIC), Integer(WORDLEN, 0xe9b5dba5UL, PUBLIC),
      Integer(WORDLEN, 0x3956c25bUL, PUBLIC), Integer(WORDLEN, 0x59f111f1UL, PUBLIC),
      Integer(WORDLEN, 0x923f82a4UL, PUBLIC), Integer(WORDLEN, 0xab1c5ed5UL, PUBLIC),
      Integer(WORDLEN, 0xd807aa98UL, PUBLIC), Integer(WORDLEN, 0x12835b01UL, PUBLIC),
      Integer(WORDLEN, 0x243185beUL, PUBLIC), Integer(WORDLEN, 0x550c7dc3UL, PUBLIC),
      Integer(WORDLEN, 0x72be5d74UL, PUBLIC), Integer(WORDLEN, 0x80deb1feUL, PUBLIC),
      Integer(WORDLEN, 0x9bdc06a7UL, PUBLIC), Integer(WORDLEN, 0xc19bf174UL, PUBLIC),
      Integer(WORDLEN, 0xe49b69c1UL, PUBLIC), Integer(WORDLEN, 0xefbe4786UL, PUBLIC),
      Integer(WORDLEN, 0x0fc19dc6UL, PUBLIC), Integer(WORDLEN, 0x240ca1ccUL, PUBLIC),
      Integer(WORDLEN, 0x2de92c6fUL, PUBLIC), Integer(WORDLEN, 0x4a7484aaUL, PUBLIC),
      Integer(WORDLEN, 0x5cb0a9dcUL, PUBLIC), Integer(WORDLEN, 0x76f988daUL, PUBLIC),
      Integer(WORDLEN, 0x983e5152UL, PUBLIC), Integer(WORDLEN, 0xa831c66dUL, PUBLIC),
      Integer(WORDLEN, 0xb00327c8UL, PUBLIC), Integer(WORDLEN, 0xbf597fc7UL, PUBLIC),
      Integer(WORDLEN, 0xc6e00bf3UL, PUBLIC), Integer(WORDLEN, 0xd5a79147UL, PUBLIC),
      Integer(WORDLEN, 0x06ca6351UL, PUBLIC), Integer(WORDLEN, 0x14292967UL, PUBLIC),
      Integer(WORDLEN, 0x27b70a85UL, PUBLIC), Integer(WORDLEN, 0x2e1b2138UL, PUBLIC),
      Integer(WORDLEN, 0x4d2c6dfcUL, PUBLIC), Integer(WORDLEN, 0x53380d13UL, PUBLIC),
      Integer(WORDLEN, 0x650a7354UL, PUBLIC), Integer(WORDLEN, 0x766a0abbUL, PUBLIC),
      Integer(WORDLEN, 0x81c2c92eUL, PUBLIC), Integer(WORDLEN, 0x92722c85UL, PUBLIC),
      Integer(WORDLEN, 0xa2bfe8a1UL, PUBLIC), Integer(WORDLEN, 0xa81a664bUL, PUBLIC),
      Integer(WORDLEN, 0xc24b8b70UL, PUBLIC), Integer(WORDLEN, 0xc76c51a3UL, PUBLIC),
      Integer(WORDLEN, 0xd192e819UL, PUBLIC), Integer(WORDLEN, 0xd6990624UL, PUBLIC),
      Integer(WORDLEN, 0xf40e3585UL, PUBLIC), Integer(WORDLEN, 0x106aa070UL, PUBLIC),
      Integer(WORDLEN, 0x19a4c116UL, PUBLIC), Integer(WORDLEN, 0x1e376c08UL, PUBLIC),
      Integer(WORDLEN, 0x2748774cUL, PUBLIC), Integer(WORDLEN, 0x34b0bcb5UL, PUBLIC),
      Integer(WORDLEN, 0x391c0cb3UL, PUBLIC), Integer(WORDLEN, 0x4ed8aa4aUL, PUBLIC),
      Integer(WORDLEN, 0x5b9cca4fUL, PUBLIC), Integer(WORDLEN, 0x682e6ff3UL, PUBLIC),
      Integer(WORDLEN, 0x748f82eeUL, PUBLIC), Integer(WORDLEN, 0x78a5636fUL, PUBLIC),
      Integer(WORDLEN, 0x84c87814UL, PUBLIC), Integer(WORDLEN, 0x8cc70208UL, PUBLIC),
      Integer(WORDLEN, 0x90befffaUL, PUBLIC), Integer(WORDLEN, 0xa4506cebUL, PUBLIC),
      Integer(WORDLEN, 0xbef9a3f7UL, PUBLIC), Integer(WORDLEN, 0xc67178f2UL, PUBLIC)};

    SHA256Offline() {};
    ~SHA256Offline() {};

    inline void refresh() {
        compression_calls_num = 0;
        gc_in_open_flag = false;
        gc_out_open_flag = false;
    }
    inline void padding(Integer& padded_input, const Integer input) {
        uint64_t L = input.size();

        long long K = (uint64_t)CHUNKLEN - 65 - L;
        while (K < 0) {
            K += CHUNKLEN;
        }

        Integer ONE(1, 1, PUBLIC);
        Integer INTK(K, 0, PUBLIC);
        Integer INTL(64, L, PUBLIC);

        padded_input = input;
        concat(padded_input, &ONE, 1);
        concat(padded_input, &INTK, 1);
        concat(padded_input, &INTL, 1);
    }

    // reuse_out_hash_flag indicates to reuse outer value as an optimization.
    void update(Integer* dig, const Integer padded_input, bool reuse_out_hash_flag = false) {
        uint64_t padded_len = padded_input.size();
        assert(padded_len % CHUNKLEN == 0);
        vector<Integer> input_data;
        size_t input_data_size = padded_len / WORDLEN;
        input_data.resize(input_data_size);
        for (size_t i = 0; i < input_data_size; i++) {
            extract_integer(input_data[i], padded_input, i * WORDLEN, WORDLEN);
        }

        uint64_t num_chunk = padded_len / CHUNKLEN;
        for (int i = 0; i < VALLEN; i++)
            dig[i] = sha256_h[i];

        Integer* tmp_block = new Integer[CHUNKLEN / WORDLEN]; //CHUNKLEN/WORDLEN=16
        for (int j = 0; j < CHUNKLEN / WORDLEN; j++) {
            tmp_block[j] = input_data[j];
        }

        // check if the out_flag opened or not. If opened, will use the outer value (shares) as an optimization. Otherwise, it is the normal hash function.
        if (reuse_out_hash_flag == true) {
            if (gc_out_open_flag == false) {
                chunk_compress(dig, tmp_block);

                for (int i = 0; i < DIGLEN; i++)
                    iv_out_hash[i] = dig[i];
                gc_out_open_flag = true;
            } else {
                for (int i = 0; i < DIGLEN; i++)
                    dig[i] = iv_out_hash[i];
            }
        } else {
            chunk_compress(dig, tmp_block);
        }

        for (uint64_t i = 1; i < num_chunk; i++) {
            for (int j = 0; j < CHUNKLEN / WORDLEN; j++) {
                tmp_block[j] = input_data[j + i * CHUNKLEN / WORDLEN];
            }
            chunk_compress(dig, tmp_block);
        }
        delete[] tmp_block;
    }

    void opt_update(const Integer sec_input, bool reuse_in_hash_flag = false) {
        uint64_t len = sec_input.size();
        assert(len == CHUNKLEN);
        vector<Integer> input_data;
        size_t input_data_size = len / WORDLEN;
        input_data.resize(input_data_size);
        for (size_t i = 0; i < input_data_size; i++) {
            extract_integer(input_data[i], sec_input, i * WORDLEN, WORDLEN);
        }

        // enable the reuse optimization, reuse opened value and store it in iv_in_hash.
        if (reuse_in_hash_flag == true) {
            // if iv_in_hash is empty, compute the gc shares, open it and store the value in iv_in_hash.
            if (gc_in_open_flag == false) {
                Integer dig[VALLEN];
                for (int i = 0; i < VALLEN; i++)
                    dig[i] = sha256_h[i];
                chunk_compress(dig, input_data.data());
                Integer tmpInt;
                reverse_concat(tmpInt, dig, VALLEN);

                uint32_t plain_dig[VALLEN];
                tmpInt.reveal<uint32_t>((uint32_t*)plain_dig, PUBLIC);

                gc_in_open_flag = true;
            }
        } else {
            // Do not enable the reuse optimization, but still open the inner hash as an optimization.
            Integer dig[VALLEN];
            for (int i = 0; i < VALLEN; i++)
                dig[i] = sha256_h[i];

            chunk_compress(dig, input_data.data());
            Integer tmpInt;
            reverse_concat(tmpInt, dig, VALLEN);

            uint32_t plain_dig[VALLEN];
            tmpInt.reveal<uint32_t>((uint32_t*)plain_dig, PUBLIC);
        }
    }

    /* This optimization aims to save rounds, resulting in larger communication size*/
    void opt_rounds_update(Integer* dig,
                           const Integer padded_input,
                           bool reuse_in_hash_flag = false) {
        uint64_t padded_len = padded_input.size();
        assert(padded_len % CHUNKLEN == 0);
        vector<Integer> input_data;
        size_t input_data_size = padded_len / WORDLEN;
        input_data.resize(input_data_size);
        for (size_t i = 0; i < input_data_size; i++) {
            extract_integer(input_data[i], padded_input, i * WORDLEN, WORDLEN);
        }

        uint64_t num_chunk = padded_len / CHUNKLEN;
        for (int i = 0; i < VALLEN; i++)
            dig[i] = sha256_h[i];

        Integer* tmp_block = new Integer[CHUNKLEN / WORDLEN]; //CHUNKLEN/WORDLEN=16
        for (int j = 0; j < CHUNKLEN / WORDLEN; j++) {
            tmp_block[j] = input_data[j];
        }

        if (reuse_in_hash_flag == true) {
            if (gc_in_open_flag == false) {
                chunk_compress(dig, tmp_block);

                for (int i = 0; i < DIGLEN; i++)
                    iv_in_hash[i] = dig[i];
                gc_in_open_flag = true;
            } else {
                for (int i = 0; i < DIGLEN; i++)
                    dig[i] = iv_in_hash[i];
            }
        } else {
            chunk_compress(dig, tmp_block);
        }

        for (uint64_t i = 1; i < num_chunk; i++) {
            for (int j = 0; j < CHUNKLEN / WORDLEN; j++) {
                tmp_block[j] = input_data[j + i * CHUNKLEN / WORDLEN];
            }
            chunk_compress(dig, tmp_block);
        }
        delete[] tmp_block;
    }

    void chunk_compress(Integer* input_h, Integer* chunk) {
        compression_calls_num++;
        Integer* w = new Integer[KLEN];
        for (int i = 0; i < CHUNKLEN / WORDLEN; i++) //initiate w
            w[i] = chunk[i];
        for (int i = 16; i < KLEN; i++) {
            Integer s0 = rrot(w[i - 15], 7) ^ rrot(w[i - 15], 18) ^ (w[i - 15] >> 3);
            Integer s1 = rrot(w[i - 2], 17) ^ rrot(w[i - 2], 19) ^ (w[i - 2] >> 10);
            w[i] = w[i - 16] + s0 + w[i - 7] + s1;
        }

        Integer a = input_h[0], b = input_h[1], c = input_h[2], d = input_h[3], e = input_h[4],
                f = input_h[5], g = input_h[6],
                h = input_h[7]; //working variables

        Integer S1, ch, temp1, S0, maj, temp2;

        for (int i = 0; i < KLEN; i++) { //compression function main loop
            S1 = rrot(e, 6) ^ rrot(e, 11) ^ rrot(e, 25);
            ch = (e & (f ^ g)) ^ g;
            temp1 = h + sha256_k[i] + S1 + ch + w[i]; //22009 AND
            S0 = rrot(a, 2) ^ rrot(a, 13) ^ rrot(a, 22);
            maj = ((a ^ b) & (a ^ c)) ^ a;
            temp2 = S0 + maj;

            h = g;
            g = f;
            f = e;
            e = d + temp1;
            d = c;
            c = b;
            b = a;
            a = temp1 + temp2;
        }

        input_h[0] = a + input_h[0];
        input_h[1] = b + input_h[1];
        input_h[2] = c + input_h[2];
        input_h[3] = d + input_h[3];
        input_h[4] = e + input_h[4];
        input_h[5] = f + input_h[5];
        input_h[6] = g + input_h[6];
        input_h[7] = h + input_h[7];

        delete[] w;
    }

    inline void digest(Integer* res, Integer input, bool reuse_out_hash_flag = false) {
        Integer padded_input;
        padding(padded_input, input);
        update(res, padded_input, reuse_out_hash_flag);
    }

    inline void opt_digest(const Integer sec_input, bool reuse_in_hash_flag = false) {
        opt_update(sec_input, reuse_in_hash_flag);
    }
    inline void opt_rounds_digest(Integer* res,
                                  Integer input,
                                  bool reuse_in_hash_flag = false) {
        Integer padded_input;
        padding(padded_input, input);
        opt_rounds_update(res, padded_input, reuse_in_hash_flag);
    }
};

#endif

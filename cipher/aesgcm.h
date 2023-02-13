#ifndef _AES_GCM_H_
#define _AES_GCM_H_
#include "emp-tool/emp-tool.h"
#include "backend/vope.h"
#include "utils.h"
using namespace emp;

template <typename IO>
class AESGCM {
   public:
    Integer H;
    Integer expanded_key;
    block h = zero_block;
    Integer nonce;
    VOPE<IO>* vope = nullptr;
    AESGCM(Integer& key, unsigned char* iv, size_t iv_len) {
        if (iv_len != 12) {
            error("invalid IV length!\n");
        }
        reverse(iv, iv + iv_len);
        nonce = Integer(96, iv, PUBLIC);
        Integer ONE = Integer(32, 1, PUBLIC);
        concat(nonce, &ONE, 1);

        expanded_key = computeKS(key);
        computeH();
    }
    ~AESGCM() {
        if (vope != nullptr)
            delete vope;
    }

    inline void computeH() {
        Integer in(128, 0, PUBLIC);
        //H = computeAES(key, in);
        H = computeAES_KS(expanded_key, in);
    }

    inline void InitVOPE(IO* io, COT<IO>* ot) { vope = new VOPE<IO>(io, ot); }

    inline Integer inc(Integer& counter, size_t s) {
        if (counter.size() < s) {
            error("invalid length s!");
        }
        Integer msb = counter, lsb = counter;
        msb.bits.erase(msb.bits.begin(), msb.bits.begin() + s);
        lsb.bits.erase(lsb.bits.begin() + s, lsb.bits.end());
        lsb = lsb + Integer(s, 1, PUBLIC);

        concat(msb, &lsb, 1);
        return msb;
    }

    inline void gctr(Integer& res, size_t m) {
        Integer tmp(128, 0, PUBLIC);
        for (int i = 0; i < m; i++) {
            Integer content = nonce;
            //tmp = computeAES(key, content);
            tmp = computeAES_KS(expanded_key, content);

            concat(res, &tmp, 1);
            nonce = inc(nonce, 32);
        }
    }

    void enc_finished_msg(IO* io,
                          unsigned char* ctxt,
                          unsigned char* tag,
                          const unsigned char* msg,
                          size_t msg_len,
                          const unsigned char* aad,
                          size_t aad_len,
                          int party) {
        // u = 128 * ceil(msg_len/128) - 8*msg_len
        size_t u = 128 * ((msg_len * 8 + 128 - 1) / 128) - msg_len * 8;

        size_t ctr_len = (msg_len * 8 + 128 - 1) / 128;

        Integer Z;
        gctr(Z, 1 + ctr_len);

        H.bits.insert(H.bits.end(), Z.bits.end() - 128, Z.bits.end());

        block* h_z0 = new block[2];
        H.reveal<block>((block*)h_z0, ALICE);

        h = h_z0[0];

        Z.bits.erase(Z.bits.end() - 128, Z.bits.end());
        Z.bits.erase(Z.bits.begin(), Z.bits.begin() + u);

        unsigned char* z = new unsigned char[msg_len];
        Z.reveal<unsigned char>((unsigned char*)z, BOB);
        reverse(z, z + msg_len);
        if (party == ALICE) {
            // v = 128 * ceil(8*aad_len/128) - aad_len*8
            size_t v = 128 * ((aad_len * 8 + 128 - 1) / 128) - aad_len * 8;

            if (msg_len != 0) {
                io->recv_data(ctxt, msg_len);
            }

            size_t len = u / 8 + msg_len + v / 8 + aad_len + 16;

            unsigned char* x = new unsigned char[len];

            unsigned char ilen[8], mlen[8];
            for (int i = 0; i < 8; i++) {
                ilen[i] = (8 * aad_len) >> (7 - i) * 8;
                mlen[i] = (8 * msg_len) >> (7 - i) * 8;
            }

            memcpy(x, aad, aad_len);
            memset(x + aad_len, 0, v / 8);
            memcpy(x + aad_len + v / 8, ctxt, msg_len);
            memset(x + aad_len + v / 8 + msg_len, 0, u / 8);
            memcpy(x + aad_len + v / 8 + msg_len + u / 8, ilen, 8);
            memcpy(x + aad_len + v / 8 + msg_len + u / 8 + 8, mlen, 8);

            reverse(x, x + len);
            block* xblk = (block*)x;
            reverse(xblk, xblk + (8 * len) / 128);

            block t = ghash(h, xblk, 8 * len / 128);
            t = t ^ h_z0[1];

            memcpy(tag, (unsigned char*)&t, 16);
            reverse(tag, tag + 16);
            io->send_data(tag, 16);
            // io->flush();

            delete[] x;
        } else if (party == BOB) {
            for (int i = 0; i < msg_len; i++) {
                ctxt[i] = z[i] ^ msg[i];
            }
            if (msg_len != 0) {
                io->send_data(ctxt, msg_len);
                // io->flush();
            }
            io->recv_data(tag, 16);
        }

        delete[] h_z0;
        delete[] z;
    }

    bool dec_finished_msg(IO* io,
                          unsigned char* msg,
                          const unsigned char* ctxt,
                          size_t ctxt_len,
                          const unsigned char* tag,
                          const unsigned char* aad,
                          size_t aad_len,
                          int party) {
        // u = 128 * ceil(ctxt_len/128) - 8*ctxt_len
        size_t u = 128 * ((ctxt_len * 8 + 128 - 1) / 128) - ctxt_len * 8;

        size_t ctr_len = (ctxt_len * 8 + 128 - 1) / 128;

        Integer Z;
        gctr(Z, 1 + ctr_len);

        H.bits.insert(H.bits.end(), Z.bits.end() - 128, Z.bits.end());

        block* h_z0 = new block[2];
        H.reveal<block>((block*)h_z0, ALICE);

        h = h_z0[0];

        Z.bits.erase(Z.bits.end() - 128, Z.bits.end());
        Z.bits.erase(Z.bits.begin(), Z.bits.begin() + u);

        unsigned char* z = new unsigned char[ctxt_len];
        Z.reveal<unsigned char>((unsigned char*)z, BOB);
        reverse(z, z + ctxt_len);

        bool res = false;

        if (party == ALICE) {
            // v = 128 * ceil(8*aad_len/128) - aad_len*8
            size_t v = 128 * ((aad_len * 8 + 128 - 1) / 128) - aad_len * 8;

            size_t len = u / 8 + ctxt_len + v / 8 + aad_len + 16;

            unsigned char* x = new unsigned char[len];

            unsigned char ilen[8], mlen[8];
            for (int i = 0; i < 8; i++) {
                ilen[i] = (8 * aad_len) >> (7 - i) * 8;
                mlen[i] = (8 * ctxt_len) >> (7 - i) * 8;
            }

            memcpy(x, aad, aad_len);
            memset(x + aad_len, 0, v / 8);
            memcpy(x + aad_len + v / 8, ctxt, ctxt_len);
            memset(x + aad_len + v / 8 + ctxt_len, 0, u / 8);
            memcpy(x + aad_len + v / 8 + ctxt_len + u / 8, ilen, 8);
            memcpy(x + aad_len + v / 8 + ctxt_len + u / 8 + 8, mlen, 8);

            reverse(x, x + len);
            block* xblk = (block*)x;
            reverse(xblk, xblk + (8 * len) / 128);

            block t = ghash(h_z0[0], xblk, 8 * len / 128);
            t = t ^ h_z0[1];

            unsigned char* tagc = (unsigned char*)&t;
            reverse(tagc, tagc + 16);

            res = (memcmp(tag, tagc, 16) == 0);
            io->send_bool(&res, 1);
            // io->flush();

            delete[] x;
        } else if (party == BOB) {
            io->recv_bool(&res, 1);
            if (res) {
                for (int i = 0; i < ctxt_len; i++) {
                    msg[i] = ctxt[i] ^ z[i];
                }
            }
        }

        delete[] h_z0;
        delete[] z;
        return res;
    }

    void enc_record_msg(IO* io,
                        unsigned char* ctxt,
                        unsigned char* tag,
                        const unsigned char* msg,
                        size_t msg_len,
                        const unsigned char* aad,
                        size_t aad_len,
                        int party) {
        // u = 128 * ceil(msg_len/128) - 8*msg_len
        size_t u = 128 * ((msg_len * 8 + 128 - 1) / 128) - msg_len * 8;

        size_t ctr_len = (msg_len * 8 + 128 - 1) / 128;

        Integer Z;
        gctr(Z, 1 + ctr_len);

        // extract Z0;
        Integer Z0;
        Z0.bits.insert(Z0.bits.end(), Z.bits.end() - 128, Z.bits.end());

        // reveal Z0 to ALICE
        block z0 = zero_block;
        Z0.reveal<block>((block*)&z0, ALICE);

        Z.bits.erase(Z.bits.end() - 128, Z.bits.end());
        Z.bits.erase(Z.bits.begin(), Z.bits.begin() + u);

        unsigned char* z = new unsigned char[msg_len];
        Z.reveal<unsigned char>((unsigned char*)z, BOB);
        reverse(z, z + msg_len);
        if (party == ALICE) {
            // v = 128 * ceil(8*aad_len/128) - aad_len*8
            size_t v = 128 * ((aad_len * 8 + 128 - 1) / 128) - aad_len * 8;
            size_t len = u / 8 + msg_len + 16;
            size_t vope_len = (8 * len) / 128;
            size_t x_len = v / 8 + aad_len;

            block out = zero_block;
            vope->compute_send(&out, h, vope_len);
            block* out1 = new block[vope_len];
            io->recv_block(out1, vope_len);
            reverse(out1, out1 + vope_len);
            block t1 = ghash(h, out1, vope_len);

            unsigned char* x = new unsigned char[x_len];
            memcpy(x, aad, aad_len);
            memset(x + aad_len, 0, v / 8);
            reverse(x, x + x_len);

            block* sigma = (block*)x;
            reverse(sigma, sigma + (8 * x_len) / 128);
            block t = ghash(h, sigma, 8 * x_len / 128);
            t = mulBlock(t, powBlock(h, vope_len));
            t = t1 ^ t;
            t = out ^ t;
            t = z0 ^ t;

            io->send_block(&t, 1);

            delete[] x;
            delete[] out1;

        } else if (party == BOB) {
            for (int i = 0; i < msg_len; i++) {
                ctxt[i] = z[i] ^ msg[i];
            }

            size_t len = u / 8 + msg_len + 16;
            size_t vope_len = (8 * len) / 128;

            unsigned char* x = new unsigned char[len];

            unsigned char ilen[8], mlen[8];
            for (int i = 0; i < 8; i++) {
                ilen[i] = (8 * aad_len) >> (7 - i) * 8;
                mlen[i] = (8 * msg_len) >> (7 - i) * 8;
            }
            memcpy(x, ctxt, msg_len);
            memset(x + msg_len, 0, u / 8);
            memcpy(x + msg_len + u / 8, ilen, 8);
            memcpy(x + msg_len + u / 8 + 8, mlen, 8);

            reverse(x, x + len);
            block* out1 = (block*)x;

            block* out = new block[vope_len + 1];
            vope->compute_recv(out, vope_len);
            for (int i = 0; i < vope_len; i++) {
                out1[i] = out1[i] ^ out[i + 1];
            }

            io->send_block(out1, vope_len);

            block t = zero_block;
            io->recv_block(&t, 1);
            t = out[0] ^ t;

            memcpy(tag, (unsigned char*)&t, 16);
            reverse(tag, tag + 16);
            delete[] out;
            delete[] x;
        }

        delete[] z;
    }

    void dec_last_record_msg(IO* io, block* z0, size_t ctxt_len, int party) {
        size_t ctr_len = (ctxt_len * 8 + 128 - 1) / 128;
        Integer Z;
        gctr(Z, 1);
        Z.reveal<block>((block*)z0, ALICE);
        for (int i = 0; i < ctr_len; i++)
            nonce = inc(nonce, 32);
    }

    void dec_record_msg_without_check(IO* io,
                                      block* z0,
                                      unsigned char* msg,
                                      const unsigned char* ctxt,
                                      size_t ctxt_len,
                                      int party) {
        // u = 128 * ceil(msg_len/128) - 8*msg_len
        size_t u = 128 * ((ctxt_len * 8 + 128 - 1) / 128) - ctxt_len * 8;

        size_t ctr_len = (ctxt_len * 8 + 128 - 1) / 128;

        Integer Z;
        gctr(Z, 1 + ctr_len);

        // extract Z0;
        Integer Z0;
        Z0.bits.insert(Z0.bits.end(), Z.bits.end() - 128, Z.bits.end());

        // reveal Z0 to ALICE
        Z0.reveal<block>((block*)z0, ALICE);

        Z.bits.erase(Z.bits.end() - 128, Z.bits.end());
        Z.bits.erase(Z.bits.begin(), Z.bits.begin() + u);

        unsigned char* z = new unsigned char[ctxt_len];
        Z.reveal<unsigned char>((unsigned char*)z, BOB);
        reverse(z, z + ctxt_len);
        if (party == BOB) {
            for (int i = 0; i < ctxt_len; i++) {
                msg[i] = z[i] ^ ctxt[i];
            }
        }
        delete[] z;
    }

    bool dec_record_msg_with_check(IO* io,
                                   unsigned char* msg,
                                   const unsigned char* ctxt,
                                   size_t ctxt_len,
                                   const unsigned char* tag,
                                   const unsigned char* aad,
                                   size_t aad_len,
                                   int party) {
        // u = 128 * ceil(msg_len/128) - 8*msg_len
        size_t u = 128 * ((ctxt_len * 8 + 128 - 1) / 128) - ctxt_len * 8;

        size_t ctr_len = (ctxt_len * 8 + 128 - 1) / 128;

        Integer Z;
        gctr(Z, 1 + ctr_len);

        // extract Z0;
        Integer Z0;
        Z0.bits.insert(Z0.bits.end(), Z.bits.end() - 128, Z.bits.end());

        // reveal Z0 to ALICE
        block z0 = zero_block;
        Z0.reveal<block>((block*)&z0, ALICE);

        Z.bits.erase(Z.bits.end() - 128, Z.bits.end());
        Z.bits.erase(Z.bits.begin(), Z.bits.begin() + u);

        unsigned char* z = new unsigned char[ctxt_len];
        Z.reveal<unsigned char>((unsigned char*)z, BOB);
        reverse(z, z + ctxt_len);

        bool res = true;

        if (party == ALICE) {
            // v = 128 * ceil(8*aad_len/128) - aad_len*8
            size_t v = 128 * ((aad_len * 8 + 128 - 1) / 128) - aad_len * 8;
            size_t len = u / 8 + ctxt_len + 16;
            size_t vope_len = (8 * len) / 128;
            size_t x_len = v / 8 + aad_len;

            block out = zero_block;
            vope->compute_send(&out, h, vope_len);
            block* out1 = new block[vope_len];
            io->recv_block(out1, vope_len);
            reverse(out1, out1 + vope_len);
            block t1 = ghash(h, out1, vope_len);

            unsigned char* x = new unsigned char[x_len];
            memcpy(x, aad, aad_len);
            memset(x + aad_len, 0, v / 8);
            reverse(x, x + x_len);

            block* sigma = (block*)x;
            reverse(sigma, sigma + (8 * x_len) / 128);
            block t = ghash(h, sigma, 8 * x_len / 128);
            t = mulBlock(t, powBlock(h, vope_len));
            t = t1 ^ t;
            t = out ^ t;
            t = z0 ^ t;

            io->send_block(&t, 1);

            delete[] x;
            delete[] out1;

        } else if (party == BOB) {
            for (int i = 0; i < ctxt_len; i++) {
                msg[i] = z[i] ^ ctxt[i];
            }

            size_t len = u / 8 + ctxt_len + 16;
            size_t vope_len = (8 * len) / 128;

            unsigned char* x = new unsigned char[len];

            unsigned char ilen[8], mlen[8];
            for (int i = 0; i < 8; i++) {
                ilen[i] = (8 * aad_len) >> (7 - i) * 8;
                mlen[i] = (8 * ctxt_len) >> (7 - i) * 8;
            }
            memcpy(x, ctxt, ctxt_len);
            memset(x + ctxt_len, 0, u / 8);
            memcpy(x + ctxt_len + u / 8, ilen, 8);
            memcpy(x + ctxt_len + u / 8 + 8, mlen, 8);

            reverse(x, x + len);
            block* out1 = (block*)x;

            block* out = new block[vope_len + 1];
            vope->compute_recv(out, vope_len);
            for (int i = 0; i < vope_len; i++) {
                out1[i] = out1[i] ^ out[i + 1];
            }

            io->send_block(out1, vope_len);

            block t = zero_block;
            io->recv_block(&t, 1);
            t = out[0] ^ t;

            unsigned char* tagc = (unsigned char*)&t;
            reverse(tagc, tagc + 16);

            res = (memcmp(tag, tagc, 16) == 0);
            delete[] out;
            delete[] x;
        }
        delete[] z;
        return res;
    }
};
#endif
#ifndef _RECORD_H
#define _RECORD_H
#include "emp-tool/emp-tool.h"
#include "cipher/aead.h"
#include "cipher/aead_izk.h"

template <typename IO>
class Record {
   public:
    Record() {}
    ~Record() {}

    inline void encrypt(AEAD<IO>* aead_c,
                        IO* io,
                        unsigned char* ctxt,
                        unsigned char* tag,
                        const unsigned char* msg,
                        size_t msg_len,
                        const unsigned char* aad,
                        size_t aad_len,
                        int party) {
        aead_c->encrypt(io, ctxt, tag, msg, msg_len, aad, aad_len, party, true);
    }

    inline void decrypt(AEAD<IO>* aead_s,
                        IO* io,
                        unsigned char* msg,
                        const unsigned char* ctxt,
                        size_t ctxt_len,
                        const unsigned char* tag,
                        const unsigned char* aad,
                        size_t aad_len,
                        int party) {
        aead_s->decrypt(io, msg, ctxt, ctxt_len, tag, aad, aad_len, party, true);
    }

    inline void enc_record_msg(AEAD<IO>& aead_c,
                               IO* io,
                               unsigned char* ctxt,
                               unsigned char* tag,
                               const unsigned char* msg,
                               size_t msg_len,
                               const unsigned char* aad,
                               size_t aad_len,
                               int party) {
        aead_c.enc_record_msg(io, ctxt, tag, msg, msg_len, aad, aad_len, party);
    }

    inline void prove_record(AEAD_Proof<IO>* aead_proof,
                             Integer& msg,
                             const unsigned char* ctxt,
                             size_t ctxt_len) {
        aead_proof->prove_aead(msg, ctxt, ctxt_len, true);
    }
};
#endif
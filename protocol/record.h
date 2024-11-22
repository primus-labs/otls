#ifndef _RECORD_H
#define _RECORD_H
#include "emp-tool/emp-tool.h"
#include "protocol/aead.h"
#include "protocol/aead_izk.h"

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
                        const unsigned char* iv,
                        size_t iv_len,
                        int party) {
        aead_c->encrypt(io, ctxt, tag, msg, msg_len, aad, aad_len, iv, iv_len, party, true);
    }

    // Note that: the last message from server does not need to be decrypted in MPC.
    // This function is invoked in the multi-round setting.
    inline bool decrypt(AEAD<IO>* aead_s,
                        IO* io,
                        unsigned char* msg,
                        const unsigned char* ctxt,
                        size_t ctxt_len,
                        const unsigned char* tag,
                        const unsigned char* aad,
                        size_t aad_len,
                        const unsigned char* iv,
                        size_t iv_len,
                        int party) {
        return aead_s->decrypt(io, msg, ctxt, ctxt_len, tag, aad, aad_len, iv, iv_len, party,
                               true);
    }
};

class RecordOffline {
   public:
    RecordOffline() {};
    ~RecordOffline() {};

    inline void encrypt(AEADOffline* aead_c_offline, size_t msg_len) {
        aead_c_offline->encrypt(msg_len, true);
    }
    inline void decrypt(AEADOffline* aead_s_offline, size_t ctxt_len) {
        aead_s_offline->decrypt(ctxt_len, true);
    }
};

#endif

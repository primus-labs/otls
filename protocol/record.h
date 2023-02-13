#ifndef _RECORD_H
#define _RECORD_H
#include "emp-tool/emp-tool.h"
#include "cipher/aead.h"

template <typename IO>
class Record {
   public:
    Record() {}
    ~Record() {}
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
};
#endif
#ifndef _OFFLINE_PADO_EVA_H_
#define _OFFLINE_PADO_EVA_H_
#include "offline_hg_eva.h"
#include "offline_primus_party.h"

/* Offline evaluator (BOB) of the protocol */
template <typename IO>
class OfflinePADOEva : public OfflinePADOParty {
   public:
    IO* io;
    OfflineHalfGateEva<IO>* gc;
    vector<bool> pub_values;
    OfflinePADOEva(IO* io, OfflineHalfGateEva<IO>* gc) : OfflinePADOParty(BOB) {
        this->io = io;
        this->gc = gc;
    }

    void feed(block* label, int party, const bool* b, int length) {}

    void reveal(bool* b, int party, const block* label, int length) {
        if (party == PUBLIC) {
            for (int i = 0; i < length; ++i) {
                bool tmp = false;
                this->io->recv_data(&tmp, 1);
                pub_values.push_back(tmp);
            }
        }
    }
};
#endif

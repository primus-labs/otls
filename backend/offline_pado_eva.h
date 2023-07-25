#ifndef _OFFLINE_PADO_EVA_H_
#define _OFFLINE_PADO_EVA_H_
#include "offline_hg_eva.h"
#include "offline_pado_party.h"

template <typename IO>
class OfflinePADOEva : public OfflinePADOParty {
   public:
    IO* io;
    OfflineHalfGateEva<IO>* gc;
    vector<bool> pub_values;
    vector<bool> pub_values2;
    vector<bool> *p_pub_values = nullptr;
    OfflinePADOEva(IO* io, OfflineHalfGateEva<IO>* gc) : OfflinePADOParty(BOB) {
        this->io = io;
        this->gc = gc;

        p_pub_values = &pub_values;
    }

    void feed(block* label, int party, const bool* b, int length) {}

    void reveal(bool* b, int party, const block* label, int length) {
        if (party == PUBLIC) {
            for (int i = 0; i < length; ++i) {
                bool tmp = false;
                this->io->recv_data(&tmp, 1);
                p_pub_values->push_back(tmp);
            }
        }
    }

    void switch_status() {
        gc->switch_status();
        if (gc->server_finish) {
            p_pub_values = &pub_values2;
        }
        else {
            p_pub_values = &pub_values;
        }
    }
};
#endif

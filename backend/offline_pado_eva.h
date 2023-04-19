#ifndef _OFFLINE_PADO_EVA_H_
#define _OFFLINE_PADO_EVA_H_
#include "offline_hg_eva.h"
#include "offline_pado_party.h"

template <typename IO>
class OfflinePADOEva : public OfflinePADOParty {
   public:
    OfflineHalfGateEva<IO>* gc;
    OfflinePADOEva(OfflineHalfGateEva<IO>* gc) : OfflinePADOParty(BOB) { this->gc = gc; }

    void feed(block* label, int party, const bool* b, int length) {}

    void reveal(bool* b, int party, const block* label, int length) {}
};
#endif
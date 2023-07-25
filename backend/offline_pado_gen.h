#ifndef Offline_PADO_GEN_H__
#define Offline_PADO_GEN_H__
#include "offline_pado_party.h"
#include "offline_hg_gen.h"
template <typename IO>
class OfflinePADOGen : public OfflinePADOParty {
   public:
    IO* io;
    OfflineHalfGateGen<IO>* gc;
    block seed;
    block seed2;
    PRG prg;
    PRG prg2;
    PRG* p_prg = nullptr;

    OfflinePADOGen(IO* io, OfflineHalfGateGen<IO>* gc) : OfflinePADOParty(ALICE) {
        this->io = io;
        this->gc = gc;
        PRG().random_block(&seed, 1);
        prg = PRG(&seed);
        PRG().random_block(&seed2, 1);
        prg2 = PRG(&seed2);
        p_prg = &prg;
    }

    void feed(block* label, int party, const bool* b, int length) {
        p_prg->random_block(label, length);
    }

    void reveal(bool* b, int party, const block* label, int length) {
        if (party == PUBLIC)
            for (int i = 0; i < length; ++i) {
                bool lsb = getLSB(label[i]);
                this->io->send_data(&lsb, 1);
                // b[i] = false;
            }
    }

    void switch_status() {
        gc->switch_status();
        if (gc->server_finish) {
            p_prg = &prg2;
        }
        else {
            p_prg = &prg;
        }
    }
};

// class OfflinePADOGen : public ProtocolExecution {
//    public:
//     OfflineHalfGateGen* gc;
//     block seed;
//     PRG prg;
//     OfflinePADOGen(OfflineHalfGateGen* gc) : ProtocolExecution(ALICE) {
//         this->gc = gc;
//         PRG().random_block(&seed, 1);
//         prg = PRG(&seed);
//     }

//     void feed(block* label, int party, const bool* b, int length) {
//         prg.random_block(label, length);
//     }

//     void reveal(bool* b, int party, const block* label, int length) {}
// };
#endif

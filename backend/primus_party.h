#ifndef PRIMUS_PARTY_H__
#define PRIMUS_PARTY_H__
#include "emp-tool/emp-tool.h"
#include "emp-ot/emp-ot.h"
using namespace emp;

/* Define the general party in the protocol */
template <typename IO>
class PrimusParty : public ProtocolExecution {
   public:
    IO* io = nullptr;
    IKNP<IO>* ot = nullptr;
    PRG shared_prg;

    block* buf = nullptr;
    bool* buff = nullptr;
    int top = 0;
    int batch_size = 1024 * 16;
    using ProtocolExecution::cur_party;

    PrimusParty(IO* io, int party, IKNP<IO>* in_ot) : ProtocolExecution(party) {
        this->io = io;
        if (in_ot == nullptr)
            ot = new IKNP<IO>(io, true);
        else
            ot = in_ot;
        buf = new block[batch_size];
        buff = new bool[batch_size];
    }
    void set_batch_size(int size) {
        delete[] buf;
        delete[] buff;
        batch_size = size;
        buf = new block[batch_size];
        buff = new bool[batch_size];
    }

    ~PrimusParty() {
        delete[] buf;
        delete[] buff;
        delete ot;
    }
};
#endif

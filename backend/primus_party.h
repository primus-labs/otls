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
    std::unique_ptr<IKNP<IO>> p_ot;
    PRG shared_prg;

    block* buf = nullptr;
    std::unique_ptr<block[]> p_buf;
    bool* buff = nullptr;
    std::unique_ptr<bool[]> p_buff;
    int top = 0;
    int batch_size = 1024 * 16;
    using ProtocolExecution::cur_party;

    PrimusParty(IO* io, int party, IKNP<IO>* in_ot) : ProtocolExecution(party) {
        this->io = io;
        if (in_ot == nullptr)
            ot = new IKNP<IO>(io, true);
        else
            ot = in_ot;
        p_ot.reset(ot);
        buf = new block[batch_size];
        p_buf.reset(buf);
        buff = new bool[batch_size];
        p_buff.reset(buff);
    }
    void set_batch_size(int size) {
        p_buf.reset(nullptr);
        p_buff.reset(nullptr);
        batch_size = size;
        buf = new block[batch_size];
        p_buf.reset(buf);
        buff = new bool[batch_size];
        p_buff.reset(buff);
    }

    ~PrimusParty() {
    }
};
#endif

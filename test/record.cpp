#include "protocol/record.h"
#include "backend/backend.h"
#include "cipher/aead.h"
#include <iostream>

using namespace std;
using namespace emp;

int main(int argc, char** argv) {
    int port, party;
    parse_party_and_port(argv, &party, &port);

    NetIO* io = new NetIO(party == ALICE ? nullptr : "127.0.0.1", port);
    setup_backend(io, party);
    auto prot = (PADOParty<NetIO>*)(ProtocolExecution::prot_exec);
    IKNP<NetIO>* cot = prot->ot;

    unsigned char iv[12];
    memset(iv, 11, 12);
    Integer key = Integer(128, 1, ALICE);
    AEAD<NetIO> aead_c(io, cot, key, iv, 12);

    size_t msg_len = 2 * 1024;
    unsigned char* ctxt = new unsigned char[msg_len];
    unsigned char* tag = new unsigned char[16];
    unsigned char* msg = new unsigned char[msg_len];

    memset(ctxt, 0, msg_len);
    memset(tag, 0, 16);
    memset(msg, 22, msg_len);

    unsigned char aad[] = {0xfe, 0xed, 0xfa, 0xce, 0xde, 0xad, 0xbe,
                           0xef, 0xfe, 0xed, 0xfa, 0xce, 0xde};

    size_t aad_len = sizeof(aad);
    Record<NetIO> rd;
    auto start = emp::clock_start();
    rd.enc_record_msg(aead_c, io, ctxt, tag, msg, msg_len, aad, aad_len, party);

    cout << "time: " << emp::time_from(start) << " us" << endl;
    cout << "AND gates: " << dec << CircuitExecution::circ_exec->num_and() << endl;
    cout << "communication: " << io->counter << " Bytes" << endl;
    
    delete[] ctxt;
    delete[] msg;
    delete[] tag;
    finalize_backend();
    delete io;
    return 0;
};
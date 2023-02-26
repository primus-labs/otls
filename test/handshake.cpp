#include "protocol/handshake.h"
#include "backend/backend.h"
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

    EC_GROUP* group = EC_GROUP_new_by_curve_name(NID_X9_62_prime256v1);

    HandShake<NetIO>* hs = new HandShake<NetIO>(io, cot, group);

    EC_POINT* V = EC_POINT_new(group);
    EC_POINT* Tc = EC_POINT_new(group);
    BIGNUM* t = BN_new();

    BIGNUM* ts = BN_new();
    EC_POINT* Ts = EC_POINT_new(hs->group);
    //BN_rand_range(ts, hs->q);
    BN_set_word(ts, 1);
    EC_POINT_mul(hs->group, Ts, ts, NULL, NULL, hs->ctx);

    Integer ms, key, key_c, key_s, iv;

    unsigned char* rc = new unsigned char[32];
    unsigned char* rs = new unsigned char[32];

    unsigned char* ufinc = new unsigned char[finished_msg_bit_length / 8];
    unsigned char* ufins = new unsigned char[finished_msg_bit_length / 8];

    unsigned char* tau_c = new unsigned char[32];
    unsigned char* tau_s = new unsigned char[32];

    unsigned char* iv_oct = new unsigned char[24];

    memset(rc, 0x11, 32);
    memset(rs, 0x22, 32);
    memset(tau_c, 0x33, 32);
    memset(tau_s, 0x44, 32);

    unsigned char aad[] = {0xfe, 0xed, 0xfa, 0xce, 0xde, 0xad, 0xbe, 0xef, 0xfe, 0xed,
                           0xfa, 0xce, 0xde, 0xad, 0xbe, 0xef, 0xab, 0xad, 0xda, 0xd2};

    size_t aad_len = sizeof(aad);

    auto start = emp::clock_start();

    if (party == BOB) {
        hs->compute_pado_VA(V, t, Ts);
    } else {
        hs->compute_client_VB(Tc, V, t, Ts);
    }

    hs->compute_pms_offline(party);

    BIGNUM* pms = BN_new();
    hs->compute_pms_online(pms, V, party);

    hs->compute_master_key(ms, pms, rc, 32, rs, 32, party);
    hs->compute_expansion_keys(key, ms, rc, 32, rs, 32);


    iv.bits.insert(iv.bits.begin(), key.bits.begin(), key.bits.begin() + 96 * 2);
    key_s.bits.insert(key_s.bits.begin(), key.bits.begin() + 2 * 96,
                      key.bits.begin() + 2 * 96 + 128);
    key_c.bits.insert(key_c.bits.begin(), key.bits.begin() + 2 * 96 + 128,
                      key.bits.begin() + 2 * (96 + 128));

    iv.reveal<unsigned char>((unsigned char*)iv_oct, PUBLIC);

    hs->compute_finished_msg(ufinc, ms, client_finished_label, client_finished_label_length,
                             tau_c, 32);

    AEAD<NetIO> aead_c(io, cot, key_c, iv_oct + 12, 12);
    AEAD<NetIO> aead_s(io, cot, key_s, iv_oct, 12);

    unsigned char* ctxt = new unsigned char[finished_msg_bit_length / 8];
    unsigned char* tag = new unsigned char[16];

    hs->encrypt_client_finished_msg(aead_c, ctxt, tag, ufinc, finished_msg_bit_length * 8, aad, aad_len, party);

    cout << "tag: ";
    for (int i = 0; i < 16; i++) {
        cout << hex << (int)tag[i];
    }
    cout << endl;

    cout << "ctxt: ";
    for (int i = 0; i < finished_msg_bit_length / 8; i++) {
        cout << hex << (int)ctxt[i];
    }
    cout << endl;

    hs->compute_finished_msg(ufins, ms, server_finished_label, server_finished_label_length,
                             tau_s, 32);

    // ctxt and tag are received from Server. res should be false
    bool res = hs->decrypt_and_check_server_finished_msg(aead_s, ufins, ctxt, finished_msg_bit_length * 8, tag, aad,
                                                         aad_len, party);
    cout << res << endl;
    cout << "time " << emp::time_from(start) << " us" << endl;
    cout << "AND gates: " << dec << CircuitExecution::circ_exec->num_and() << endl;
    cout << "communication: " << io->counter << " Bytes" << endl;
    EC_POINT_free(V);
    EC_POINT_free(Tc);
    BN_free(t);
    BN_free(ts);
    EC_POINT_free(Ts);

    delete hs;
    delete[] rc;
    delete[] rs;
    delete[] ufinc;
    delete[] ufins;
    delete[] tau_c;
    delete[] tau_s;
    delete[] iv_oct;
    EC_GROUP_free(group);

    finalize_backend();
    delete io;
}

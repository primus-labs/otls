#include "backend/backend.h"
#include "emp-zk/emp-zk.h"
#include <iostream>
#include "emp-tool/emp-tool.h"
#include "protocol/handshake.h"
#include "protocol/record.h"
#include "protocol/com_conv.h"
#include "protocol/aead.h"
#include "protocol/aead_izk.h"
#include "protocol/post_record.h"
#if defined(__linux__)
#include <sys/time.h>
#include <sys/resource.h>
#elif defined(__APPLE__)
#include <unistd.h>
#include <sys/resource.h>
#include <mach/mach.h>
#endif

using namespace std;
using namespace emp;

const size_t QUERY_BYTE_LEN = 2 * 1024;
const size_t RESPONSE_BYTE_LEN = 2 * 1024;

const int threads = 1;

void full_protocol_offline() {
    EC_GROUP* group = EC_GROUP_new_by_curve_name(NID_X9_62_prime256v1);

    unsigned char* rc = new unsigned char[32];
    unsigned char* rs = new unsigned char[32];

    unsigned char* tau_c = new unsigned char[32];
    unsigned char* tau_s = new unsigned char[32];

    memset(rc, 0x11, 32);
    memset(rs, 0x22, 32);
    memset(tau_c, 0x33, 32);
    memset(tau_s, 0x44, 32);

    HandShakeOffline* hs_offline = new HandShakeOffline(group);
    hs_offline->compute_extended_master_key(rc, 32);
    hs_offline->compute_expansion_keys(rc, 32, rs, 32);
    hs_offline->compute_client_finished_msg(client_finished_label,
                                            client_finished_label_length, tau_c, 32);
    hs_offline->compute_server_finished_msg(server_finished_label,
                                            server_finished_label_length, tau_s, 32);

    AEADOffline* aead_c_offline = new AEADOffline(hs_offline->client_write_key);
    AEADOffline* aead_s_offline = new AEADOffline(hs_offline->server_write_key);

    RecordOffline* rd_offline = new RecordOffline();

    hs_offline->encrypt_client_finished_msg(aead_c_offline, 12);
    hs_offline->decrypt_server_finished_msg(aead_s_offline, 12);

    rd_offline->encrypt(aead_c_offline, QUERY_BYTE_LEN);

    delete hs_offline;
    delete aead_c_offline;
    delete aead_s_offline;
}
template <typename IO>
void full_protocol(HandShake<IO>* hs, IO* io, COT<IO>* cot, int party) {
    EC_GROUP* group = EC_GROUP_new_by_curve_name(NID_X9_62_prime256v1);
    //HandShake<NetIO>* hs = new HandShake<NetIO>(io, cot, group);

    EC_POINT* V = EC_POINT_new(group);
    EC_POINT* Tc = EC_POINT_new(group);
    BIGNUM* t = BN_new();

    BIGNUM* ts = BN_new();
    EC_POINT* Ts = EC_POINT_new(hs->group);
    BN_set_word(ts, 2);
    EC_POINT_mul(hs->group, Ts, ts, NULL, NULL, hs->ctx);

    unsigned char* rc = new unsigned char[32];
    unsigned char* rs = new unsigned char[32];

    unsigned char* ufinc = new unsigned char[finished_msg_length];
    unsigned char* ufins = new unsigned char[finished_msg_length];

    unsigned char* tau_c = new unsigned char[32];
    unsigned char* tau_s = new unsigned char[32];

    unsigned char* cmsg = new unsigned char[QUERY_BYTE_LEN];
    unsigned char* smsg = new unsigned char[RESPONSE_BYTE_LEN];

    memset(rc, 0x11, 32);
    memset(rs, 0x22, 32);
    memset(tau_c, 0x33, 32);
    memset(tau_s, 0x44, 32);
    memset(cmsg, 0x55, QUERY_BYTE_LEN);
    memset(smsg, 0x66, QUERY_BYTE_LEN);

    unsigned char aad[] = {0xfe, 0xed, 0xfa, 0xce, 0xde, 0xad, 0xbe, 0xef, 0xfe, 0xed,
                           0xfa, 0xce, 0xde, 0xad, 0xbe, 0xef, 0xab, 0xad, 0xda, 0xd2};

    size_t aad_len = sizeof(aad);
    BIGNUM* pms = BN_new();
    BIGNUM* full_pms = BN_new();
    unsigned char iv_c[12], iv_s[12];

    // hs->compute_pms_offline(party);

    auto rounds = io->rounds;
    auto start = emp::clock_start();
    if (party == BOB) {
        hs->compute_pado_VA(V, Ts);
    } else {
        hs->compute_client_VB(Tc, V, Ts);
    }
    cout << "VA/VB rounds: " << io->rounds - rounds << endl;
    rounds = io->rounds;
    hs->compute_pms_online(pms, V, party);
    cout << "pms rounds: " << io->rounds - rounds << endl;
    rounds = io->rounds;
    //hs->compute_master_key(pms, rc, 32, rs, 32);

    // Use session_hash instead of rc!
    hs->compute_extended_master_key(pms, rc, 32);
    cout << "master key rounds: " << io->rounds - rounds << endl;
    rounds = io->rounds;
    hs->compute_expansion_keys(rc, 32, rs, 32);
    cout << "expansion key rounds: " << io->rounds - rounds << endl;
    rounds = io->rounds;

    hs->compute_client_finished_msg(client_finished_label, client_finished_label_length, tau_c,
                                    32);
    cout << "client finished rounds: " << io->rounds - rounds << endl;
    rounds = io->rounds;
    hs->compute_server_finished_msg(server_finished_label, server_finished_label_length, tau_s,
                                    32);
    cout << "server finished rounds: " << io->rounds - rounds << endl;
    rounds = io->rounds;

    // padding the last 8 bytes of iv_c and iv_s according to TLS!
    memcpy(iv_c, hs->client_write_iv, iv_length);
    memset(iv_c + iv_length, 0x11, 8);
    memcpy(iv_s, hs->server_write_iv, iv_length);
    memset(iv_s + iv_length, 0x22, 8);
    AEAD<IO>* aead_c = new AEAD<IO>(io, cot, hs->client_write_key);
    AEAD<IO>* aead_s = new AEAD<IO>(io, cot, hs->server_write_key);

    Record<IO>* rd = new Record<IO>;
    cout << "constructors rounds: " << io->rounds - rounds << endl;
    rounds = io->rounds;
    unsigned char* finc_ctxt = new unsigned char[finished_msg_length];
    unsigned char* finc_tag = new unsigned char[tag_length];
    unsigned char* msg = new unsigned char[finished_msg_length];

    // Use correct message instead of hs->client_ufin!
    hs->encrypt_client_finished_msg(aead_c, finc_ctxt, finc_tag, hs->client_ufin, 12, aad,
                                    aad_len, iv_c, 12, party);

    cout << "enc client finished rounds: " << io->rounds - rounds << endl;
    rounds = io->rounds;
    // Use correct ciphertext instead of finc_ctxt!
    hs->decrypt_server_finished_msg(aead_s, msg, finc_ctxt, finished_msg_length, finc_tag, aad,
                                    aad_len, iv_s, 12, party);
    cout << "dec server finished rounds: " << io->rounds - rounds << endl;
    // cout << "handshake time: " << emp::time_from(start) << " us" << endl;

    unsigned char* cctxt = new unsigned char[QUERY_BYTE_LEN];
    unsigned char* ctag = new unsigned char[tag_length];

    unsigned char* sctxt = new unsigned char[RESPONSE_BYTE_LEN];
    unsigned char* stag = new unsigned char[tag_length];
    start = emp::clock_start();

    // the client encrypts the first message, and sends to the server.
    rd->encrypt(aead_c, io, cctxt, ctag, cmsg, QUERY_BYTE_LEN, aad, aad_len, iv_c, 12, party);
    // cout << "record time: " << emp::time_from(start) << " us" << endl;
    // prove handshake in post-record phase.
    start = emp::clock_start();
    switch_to_zk();
    PostRecord<IO>* prd = new PostRecord<IO>(io, hs, aead_c, aead_s, rd, party);
    prd->reveal_pms(Ts);
    // Use correct finc_ctxt, fins_ctxt, iv_c, iv_s according to TLS!
    prd->prove_and_check_handshake(finc_ctxt, finished_msg_length, finc_ctxt,
                                   finished_msg_length, rc, 32, rs, 32, tau_c, 32, tau_s, 32,
                                   iv_c, 12, iv_s, 12, rc, 32);
    Integer prd_cmsg, prd_cmsg2, prd_smsg, prd_smsg2, prd_cz0, prd_c2z0, prd_sz0, prd_s2z0;
    prd->prove_record_client(prd_cmsg, prd_cz0, cctxt, QUERY_BYTE_LEN, iv_c, 12);
    prd->prove_record_server_last(prd_smsg2, prd_s2z0, cctxt, RESPONSE_BYTE_LEN, iv_s, 12);

    // Use correct finc_ctxt and fins_ctxt!
    prd->finalize_check(finc_ctxt, finc_tag, 12, aad, finc_ctxt, finc_tag, 12, aad, {prd_cz0},
                        {cctxt}, {ctag}, {QUERY_BYTE_LEN}, {aad}, 1, {prd_sz0}, {sctxt},
                        {stag}, {RESPONSE_BYTE_LEN}, {aad}, 1, aad_len);

    sync_zk_gc<IO>();
    switch_to_gc();
    // cout << "post record: " << emp::time_from(start) << " us" << endl;
    EC_POINT_free(V);
    EC_POINT_free(Tc);
    BN_free(t);
    BN_free(ts);
    BN_free(pms);
    BN_free(full_pms);
    EC_POINT_free(Ts);

    // delete hs;
    delete[] rc;
    delete[] rs;
    delete[] ufinc;
    delete[] ufins;
    delete[] tau_c;
    delete[] tau_s;
    delete[] finc_ctxt;
    delete[] finc_tag;
    delete[] msg;
    delete[] cmsg;
    delete[] smsg;

    delete aead_c;
    delete aead_s;
    delete rd;
    delete prd;
    EC_GROUP_free(group);
}

int main(int argc, char** argv) {
    int port, party;
    parse_party_and_port(argv, &party, &port);
    NetIO* io = new NetIO(party == ALICE ? nullptr : "127.0.0.1", port);
    BoolIO<NetIO>* ios[threads];
    for (int i = 0; i < threads; i++)
        ios[i] = new BoolIO<NetIO>(io, party == ALICE);

    EC_GROUP* group = EC_GROUP_new_by_curve_name(NID_X9_62_prime256v1);

    auto start = emp::clock_start();
    auto comm = io->counter;
    auto rounds = io->rounds;
    // setup_protocol<NetIO>(io, ios, threads, party, true);
    setup_protocol<NetIO>(io, ios, threads, party);

    cout << "setup time: " << emp::time_from(start) << " us" << endl;
    cout << "setup comm: " << io->counter << endl;
    cout << "setup rounds: " << io->rounds << endl;

    start = clock_start();
    comm = io->counter;
    rounds = io->rounds;

    auto prot = (PADOParty<NetIO>*)(gc_prot_buf);
    IKNP<NetIO>* cot = prot->ot;
    HandShake<NetIO>* hs = new HandShake<NetIO>(io, cot, group);

    //full_protocol_offline();
    hs->compute_pms_offline(party);

    //switch_to_online<NetIO>(party);
    cout << "offline time: " << emp::time_from(start) << " us" << endl;
    cout << "offline comm: " << io->counter - comm << endl;
    cout << "offline rounds: " << io->rounds - rounds << endl;

    start = emp::clock_start();
    comm = io->counter;
    rounds = io->rounds;
    full_protocol<NetIO>(hs, io, cot, party);
    cout << "online time: " << emp::time_from(start) << " us" << endl;
    cout << "online comm: " << io->counter - comm << endl;
    cout << "onlie rounds: " << io->rounds - rounds << endl;

    cout << "gc AND gates: " << dec << gc_circ_buf->num_and() << endl;
    cout << "zk AND gates: " << dec << zk_circ_buf->num_and() << endl;
    finalize_protocol();

    bool cheat = CheatRecord::cheated();
    if (cheat)
        error("cheat!\n");

#if defined(__linux__)
    struct rusage rusage;
    if (!getrusage(RUSAGE_SELF, &rusage))
        std::cout << "[Linux]Peak resident set size: " << (size_t)rusage.ru_maxrss
                  << std::endl;
    else
        std::cout << "[Linux]Query RSS failed" << std::endl;
#elif defined(__APPLE__)
    struct mach_task_basic_info info;
    mach_msg_type_number_t count = MACH_TASK_BASIC_INFO_COUNT;
    if (task_info(mach_task_self(), MACH_TASK_BASIC_INFO, (task_info_t)&info, &count) ==
        KERN_SUCCESS)
        std::cout << "[Mac]Peak resident set size: " << (size_t)info.resident_size_max
                  << std::endl;
    else
        std::cout << "[Mac]Query RSS failed" << std::endl;
#endif
    cout << "comm: " << ((io->counter) * 1.0) / 1024 << " KBytes" << endl;
    delete io;
    for (int i = 0; i < threads; i++) {
        delete ios[i];
    }
    // delete io1;
    return 0;
}

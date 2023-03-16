#include "protocol/post_record.h"
#include "protocol/record.h"
#include "emp-tool/emp-tool.h"
#include "backend/switch.h"

using namespace emp;

template <typename IO>
void post_record_test(IO* io, COT<IO>* cot, int party) {
    EC_GROUP* group = EC_GROUP_new_by_curve_name(NID_X9_62_prime256v1);
    HandShake<NetIO>* hs = new HandShake<NetIO>(io, cot, group);

    EC_POINT* V = EC_POINT_new(group);
    EC_POINT* Tc = EC_POINT_new(group);
    BIGNUM* t = BN_new();

    BIGNUM* ts = BN_new();
    EC_POINT* Ts = EC_POINT_new(hs->group);
    BN_set_word(ts, 1);
    EC_POINT_mul(hs->group, Ts, ts, NULL, NULL, hs->ctx);

    unsigned char* rc = new unsigned char[32];
    unsigned char* rs = new unsigned char[32];

    unsigned char* ufinc = new unsigned char[finished_msg_length];
    unsigned char* ufins = new unsigned char[finished_msg_length];

    unsigned char* tau_c = new unsigned char[32];
    unsigned char* tau_s = new unsigned char[32];

    unsigned char* cmsg = new unsigned char[64];
    unsigned char* smsg = new unsigned char[64];

    memset(rc, 0x11, 32);
    memset(rs, 0x22, 32);
    memset(tau_c, 0x33, 32);
    memset(tau_s, 0x44, 32);
    memset(cmsg, 0x55, 64);
    memset(smsg, 0x66, 64);

    unsigned char aad[] = {0xfe, 0xed, 0xfa, 0xce, 0xde, 0xad, 0xbe, 0xef, 0xfe, 0xed,
                           0xfa, 0xce, 0xde, 0xad, 0xbe, 0xef, 0xab, 0xad, 0xda, 0xd2};

    size_t aad_len = sizeof(aad);

    if (party == BOB) {
        hs->compute_pado_VA(V, Ts);
    } else {
        hs->compute_client_VB(Tc, V, Ts);
    }

    hs->compute_pms_offline(party);

    BIGNUM* pms = BN_new();
    BIGNUM* full_pms = BN_new();
    hs->compute_pms_online(pms, V, party);

    hs->compute_master_key(pms, rc, 32, rs, 32);

    hs->compute_expansion_keys(rc, 32, rs, 32);

    hs->compute_client_finished_msg(client_finished_label, client_finished_label_length, tau_c,
                                    32);
    hs->compute_server_finished_msg(server_finished_label, server_finished_label_length, tau_s,
                                    32);

    AEAD<IO>* aead_c = new AEAD<IO>(io, cot, hs->client_write_key, hs->iv_oct + 12, 12);
    AEAD<IO>* aead_s = new AEAD<IO>(io, cot, hs->server_write_key, hs->iv_oct, 12);

    Record<IO>* rd = new Record<IO>;

    // These AEAD instances simulate the server side.
    AEAD<IO>* aead_c_server = new AEAD<IO>(io, cot, hs->client_write_key, hs->iv_oct + 12, 12);

    AEAD<IO>* aead_s_server = new AEAD<IO>(io, cot, hs->server_write_key, hs->iv_oct, 12);

    unsigned char* finc_ctxt = new unsigned char[finished_msg_length];
    unsigned char* finc_tag = new unsigned char[tag_length];
    unsigned char* msg = new unsigned char[finished_msg_length];

    hs->encrypt_client_finished_msg(aead_c, finc_ctxt, finc_tag, aad, aad_len, party);
    bool res = aead_c_server->decrypt(io, msg, finc_ctxt, finished_msg_length, finc_tag, aad,
                                      aad_len, party);
    cout << "res: " << res << endl;
    for (int i = 0; i < finished_msg_length; i++)
        cout << hex << (int)msg[i];
    cout << endl;

    for (int i = 0; i < finished_msg_length; i++)
        cout << hex << (int)hs->client_ufin[i];
    cout << endl;

    unsigned char* fins_ctxt = new unsigned char[finished_msg_length];
    unsigned char* fins_tag = new unsigned char[tag_length];
    // unsigned char* msg2 = new unsigned char[finished_msg_length];

    // simulate the server
    aead_s_server->encrypt(io, fins_ctxt, fins_tag, hs->server_ufin, finished_msg_length, aad,
                           aad_len, party);

    bool res2 = hs->decrypt_and_check_server_finished_msg(aead_s, fins_ctxt, fins_tag, aad,
                                                          aad_len, party);
    cout << "res2: " << res2 << endl;

    unsigned char* cctxt = new unsigned char[64];
    unsigned char* ctag = new unsigned char[tag_length];

    unsigned char* sctxt = new unsigned char[64];
    unsigned char* stag = new unsigned char[tag_length];

    unsigned char* cctxt2 = new unsigned char[64];
    unsigned char* ctag2 = new unsigned char[tag_length];

    unsigned char* sctxt2 = new unsigned char[64];
    unsigned char* stag2 = new unsigned char[tag_length];

    // the client encrypts the first message, and sends to the server.
    rd->encrypt(aead_c, io, cctxt, ctag, cmsg, 64, aad, aad_len, party);

    // simulate the server, send sctxt and stag to the client.
    aead_s_server->encrypt(io, sctxt, stag, smsg, 64, aad, aad_len, party, true);

    // the client decrypts the first message from the server.
    rd->decrypt(aead_s, io, smsg, sctxt, 64, stag, aad, aad_len, party);

    // the client encrypts the second message, and sends to the server.
    rd->encrypt(aead_c, io, cctxt2, ctag2, cmsg, 64, aad, aad_len, party);

    // simulate the server, send sctxt2, stag2 to the client.
    aead_s_server->encrypt(io, sctxt2, stag2, smsg, 64, aad, aad_len, party, true);

    // prove handshake in post-record phase.
    switch_to_zk();
    PostRecord<IO>* prd = new PostRecord<IO>(io, hs, aead_c, aead_s, rd, party);
    prd->reveal_pms();
    prd->prove_and_check_handshake(finc_ctxt, fins_ctxt, rc, 32, rs, 32, tau_c, 32, tau_s, 32);
    Integer prd_cmsg, prd_cmsg2, prd_smsg, prd_smsg2, prd_cz0, prd_c2z0, prd_sz0, prd_s2z0;
    prd->prove_record_client(prd_cmsg, prd_cz0, cctxt, 64);
    prd->prove_record_server(prd_smsg, prd_sz0, sctxt, 64);
    prd->prove_record_client(prd_cmsg2, prd_c2z0, cctxt2, 64);
    prd->prove_record_server_last(prd_smsg2, prd_s2z0, sctxt2, 64);

    bool res3 = prd->finalize_check(
      finc_ctxt, finc_tag, aad, fins_ctxt, fins_tag, aad, {prd_cz0, prd_c2z0}, {cctxt, cctxt2},
      {ctag, ctag2}, {64, 64}, {aad, aad}, 2, {prd_sz0, prd_s2z0}, {sctxt, sctxt2},
      {stag, stag2}, {64, 64}, {aad, aad}, 2, aad_len);
    cout << "res3: " << res3 << endl;
    sync_zk_gc<IO>();
    switch_to_gc();

    EC_POINT_free(V);
    EC_POINT_free(Tc);
    BN_free(t);
    BN_free(ts);
    BN_free(pms);
    BN_free(full_pms);
    EC_POINT_free(Ts);

    delete hs;
    delete[] rc;
    delete[] rs;
    delete[] ufinc;
    delete[] ufins;
    delete[] tau_c;
    delete[] tau_s;
    delete[] finc_ctxt;
    delete[] fins_ctxt;
    delete[] fins_tag;
    // delete[] msg2;
    delete[] finc_tag;
    delete[] msg;
    delete[] cmsg;
    delete[] smsg;

    delete aead_c;
    delete aead_s;
    delete aead_c_server;
    delete aead_s_server;
    delete rd;
    delete prd;
    EC_GROUP_free(group);
}

const int threads = 1;
int main(int argc, char** argv) {
    int port, party;
    parse_party_and_port(argv, &party, &port);
    NetIO* io = new NetIO(party == ALICE ? nullptr : "127.0.0.1", port);
    BoolIO<NetIO>* ios[threads];
    for (int i = 0; i < threads; i++)
        ios[i] = new BoolIO<NetIO>(io, party == ALICE);

    setup_protocol<NetIO>(io, ios, threads, party);

    auto prot = (PADOParty<NetIO>*)(ProtocolExecution::prot_exec);
    IKNP<NetIO>* cot = prot->ot;
    post_record_test<NetIO>(io, cot, party);
    finalize_protocol();

    bool cheat = CheatRecord::cheated();
    if (cheat)
        error("cheat!\n");

    delete io;
    for (int i = 0; i < threads; i++) {
        delete ios[i];
    }
    return 0;
}
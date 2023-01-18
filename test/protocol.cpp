#include "backend/backend.h"
#include "emp-zk/emp-zk.h"
#include <iostream>
#include "emp-tool/emp-tool.h"
#include "protocol/izk.h"
#include "protocol/handshake.h"
#include "protocol/record.h"
#include "protocol/com_conv.h"
#include "cipher/aead.h"
#include "cipher/aead_izk.h"

using namespace std;
using namespace emp;

const size_t QUERY_BYTE_LEN = 2 * 1024;
const size_t RESPONSE_BYTE_LEN = 2 * 1024;

const int threads = 1;

void hs_query_resp_gc(NetIO* io, EC_GROUP* group, int party) {
    setup_backend(io, party);
    auto prot = (PADOParty<NetIO>*)(ProtocolExecution::prot_exec);
    IKNP<NetIO>* cot = prot->ot;
    HandShake<NetIO>* hs = new HandShake<NetIO>(io, cot, group);

    EC_POINT* V = EC_POINT_new(group);
    EC_POINT* Tc = EC_POINT_new(group);
    BIGNUM* t = BN_new();

    BIGNUM* ts = BN_new();
    EC_POINT* Ts = EC_POINT_new(hs->group);
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

    unsigned char aad[] = {0xfe, 0xed, 0xfa, 0xce, 0xde, 0xad, 0xbe,
                           0xef, 0xfe, 0xed, 0xfa, 0xce, 0xde};

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

    hs->compute_master_and_expansion_keys(ms, key, pms, rc, 32, rs, 32, party);

    iv.bits.insert(iv.bits.begin(), key.bits.begin(), key.bits.begin() + 96 * 2);
    key_s.bits.insert(key_s.bits.begin(), key.bits.begin() + 2 * 96,
                      key.bits.begin() + 2 * 96 + 128);
    key_c.bits.insert(key_c.bits.begin(), key.bits.begin() + 2 * 96 + 128,
                      key.bits.begin() + 2 * (96 + 128));

    iv.reveal<unsigned char>((unsigned char*)iv_oct, PUBLIC);

    AEAD<NetIO> aead_c(io, cot, key_c, iv_oct + 12, 12);
    AEAD<NetIO> aead_s(io, cot, key_s, iv_oct, 12);

    unsigned char* ctxt = new unsigned char[finished_msg_bit_length / 8];
    unsigned char* tag = new unsigned char[16];

    hs->compute_finished_msg(ufinc, ms, client_finished_label, client_finished_label_length,
                             tau_c, 32);
    hs->encrypt_client_finished_msg(aead_c, ctxt, tag, ufinc, aad, aad_len, party);

    //hs->compute_finished_msg(ufins, ms, server_finished_label, server_finished_label_length,
    //                         tau_s, 32);
    //hs->decrypt_and_check_server_finished_msg(aead_s, ufins, ctxt, tag, aad, aad_len, party);
    auto hs_gc_time = emp::time_from(start);
    cout << "handshake GC time: " << (hs_gc_time * 1.0) / 1000 << " ms" << endl;

    auto hs_gc_gates = CircuitExecution::circ_exec->num_and();
    cout << "handshake gates: " << hs_gc_gates << endl;

    auto hs_gc_comm = io->counter;
    cout << "handshake comm.: " << (hs_gc_comm)*1.0 / 1024 << " KBytes" << endl;
    Record<NetIO>* rd = new Record<NetIO>;

    unsigned char query_msg[QUERY_BYTE_LEN];
    unsigned char query_ctxt[QUERY_BYTE_LEN];
    memset(query_msg, 11, QUERY_BYTE_LEN);
    memset(query_ctxt, 0, QUERY_BYTE_LEN);

    auto start1 = emp::clock_start();
    rd->enc_record_msg(aead_c, io, query_ctxt, tag, query_msg, QUERY_BYTE_LEN, aad, aad_len,
                       party);
    auto rd_gc_time = emp::time_from(start1);
    cout << "record GC time: " << (rd_gc_time)*1.0 / 1000 << " ms" << endl;

    auto rd_gc_gates = CircuitExecution::circ_exec->num_and() - hs_gc_gates;
    cout << "record gates: " << rd_gc_gates << endl;

    auto rd_gc_comm = io->counter - hs_gc_comm;
    cout << "record comm.: " << (rd_gc_comm * 1.0) / 1024 << " KBytes" << endl;
    finalize_backend();

    EC_POINT_free(V);
    EC_POINT_free(Tc);
    BN_free(t);
    BN_free(ts);
    EC_POINT_free(Ts);

    delete hs;
    delete rd;
    delete[] rc;
    delete[] rs;
    delete[] ufinc;
    delete[] ufins;
    delete[] tau_c;
    delete[] tau_s;
    delete[] iv_oct;
}

void hs_query_resp_izk(BoolIO<NetIO>* ios[threads],
                       EC_GROUP* group,
                       vector<block>& out,
                       int party) {
    auto start = emp::clock_start();
    setup_zk_bool<BoolIO<NetIO>>(ios, threads, party);
    IZK<NetIO>* izk = new IZK<NetIO>(group);

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

    BIGNUM* pms_a = BN_new();
    BIGNUM* pms_b = BN_new();

    BN_rand_range(pms_a, izk->q);
    BN_rand_range(pms_b, izk->q);

    izk->prove_master_and_expansion_keys(ms, key, pms_a, pms_b, rc, 32, rs, 32, party);

    iv.bits.insert(iv.bits.begin(), key.bits.begin(), key.bits.begin() + 96 * 2);
    key_s.bits.insert(key_s.bits.begin(), key.bits.begin() + 2 * 96,
                      key.bits.begin() + 2 * 96 + 128);
    key_c.bits.insert(key_c.bits.begin(), key.bits.begin() + 2 * 96 + 128,
                      key.bits.begin() + 2 * (96 + 128));

    iv.reveal<unsigned char>((unsigned char*)iv_oct, PUBLIC);

    izk->prove_compute_finished_msg(ufinc, ms, client_finished_label,
                                    client_finished_label_length, tau_c, 32);

    AEAD_IZK aead_c(key_c, iv_oct + 12, 12);
    AEAD_IZK aead_s(key_s, iv_oct, 12);

    Integer ctxt, msg;
    izk->prove_encrypt_client_finished_msg(aead_c, ctxt, finished_msg_bit_length);

    izk->prove_compute_finished_msg(ufins, ms, server_finished_label,
                                    server_finished_label_length, tau_s, 32);

    izk->prove_decrypt_server_finished_msg(aead_s, msg, finished_msg_bit_length);
    auto hs_izk_time = emp::time_from(start);
    cout << "handshake izk time: " << (hs_izk_time * 1.0) / 1000 << " ms" << endl;

    auto hs_izk_gates = CircuitExecution::circ_exec->num_and();
    cout << "handshake izk gates: " << hs_izk_gates << endl;

    auto hs_izk_comm = ios[0]->counter;
    cout << "handshake izk comm.: " << (hs_izk_comm * 1.0) / 1024 << " KBytes" << endl;

    auto start1 = emp::clock_start();
    izk->prove_encrypt_record_msg(aead_c, ctxt, QUERY_BYTE_LEN * 8);
    izk->prove_decrypt_record_msg(aead_s, msg, RESPONSE_BYTE_LEN * 8);
    auto rd_izk_time = emp::time_from(start1);
    cout << "record izk time: " << (rd_izk_time * 1.0) / 1000 << " ms" << endl;

    auto rd_izk_gates = CircuitExecution::circ_exec->num_and() - hs_izk_gates;
    cout << "record izk gates: " << rd_izk_gates << endl;

    auto rd_izk_comm = ios[0]->counter - hs_izk_comm;
    cout << "record izk comm.: " << (rd_izk_comm * 1.0) / 1024 << " KBytes" << endl;

    // cout << "time: " << emp::time_from(start) << " us" << endl;
    // cout << "AND gates: " << CircuitExecution::circ_exec->num_and() << endl;
    ios[0]->flush();
    // cout << "communication: " << ios[0]->counter << " Bytes" << endl;

    for (int i = 3 * 128; i < ctxt.size(); i++) {
        out.push_back(ctxt[i].bit);
    }
    for (int i = 3 * 128; i < msg.size(); i++) {
        out.push_back(msg[i].bit);
    }
    bool cheat = finalize_zk_bool<BoolIO<NetIO>>();
    if (cheat)
        error("cheat!\n");
    BN_free(pms_a);
    BN_free(pms_b);

    delete[] rc;
    delete[] rs;
    delete[] ufinc;
    delete[] ufins;
    delete[] tau_c;
    delete[] tau_s;
    delete[] iv_oct;
    delete izk;
}

void com_conv(NetIO* io, EC_GROUP* group, vector<block>& input, int party) {
    setup_backend(io, party);
    auto prot1 = (PADOParty<NetIO>*)(ProtocolExecution::prot_exec);
    IKNP<NetIO>* cot = prot1->ot;
    EC_POINT* h = EC_POINT_new(group);
    EC_POINT_copy(h, EC_GROUP_get0_generator(group));
    PedersenComm pc(h, group);
    BIGNUM* q = BN_new();
    BN_copy(q, EC_GROUP_get0_order(group));
    if(party == BOB)
		cot->Delta=zero_block;
    ComConv<NetIO> conv(io, cot, q);
	

    vector<EC_POINT*> coms;
    vector<BIGNUM*> rnds;

    size_t chunk_len = (input.size() + BN_num_bits(q) - 1) / BN_num_bits(q);
    coms.resize(chunk_len);
    rnds.resize(chunk_len);
    for (int i = 0; i < chunk_len; i++) {
        coms[i] = EC_POINT_new(group);
        rnds[i] = BN_new();
    }

    auto start = emp::clock_start();
    if (party == BOB) {
        conv.compute_com_send(coms, input, pc);
        auto cc_time = emp::time_from(start);
        cout << "com conv time: " << (cc_time * 1.0) / 1000 << " ms" << endl;
        cout << "com conv comm. " << ((io->counter) * 1.0) / 1024 << " KBytes" << endl;
    } else {
        conv.compute_com_recv(coms, rnds, input, pc);
        auto cc_time = emp::time_from(start);
        cout << "com conv time: " << (cc_time * 1.0) / 1000 << " ms" << endl;
        cout << "com conv comm. " << ((io->counter) * 1.0) / 1024 << " KBytes" << endl;
    }

    finalize_backend();
}
int main(int argc, char** argv) {
    int port, party;
    parse_party_and_port(argv, &party, &port);

    EC_GROUP* group = EC_GROUP_new_by_curve_name(NID_X9_62_prime256v1);

    NetIO* io = new NetIO(party == ALICE ? nullptr : "127.0.0.1", port);

    // GC
    hs_query_resp_gc(io, group, party);

    BoolIO<NetIO>* ios[threads];
    for (int i = 0; i < threads; ++i)
        ios[i] = new BoolIO<NetIO>(io, party == ALICE);

    vector<block> out;

    // IZK
    hs_query_resp_izk(ios, group, out, party);
    for (int i = 0; i < threads; ++i) {
        delete ios[i]->io;
        delete ios[i];
    }

    // vector<block> out(QUERY_BYTE_LEN * 8 + RESPONSE_BYTE_LEN * 8);
    // for (int i = 0; i < out.size(); i++)
    //     out[i] = zero_block;

    NetIO* io1 = new NetIO(party == ALICE ? nullptr : "127.0.0.1", port);

    // Com conversion
    com_conv(io1, group, out, party);

    EC_GROUP_free(group);

    delete io1;
    return 0;
}
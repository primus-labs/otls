#include "cipher/aead_izk.h"
#include "emp-tool/emp-tool.h"
#include "cipher/utils.h"
#include "backend/backend.h"
#include "backend/switch.h"
#include "backend/checkzero.h"

using namespace emp;

template <typename IO>
void it_mac_add_test(IO* io, int party) {
    Integer a(128, 1, ALICE);
    block A = integer_to_block(a);

    switch_to_zk();
    Integer aa(128, 1, ALICE);
    Integer b(128, &A, ALICE);

    itmac_hom_add_check<IO>(aa, b, party, A);
    sync_zk_gc<IO>();
    switch_to_gc();

    PRG prg;
    int len = 4;
    unsigned char* buf = new unsigned char[len];
    unsigned char* buff = new unsigned char[len];
    prg.random_data(buf, len);

    Integer ac(len * 8, buf, ALICE);

    integer_to_chars(buff, ac);

    switch_to_zk();
    Integer aac(len * 8, buf, ALICE);
    reverse(buff, buff + len);
    Integer bc(len * 8, buff, ALICE);

    itmac_hom_add_check<IO>(aac, bc, party, buff, len);
    sync_zk_gc<IO>();
    switch_to_gc();

    delete[] buf;
    delete[] buff;
}

template <typename IO>
void aead_enc_garble_then_prove_test(IO* io, COT<IO>* ot, int party, bool sec_type = false) {
    unsigned char keyc[] = {0xfe, 0xff, 0xe9, 0x92, 0x86, 0x65, 0x73, 0x1c,
                            0x6d, 0x6a, 0x8f, 0x94, 0x67, 0x30, 0x83, 0x08};
    reverse(keyc, keyc + 16);
    Integer key(128, keyc, ALICE);

    unsigned char msg[] = {0xd9, 0x31, 0x32, 0x25, 0xf8, 0x84, 0x06, 0xe5, 0xa5, 0x59,
                           0x09, 0xc5, 0xaf, 0xf5, 0x26, 0x9a, 0x86, 0xa7, 0xa9, 0x53,
                           0x15, 0x34, 0xf7, 0xda, 0x2e, 0x4c, 0x30, 0x3d, 0x8a, 0x31,
                           0x8a, 0x72, 0x1c, 0x3c, 0x0c, 0x95, 0x95, 0x68, 0x09, 0x53,
                           0x2f, 0xcf, 0x0e, 0x24, 0x49, 0xa6, 0xb5, 0x25, 0xb1, 0x6a,
                           0xed, 0xf5, 0xaa, 0x0d, 0xe6, 0x57, 0xba, 0x63, 0x7b, 0x39};
    size_t msg_len = sizeof(msg);
    unsigned char aad[] = {0xfe, 0xed, 0xfa, 0xce, 0xde, 0xad, 0xbe, 0xef, 0xfe, 0xed,
                           0xfa, 0xce, 0xde, 0xad, 0xbe, 0xef, 0xab, 0xad, 0xda, 0xd2};

    size_t aad_len = sizeof(aad);

    unsigned char iv[] = {0xca, 0xfe, 0xba, 0xbe, 0xfa, 0xce,
                          0xdb, 0xad, 0xde, 0xca, 0xf8, 0x88};

    size_t iv_len = sizeof(iv);

    unsigned char* ctxt = new unsigned char[msg_len];
    unsigned char tag[16];

    auto start = emp::clock_start();

    // AEAD encryption with GC
    AEAD<IO>* aead = new AEAD<IO>(io, ot, key, iv, iv_len);
    aead->encrypt(io, ctxt, tag, msg, msg_len, aad, aad_len, party, sec_type);

    cout << "time: " << emp::time_from(start) << " us" << endl;
    cout << "tag: ";
    for (int i = 0; i < 16; i++) {
        cout << hex << (int)tag[i];
    }
    cout << endl;

    cout << "ctxt: ";
    for (int i = 0; i < msg_len; i++) {
        cout << hex << (int)ctxt[i];
    }
    cout << endl;

    // Prove with IZK
    start = emp::clock_start();
    switch_to_zk();
    Integer key_zk(128, keyc, ALICE);
    AEAD_Proof<IO>* aead_proof = new AEAD_Proof<IO>(aead, key_zk, iv, iv_len, party);
    Integer msg_zk;
    aead_proof->prove_aead(msg_zk, ctxt, msg_len, sec_type);
    if (sec_type) {
        cout << msg_zk.reveal<string>() << endl;
    }
    sync_zk_gc<IO>();
    switch_to_gc();
    cout << "prove time: " << time_from(start) << endl;
    delete aead;
    delete aead_proof;
    delete[] ctxt;
}

template <typename IO>
void aead_dec_garble_then_prove_test(IO* io, COT<IO>* ot, int party, bool sec_type = false) {
    unsigned char keyc[] = {0xfe, 0xff, 0xe9, 0x92, 0x86, 0x65, 0x73, 0x1c,
                            0x6d, 0x6a, 0x8f, 0x94, 0x67, 0x30, 0x83, 0x08};
    reverse(keyc, keyc + 16);
    Integer key(128, keyc, ALICE);

    unsigned char msg[] = {0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                           0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                           0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                           0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                           0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                           0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00};
    size_t msg_len = sizeof(msg);

    unsigned char aad[] = {0xfe, 0xed, 0xfa, 0xce, 0xde, 0xad, 0xbe, 0xef, 0xfe, 0xed,
                           0xfa, 0xce, 0xde, 0xad, 0xbe, 0xef, 0xab, 0xad, 0xda, 0xd2};

    size_t aad_len = sizeof(aad);

    unsigned char iv[] = {0xca, 0xfe, 0xba, 0xbe, 0xfa, 0xce,
                          0xdb, 0xad, 0xde, 0xca, 0xf8, 0x88};

    size_t iv_len = sizeof(iv);

    unsigned char ctxt[] = {0x42, 0x83, 0x1e, 0xc2, 0x21, 0x77, 0x74, 0x24, 0x4b, 0x72,
                            0x21, 0xb7, 0x84, 0xd0, 0xd4, 0x9c, 0xe3, 0xaa, 0x21, 0x2f,
                            0x2c, 0x02, 0xa4, 0xe0, 0x35, 0xc1, 0x7e, 0x23, 0x29, 0xac,
                            0xa1, 0x2e, 0x21, 0xd5, 0x14, 0xb2, 0x54, 0x66, 0x93, 0x1c,
                            0x7d, 0x8f, 0x6a, 0x5a, 0xac, 0x84, 0xaa, 0x05, 0x1b, 0xa3,
                            0x0b, 0x39, 0x6a, 0x0a, 0xac, 0x97, 0x3d, 0x58, 0xe0, 0x91};

    size_t ctxt_len = sizeof(ctxt);

    unsigned char tag[] = {0x5b, 0xc9, 0x4f, 0xbc, 0x32, 0x21, 0xa5, 0xdb,
                           0x94, 0xfa, 0xe9, 0x5a, 0xe7, 0x12, 0x1a, 0x47};

    auto start = emp::clock_start();

    // AEAD decryption with GC
    AEAD<NetIO>* aead = new AEAD<NetIO>(io, ot, key, iv, iv_len);
    bool res = aead->decrypt(io, msg, ctxt, ctxt_len, tag, aad, aad_len, party, sec_type);

    cout << "time: " << emp::time_from(start) << " us" << endl;
    if (party == ALICE) {
        cout << "ALICE res: " << res << endl;
        cout << "ALICE msg: ";
        for (int i = 0; i < msg_len; i++) {
            cout << hex << (int)msg[i];
        }
        cout << endl;

    } else {
        cout << "BOB res: " << res << endl;
        cout << "BOB msg: ";
        for (int i = 0; i < msg_len; i++) {
            cout << hex << (int)msg[i];
        }
        cout << endl;
    }

    // Prove with IZK
    start = emp::clock_start();
    switch_to_zk();
    Integer key_zk(128, keyc, ALICE);
    AEAD_Proof<IO>* aead_proof = new AEAD_Proof<IO>(aead, key_zk, iv, iv_len, party);
    Integer msg_zk;
    aead_proof->prove_aead(msg_zk, ctxt, msg_len, sec_type);
    if (sec_type) {
        cout << msg_zk.reveal<string>() << endl;
    }

    sync_zk_gc<IO>();
    switch_to_gc();
    cout << "prove time: " << time_from(start) << endl;

    delete aead;
    delete aead_proof;
}
const int threads = 1;

int main(int argc, char** argv) {
    int party, port;
    parse_party_and_port(argv, &party, &port);
    NetIO* io = new NetIO(party == ALICE ? nullptr : "127.0.0.1", port);
    BoolIO<NetIO>* ios[threads];
    for (int i = 0; i < threads; i++)
        ios[i] = new BoolIO<NetIO>(io, party == ALICE);

    auto start = emp::clock_start();
    setup_protocol<NetIO>(io, ios, threads, party);
    cout << "setup time: " << emp::time_from(start) << endl;
    auto prot = (PADOParty<NetIO>*)(ProtocolExecution::prot_exec);
    IKNP<NetIO>* cot = prot->ot;
    //it_mac_add_test<NetIO>(io, party);
    //aead_enc_garble_then_prove_test<NetIO>(io, cot, party, true);
    aead_dec_garble_then_prove_test<NetIO>(io, cot, party, true);

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
#include "emp-tool/emp-tool.h"
#include "cipher/sha256.h"
#include "cipher/hmac_sha256.h"
#include "backend/backend.h"
#include "backend/switch.h"
#include <iostream>
#include <string>
#include <vector>
#include <algorithm>

using std::string;
using std::vector;
using namespace std;
using namespace emp;

void sha256test() {
    SHA256 sha;
    Integer* dig = new Integer[sha.DIGLEN];
    vector<uint32_t> outhex;

    string str =
      "01234567890123456789012345678901234567890123456789012345678901230123456789012345678901234567890123456789012345678901234567890123";

    Integer input = str_to_int(str, PUBLIC);
    auto start = clock_start();
    sha.digest(dig, input, true);
    cout << "time: " << time_from(start) << "us" << endl;
    print_hex_32(dig, sha.DIGLEN);

    delete[] dig;
}

void optsha256test() {
    SHA256 sha;
    uint32_t* dig = new uint32_t[sha.DIGLEN];
    string sec = "0123456789012345678901234567890123456789012345678901234567890123";
    Integer sec_input = str_to_int(sec, PUBLIC);
    unsigned char pub_input[] = {
      "0123456789012345678901234567890123456789012345678901234567890123"};
    sha.opt_digest(dig, sec_input, pub_input, 64, true);

    for (int i = 0; i < sha.DIGLEN; i++) {
        cout << hex << dig[i];
    }
    cout << endl;
}

void hmac_sha256test() {
    HMAC_SHA256 hmac256;
    Integer* dig = new Integer[hmac256.DIGLEN];

    string key_str = "01234567890123456789012345678901";
    string msg_str =
      "master secret0123456789012345678901234567890101234567890123456789012345678901";
    Integer key = str_to_int(key_str, PUBLIC);
    Integer msg = str_to_int(msg_str, PUBLIC);
    auto start = clock_start();
    hmac256.init(key);
    hmac256.hmac_sha256(dig, msg);
    cout << "time: " << time_from(start) << "us" << endl;

    // cout << "call: " << hmac256.SHA256_call << endl;
    cout << "hmac-sha256: ";
    print_hex_32(dig, hmac256.DIGLEN);
    delete[] dig;
}

void opt_hmac_sha256test() {
    HMAC_SHA256 hmac256;
    Integer* dig = new Integer[hmac256.DIGLEN];

    string key_str = "01234567890123456789012345678901";
    unsigned char msg[] = {
      "master secret0123456789012345678901234567890101234567890123456789012345678901"};
    Integer key = str_to_int(key_str, ALICE);
    auto start = clock_start();
    hmac256.init(key);
    hmac256.opt_hmac_sha256(dig, msg, 77, true, true);
    cout << "time: " << time_from(start) << "us" << endl;
    cout << "hmac_sha256: ";
    print_hex_32(dig, hmac256.DIGLEN);
    delete[] dig;
}
void hmac_sha256circ() {
    HMAC_SHA256 hmac;
    Integer* dig = new Integer[hmac.DIGLEN];
    int keylen = 256;
    int msglen = 530;
    Integer keyA = Integer(keylen, 0, ALICE);
    Integer keyB = Integer(keylen, 1, BOB);

    Integer msgA = Integer(msglen, 0, ALICE);
    Integer msgB = Integer(msglen, 1, BOB);

    Integer key = keyA ^ keyB;
    Integer msg = msgA ^ msgB;
    auto start = clock_start();
    hmac.init(key);
    hmac.hmac_sha256(dig, msg);
    cout << "time: " << time_from(start) << "us" << endl;

    cout << "CALL Compression Function: " << hmac.compression_calls() << " times" << endl;
    cout << "hmac_sha256: ";
    print_hex_32(dig, hmac.DIGLEN);
    delete[] dig;
}

void opt_hmac_sha256circ() {
    HMAC_SHA256 hmac;
    Integer* dig = new Integer[hmac.DIGLEN];
    int keylen = 256;
    Integer keyA = Integer(keylen, 0, ALICE);

    string key_str = "01234567890123456789012345678901";

    Integer keyB = str_to_int(key_str, BOB);

    Integer key = keyA ^ keyB;

    unsigned char msg[] = {
      "master secret0123456789012345678901234567890101234567890123456789012345678902"};
    auto start = clock_start();
    hmac.init(key);
    hmac.opt_hmac_sha256(dig, msg, 77, true, true);
    cout << "time: " << time_from(start) << "us" << endl;

    cout << "CALL Compression Function: " << hmac.compression_calls() << " times" << endl;
    cout << "hmac_sha256: ";
    print_hex_32(dig, hmac.DIGLEN);
    delete[] dig;
}

void sha256_compressiontest() {
    SHA256 sha;
    Integer* input = new Integer[sha.DIGLEN];

    for (int i = 0; i < sha.DIGLEN; i++) {
        input[i] = Integer(sha.WORDLEN, 0, ALICE);
    }

    Integer* chunk = new Integer[16];
    for (int i = 0; i < 16; i++) {
        chunk[i] = Integer(sha.WORDLEN, 1, ALICE);
    }
    sha.chunk_compress(input, chunk);
}

void zk_gc_hmac_test() {
    HMAC_SHA256 hmac256;
    Integer* dig = new Integer[hmac256.DIGLEN];

    string key_str = "01234567890123456789012345678901";
    unsigned char msg[] = {
      "master secret0123456789012345678901234567890101234567890123456789012345678901"};
    Integer key = str_to_int(key_str, ALICE);
    hmac256.init(key);
    hmac256.opt_hmac_sha256(dig, msg, 77, true, true);
    cout << "hmac_sha256: ";
    print_hex_32(dig, hmac256.DIGLEN);

    switch_to_zk();

    key = str_to_int(key_str, ALICE);
    hmac256.init(key);
    hmac256.opt_hmac_sha256(dig, msg, 77, true, true, true);
    cout << "hmac_sha256: ";
    print_hex_32(dig, hmac256.DIGLEN);

    sync_zk_gc<NetIO>();
    switch_to_gc();
    delete[] dig;
}

int threads = 1;
int main(int argc, char** argv) {
    // setup_plain_prot(true, "hmacsha256.txt");
    // //setup_plain_prot(false, "");
    // hmac_sha256test();
    // cout << "AND gates: " << CircuitExecution::circ_exec->num_and() << endl;
    // finalize_plain_prot();

    int port, party;
    parse_party_and_port(argv, &party, &port);
    NetIO* io = new NetIO(party == ALICE ? nullptr : "127.0.0.1", port);
    //setup_backend(io, party);

    //hmac_sha256circ();
    //sha256test();
    //optsha256test();
    //hmac_sha256test();
    //opt_hmac_sha256test();
    //opt_hmac_sha256circ();
    //sha256_compressiontest();
    BoolIO<NetIO>* ios[threads];
    for (int i = 0; i < threads; i++)
        ios[i] = new BoolIO<NetIO>(io, party == ALICE);

    setup_protocol(io, ios, threads, party);
    zk_gc_hmac_test();
    finalize_protocol();
    // cout << "AND gates: " << dec << CircuitExecution::circ_exec->num_and() << endl;
    // finalize_backend();

    for (int i = 0; i < CheatRecord::message.size(); i++) {
        cout << CheatRecord::message[i] << endl;
    }
    bool cheat = CheatRecord::cheated();
    if (cheat)
        error("cheat!\n");

    delete io;
    for (int i = 0; i < threads; i++) {
        delete ios[i];
    }
}

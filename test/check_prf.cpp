
#include "emp-tool/emp-tool.h"
#include "backend/backend.h"
#include "cipher/prf.h"
#include "cipher/hmac_sha256.h"
#include "backend/switch.h"
#include "backend/check_zero.h"

#include <iostream>
#include <vector>

using namespace std;
using namespace emp;
void test_extended_master_secret() {
    unsigned char pms[] = {0x53, 0xf3, 0xc9, 0x54, 0x26, 0xdc, 0x73, 0x19, 0xbd, 0x8a, 0x6f, 0xd2, 0x54, 0x66, 0x9d, 0xf2, 0xd0, 0x4d, 0x52, 0x38, 0xce, 0x16, 0xc6, 0x7e, 0xa3, 0x6e, 0x40, 0xd3, 0x2f, 0xf0, 0xdb, 0x9f};
    unsigned char hash[] = {0x4f, 0x92, 0x77, 0x83, 0x38, 0xe9, 0xd8, 0xe0, 0xeb, 0xba, 0x01, 0x76, 0x4c, 0x71, 0xd3, 0x3e, 0x74, 0x1f, 0x76, 0x80, 0x90, 0x47, 0x25, 0x02, 0xd9, 0x4d, 0xb6, 0x38, 0x5a, 0x13, 0x99, 0xd9};
    Integer master_key;
    int master_key_length = 48;
    int hash_len = sizeof(hash);

    const unsigned char* extended_master_key_label = (const unsigned char*)"extended master secret";
    int extended_master_key_label_length = strlen((const char*)extended_master_key_label);

    reverse(pms, pms + 32);
    Integer pmsbits = Integer(32 * 8, pms, PUBLIC);
    PRF prf;
    HMAC_SHA256 hmac;
    prf.init(hmac, pmsbits);
    prf.opt_compute(hmac, master_key, master_key_length * 8, pmsbits, extended_master_key_label,
                    extended_master_key_label_length, hash, hash_len, true, true);
    unsigned char key[48];
    master_key.reveal<unsigned char>(key, PUBLIC);
    reverse(key, key + 48);
    printf("extended master key out:\n");
    for (int i = 0; i < 48; i++)
    	printf("%02x ", key[i]);
    printf("\n");

}
int threads = 1;
int main(int argc, char** argv) {
    int port, party;
    parse_party_and_port(argv, &party, &port);
    NetIO* io = new NetIO(party == ALICE ? nullptr : "127.0.0.1", port);
    BoolIO<NetIO>* ios[threads];
    for (int i = 0; i < threads; i++)
        ios[i] = new BoolIO<NetIO>(io, party == ALICE);

    setup_protocol(io, ios, threads, party);
    test_extended_master_secret();

    finalize_protocol();

    bool cheat = CheatRecord::cheated();
    if (cheat)
        error("cheat!\n");
    delete io;
    for (int i = 0; i < threads; i++) {
        delete ios[i];
    }
}

#include "emp-zk/emp-zk.h"
#include <iostream>
#include "cipher/utils.h"
#include "protocol/prove_aes.h"
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

bool prove_aes() {
    unsigned char key_hex[] = {0x2b, 0x7e, 0x15, 0x16, 0x28, 0xae, 0xd2, 0xa6,
                               0xab, 0xf7, 0x15, 0x88, 0x09, 0xcf, 0x4f, 0x3c};
    reverse(key_hex, key_hex + 16);
    Integer key(128, key_hex, ALICE);

    unsigned char nounces[] = {0x6b, 0xc1, 0xbe, 0xe2, 0x2e, 0x40, 0x9f, 0x96,
                               0xe9, 0x3d, 0x7e, 0x11, 0x73, 0x93, 0x17, 0x2a,
                               0xae, 0x2d, 0x8a, 0x57, 0x1e, 0x03, 0xac, 0x9c,
                               0x9e, 0xb7, 0x6f, 0xac, 0x45, 0xaf, 0x8e, 0x51};

    unsigned char msgs[] = {0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00};

    unsigned char ctxts[] = {0x3a, 0xd7, 0x7b, 0xb4, 0x0d, 0x7a, 0x36, 0x60, 0xa8, 0x9e, 0xca,
                             0xf3, 0x24, 0x66, 0xef, 0x97, 0xf5, 0xd3, 0xd5, 0x85, 0x03, 0xb9,
                             0x69, 0x9d, 0xe7, 0x85, 0x89, 0x5a, 0x96, 0xfd, 0xba, 0xaf};

    AESProver prover(key);
    size_t len_bytes = sizeof(nounces);

    Integer private_msg(len_bytes * 8, nounces, ALICE);

    bool res = prover.prove_public_msgs(nounces, msgs, ctxts, len_bytes);
    res ^= prover.prove_private_msgs(nounces, private_msg, ctxts, len_bytes);

    return res;
}

const int threads = 1;
int main(int argc, char** argv) {
    int port, party;
    parse_party_and_port(argv, &party, &port);
    NetIO* io[threads];
    for (int i = 0; i < threads; i++) {
        io[i] = new NetIO(party == ALICE ? nullptr : "127.0.0.1", port + i);
    }
    BoolIO<NetIO>* ios[threads];
    for (int i = 0; i < threads; i++)
        ios[i] = new BoolIO<NetIO>(io[i], party == ALICE);

    auto start = emp::clock_start();
    auto comm = io[0]->counter;
    auto rounds = io[0]->rounds;

    setup_proxy_protocol(ios, threads, party);

    cout << "setup time: " << emp::time_from(start) << " us" << endl;
    cout << "setup comm: " << (io[0]->counter - comm) * 1.0 / 1024 << " Kbytes" << endl;
    cout << "setup rounds: " << (io[0]->rounds - rounds) << " rounds" << endl;

    comm = io[0]->counter;
    rounds = io[0]->rounds - rounds;

    start = emp::clock_start();
    bool res = prove_aes();
    if (!res) {
        error("prove error:\n");
    }

    cout << "zk AND gates: " << CircuitExecution::circ_exec->num_and() << endl;

    bool cheated = finalize_proxy_protocol<BoolIO<NetIO>>();
    if (cheated)
        error("cheated\n");

    cout << "prove time: " << emp::time_from(start) << " us" << endl;
    cout << "prove comm: " << (io[0]->counter - comm) * 1.0 / 1024 << " Kbytes" << endl;
    cout << "prove rounds: " << (io[0]->rounds - rounds) << " rounds" << endl;
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

    for (int i = 0; i < threads; ++i) {
        delete ios[i]->io;
        delete ios[i];
    }

    return 0;
}

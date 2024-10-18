#include "emp-zk/emp-zk.h"
#include <iostream>
#include "cipher/utils.h"
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

void prove_aes() {}

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

    setup_zk_bool<BoolIO<NetIO>>(ios, threads, party);

    cout << "setup time: " << emp::time_from(start) << " us" << endl;
    cout << "setup comm: " << (io[0]->counter - comm) * 1.0 / 1024 << " Kbytes" << endl;
    cout << "setup rounds: " << (io[0]->rounds - rounds) << " rounds" << endl;

    comm = io[0]->counter;
    rounds = io[0]->rounds - rounds;
    init_files();

    unsigned char* z = new unsigned char[16];

    start = emp::clock_start();

    Integer key(128, 0, ALICE);
    Integer expended_key = computeKS(key);
    for (int i = 0; i < 64; ++i) {
        Integer m(128, 0, ALICE);
        Integer nounce(128, 0, PUBLIC);
        Integer c = computeAES_KS(expended_key, nounce);
        Integer out = (c ^ m);
        out.reveal<unsigned char>((unsigned char*)z, PUBLIC);
    }

    cout << "zk AND gates: " << CircuitExecution::circ_exec->num_and() << endl;

    bool cheated = finalize_zk_bool<BoolIO<NetIO>>();

    cout << "prove time: " << emp::time_from(start) << " us" << endl;
    cout << "prove comm: " << (io[0]->counter - comm) * 1.0 / 1024 << " Kbytes" << endl;
    cout << "prove rounds: " << (io[0]->rounds - rounds) << " rounds" << endl;
    if (cheated)
        error("cheated\n");
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
    uninit_files();

    for (int i = 0; i < threads; ++i) {
        delete ios[i]->io;
        delete ios[i];
    }

    return 0;
}

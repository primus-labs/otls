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
    bool res = false;
    unsigned char client_fin_msg[] = {0x14, 0x00, 0x00, 0x0c, 0x62, 0x9c, 0xb5, 0x1d, 0x0f, 0xf0, 0x13, 0xf9, 0x27, 0xb5, 0xec, 0x57};
    unsigned char client_fin_iv[] = {0xa1, 0x60, 0x62, 0x7c, 0x3c, 0xc3, 0x9f, 0x8e};
    unsigned char client_fin_ctxt[] = {0xf3, 0x3e, 0x33, 0xb7, 0xad, 0xf3, 0x0a, 0xbd, 0x49, 0xa4, 0xdc, 0x2d, 0x7b, 0x00, 0xe1, 0x05};
    unsigned char server_fin_msg[] = {0x14, 0x00, 0x00, 0x0c, 0x06, 0x61, 0x2f, 0xa6, 0xdf, 0xc2, 0x41, 0x45, 0xb5, 0x8f, 0x57, 0x81};
    unsigned char server_fin_iv[] =  {0xd9, 0x2f, 0xd9, 0xa4, 0xa1, 0x38, 0x1b, 0xca};
    unsigned char server_fin_ctxt[] = {0x02, 0x42, 0x44, 0x7a, 0xc3, 0x3d, 0x4b, 0xf9, 0x89, 0x0e, 0x00, 0xd9, 0x7d, 0x06, 0x87, 0xb5};

    unsigned char http_msg[] = {0x47, 0x45, 0x54, 0x20, 0x2f, 0x61, 0x70, 0x69, 0x2f, 0x76, 0x31, 0x2f, 0x67, 0x65, 0x74, 0x76, 0x61, 0x6c, 0x75, 0x65, 0x31, 0x20, 0x48, 0x54, 0x54, 0x50, 0x2f, 0x31, 0x2e, 0x31, 0x0d, 0x0a, 0x48, 0x6f, 0x73, 0x74, 0x3a, 0x20, 0x6c, 0x6f, 0x63, 0x61, 0x6c, 0x68, 0x6f, 0x73, 0x74, 0x0d, 0x0a, 0x0d, 0x0a};
    unsigned char http_iv[] = {0xa1, 0x60, 0x62, 0x7c, 0x3c, 0xc3, 0x9f, 0x8f};
    unsigned char http_ctxt[] = {0x9b, 0x75, 0xf9, 0x00, 0x0a, 0xd3, 0x9d, 0xef, 0x92, 0x56, 0x4a, 0x78, 0xa1, 0xb4, 0xa0, 0x71, 0xe5, 0x8c, 0xd7, 0x07, 0x61, 0xef, 0xb2, 0x4e, 0x28, 0xe1, 0x40, 0xa2, 0x72, 0xf6, 0xad, 0xa7, 0xbf, 0x6d, 0xe6, 0x0f, 0x65, 0xe7, 0xe8, 0xc1, 0x98, 0xad, 0xcd, 0x37, 0x8e, 0xbd, 0x19, 0xa8, 0x05, 0xbf, 0x52};

    unsigned char key_c_oct[] = {0x75, 0x29, 0x45, 0x4c, 0x53, 0x28, 0x9c, 0x44, 0x7c, 0xa7, 0x67, 0x87, 0x85, 0x63, 0x81, 0x95};
    unsigned char key_s_oct[] = {0x75, 0x47, 0x93, 0x57, 0xd9, 0xe4, 0x85, 0x90, 0x2b, 0xb5, 0x9a, 0xd8, 0x37, 0x2d, 0x06, 0xf5};
    unsigned char iv_c_oct[] = {0xcc, 0xd4, 0xa4, 0x62};
    unsigned char iv_s_oct[] = {0xad, 0xbc, 0x4e, 0x8e};

    // private input
    Integer key_c, key_s, iv_c, iv_s, fin_c, fin_s;
    {
        reverse(key_c_oct, key_c_oct + sizeof(key_c_oct));
        reverse(key_s_oct, key_s_oct + sizeof(key_s_oct));
        reverse(iv_c_oct, iv_c_oct + sizeof(iv_c_oct));
        reverse(iv_s_oct, iv_s_oct + sizeof(iv_s_oct));
        reverse(client_fin_msg, client_fin_msg + sizeof(client_fin_msg));
        reverse(server_fin_msg, server_fin_msg + sizeof(server_fin_msg));

        key_c = Integer(8 * sizeof(key_c_oct), key_c_oct, ALICE);
        key_s = Integer(8 * sizeof(key_s_oct), key_s_oct, ALICE);
        iv_c = Integer(8 * sizeof(iv_c_oct), iv_c_oct, ALICE);
        iv_s = Integer(8 * sizeof(iv_s_oct), iv_s_oct, ALICE);
        fin_c = Integer(8 * sizeof(client_fin_msg), client_fin_msg, ALICE);
        fin_s = Integer(8 * sizeof(server_fin_msg), server_fin_msg, ALICE);
    }

    // prove aes
    {
        AESProver prover_c(key_c, iv_c);
        AESProver prover_s(key_s, iv_s);

        res = prover_c.prove_private_msgs(client_fin_iv, sizeof(client_fin_iv), fin_c, client_fin_ctxt, sizeof(client_fin_ctxt));
        if (!res) {
            error("prove client finish msg error");
        }

        res = prover_s.prove_private_msgs(server_fin_iv, sizeof(server_fin_iv), fin_s, server_fin_ctxt, sizeof(server_fin_ctxt));
        if (!res) {
            error("prove server finish msg error");
        }

        unsigned char* buf = new unsigned char[sizeof(http_msg)];
        memcpy(buf, http_msg, sizeof(http_msg));
        reverse(buf, buf + sizeof(http_msg));
        Integer tmp(8 * sizeof(http_msg), buf, ALICE);

        res = prover_c.prove_private_msgs(http_iv, sizeof(http_iv), tmp, http_ctxt, sizeof(http_ctxt));
        if (!res) {
            error("prove http msg error");
        }
        delete[] buf;
         
    }
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

    setup_proxy_protocol(ios, threads, party);

    cout << "setup time: " << emp::time_from(start) << " us" << endl;
    cout << "setup comm: " << (io[0]->counter - comm) * 1.0 / 1024 << " Kbytes" << endl;

    comm = io[0]->counter;

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

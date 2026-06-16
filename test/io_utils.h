#include <emp-tool/io/net_io_channel.h>

inline size_t getComm(NetIO** io, int threads, NetIO* io_opt) {
    // FULLPORT: upstream IOChannel uses send_counter/recv_counter (the original fork used a single counter)
    size_t totalCounter = 0;
    for (int i = 0; i < threads; i++) {
        totalCounter += io[i]->send_counter + io[i]->recv_counter;
    }
    if (io_opt != nullptr) {
        totalCounter += io_opt->send_counter + io_opt->recv_counter;
    }
    return totalCounter;
}

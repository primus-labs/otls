#include <emp-tool/io/net_io_channel.h>

inline size_t getComm(NetIO** io, int threads, NetIO* io_opt) {
    size_t totalCounter = 0;
    for (int i = 0; i < threads; i++) {
        totalCounter += io[i]->counter;
    }
    if (io_opt != nullptr) {
        totalCounter += io_opt->counter;
    }
    return totalCounter;
}

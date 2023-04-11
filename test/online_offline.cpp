#include "backend/backend.h"
using namespace emp;
using namespace std;

void test_sort(int party, bool online = false) {
    int size = 100;
    Integer* A = new Integer[size];
    Integer* B = new Integer[size];
    Integer* res = new Integer[size];

    // First specify Alice's input
    for (int i = 0; i < size; ++i)
        A[i] = Integer(32, rand() % 102400, ALICE);

    // Now specify Bob's input
    for (int i = 0; i < size; ++i)
        B[i] = Integer(32, rand() % 102400, BOB);

    //Now compute
    for (int i = 0; i < size; ++i)
        res[i] = A[i] ^ B[i];

    sort(res, size);
    for (int i = 0; i < 100; ++i) {
        auto r = res[i].reveal<int32_t>();
        if (party == ALICE and online)
            cout << r << endl;
    }
    delete[] A;
    delete[] B;
    delete[] res;
}

int main(int argc, char** argv) {
    auto start = clock_start();
    int port, party;
    parse_party_and_port(argv, &party, &port);

    OfflinePADOGen* offline;
    if (party == ALICE) {
        offline = setup_offline_backend(party);
        test_sort(party, true);
    }

    NetIO* io = new NetIO(party == ALICE ? nullptr : "127.0.0.1", port);
    vector<block> GCvec;
    block seed, delta;
    if (party == ALICE) {
        size_t length = offline->gc->GC.size();
        io->send_data(&length, sizeof(size_t));
        io->send_block(offline->gc->GC.data(), length);
        seed = offline->seed;
        delta = offline->gc->delta;
    } else {
        size_t length;
        io->recv_data(&length, sizeof(size_t));
        GCvec.resize(length);
        io->recv_block(GCvec.data(), length);
    }
    finalize_backend();
    cout << "offline:" << time_from(start) << "\n";
    start = clock_start();

    auto back = setup_online_backend(io, party);
    if (party == ALICE) {
        OnlinePADOGen<NetIO>* gen = (OnlinePADOGen<NetIO>*)back;
        gen->set_seed(seed);
        gen->gc->set_delta(delta);
    } else {
        OnlinePADOEva<NetIO>* eva = (OnlinePADOEva<NetIO>*)back;
        eva->gc->GC = GCvec;
    }

    test_sort(party, true);
    cout << "gates: " << CircuitExecution::circ_exec->num_and() << endl;
    finalize_backend();
    cout << "online:" << time_from(start) << "\n";

    delete io;
}

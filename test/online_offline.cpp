#include "backend/backend.h"
using namespace emp;
using namespace std;

void test_sort(int party, bool online = false) {
    int size = 2;
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
    for (int i = 0; i < size; ++i) {
        auto r = res[i].reveal<int32_t>();
        cout << r << endl;
    }
    delete[] A;
    delete[] B;
    delete[] res;
}

int main(int argc, char** argv) {
    int port, party;
    parse_party_and_port(argv, &party, &port);
    NetIO* io = new NetIO(party == ALICE ? nullptr : "127.0.0.1", port);
    auto start = emp::clock_start();
    auto offline = setup_offline_backend<NetIO>(io, party);
    test_sort(party, true);
    cout << "offline:" << emp::time_from(start) << endl;

    start = emp::clock_start();
    auto online = setup_online_backend<NetIO>(io, party);
    sync_offline_online<NetIO>(offline, online, party);

    test_sort(party, true);
    cout << "gates: " << CircuitExecution::circ_exec->num_and() << endl;
    finalize_backend();
    cout << "online:" << emp::time_from(start) << endl;

    delete io;
}

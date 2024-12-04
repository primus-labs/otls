#include "backend/backend.h"
using namespace emp;
using namespace std;

void test_sort(int party) {
	int size = 100;
	Integer *A = new Integer[size];
	Integer *B = new Integer[size];
	Integer *res = new Integer[size];

// First specify Alice's input
	for(int i = 0; i < size; ++i)
		A[i] = Integer(32, rand()%102400, ALICE);


// Now specify Bob's input
	for(int i = 0; i < size; ++i)
		B[i] = Integer(32, rand()%102400, BOB);

//Now compute
	for(int i = 0; i < size; ++i)
		res[i] = A[i] ^ B[i];
	

	sort(res, size);
	for(int i = 0; i < 100; ++i) {
		if(party == ALICE)
		cout << res[i].reveal<int32_t>()<<endl;
		else res[i].reveal<int32_t>();
	}
	delete[] A;
	delete[] B;
	delete[] res;
}

int main(int argc, char** argv) {
	int port, party;
	parse_party_and_port(argv, &party, &port);
	NetIO * io = new NetIO(party==ALICE ? nullptr : "127.0.0.1", port);

	setup_backend(io, party);
	test_sort(party);
	test_sort(party);
	cout << "gates: "<<CircuitExecution::circ_exec->num_and()<<endl;
	finalize_backend();
	delete io;
}

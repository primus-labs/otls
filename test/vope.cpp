#include "backend/backend.h"
#include "backend/vope.h"
#include <iostream>

using namespace std;
using namespace emp;

int main(int argc, char** argv) {
	int port, party;
	const int num_vope = 6;
	parse_party_and_port(argv, &party, &port);
	NetIO* ios[1];
	for(int i = 0; i < 1; ++i)
		ios[i] = new NetIO(party == ALICE?nullptr:"127.0.0.1",port+i);


	setup_backend(ios[0], party);

	//	FerretCOT<NetIO> * cot = new FerretCOT<NetIO>(party, 1, ios, true, true, ferret_b13);

	auto prot = (PADOParty<NetIO>*)(ProtocolExecution::prot_exec);
	IKNP<NetIO> * cot = prot->ot;
	vector<block> out;
	out.resize(num_vope+1);
	block h;
	PRG prg; prg.random_data(&h, sizeof(block));
	prg.random_data(out.data(), num_vope*sizeof(block));

	auto t1 = clock_start();
	VOPE<NetIO> vope(ios[0], cot);
	block B;
	if(party == ALICE) {
		vope.compute_send(&B, h, num_vope);
	} else {
		vope.compute_recv(out.data(), num_vope);
	}
	cout<<"execute" << time_from(t1)<<endl;

	if(party == ALICE) {
		ios[0]->send_data(&h, sizeof(block));
		cout <<"A:"<< B[0]<<endl;
	} else {
		ios[0]->recv_data(&h, sizeof(block));
		vector<block> hs;
		hs.push_back(zero_block);
		hs.push_back(h);
		for(int i = 2; i < num_vope; ++i) 
			hs.push_back(mulBlock(hs.back(), h));
		block tmp;
		vector_inn_prdt_sum_red(&tmp, hs.data(), out.data(), num_vope+1);
	}
	//	delete cot;
	finalize_backend();
	for(int i = 0; i < 1; ++i)
		delete ios[i];

}

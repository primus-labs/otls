#include "backend/backend.h"
#include "backend/ole_f2k.h"
#include "cipher/utils.h"
#include <iostream>

using namespace std;
using namespace emp;

int main(int argc, char** argv) {
	int port, party;
	const int num_ole = 1000;
	parse_party_and_port(argv, &party, &port);
	NetIO* ios[1];
	for(int i = 0; i < 1; ++i)
		ios[i] = new NetIO(party == ALICE?nullptr:"127.0.0.1",port+i);


	setup_backend(ios[0], party);

	//	FerretCOT<NetIO> * cot = new FerretCOT<NetIO>(party, 1, ios, true, true, ferret_b13);

	auto prot = (PADOParty<NetIO>*)(ProtocolExecution::prot_exec);
	IKNP<NetIO> * cot = prot->ot;
	vector<block> out;
	vector<block> in;
	in.resize(num_ole);
	out.resize(num_ole);
	PRG prg; prg.random_block(in.data());	

	auto t1 = clock_start();
	OLEF2K<NetIO> ole(ios[0], cot);
	ole.compute(out.data(), in.data(), num_ole);
	cout<<"execute" << time_from(t1)<<endl;

	if(party == ALICE) {
		for(int i = 0; i < num_ole; ++i) {
			ios[0]->send_block(&(in[i]), 1);
			ios[0]->send_block(&(out[i]), 1);
		}
	} else {
		for(int i = 0; i < num_ole; ++i ){
			block in2, out2;
			ios[0]->recv_block(&in2, 1);
			ios[0]->recv_block(&out2, 1);
			in2 = mulBlock(in2, in[i]);
			out2 ^= out[i];
			if(!cmpBlock(&in2, &out2, 1))
				error("not correct!!");
		}	
	}
	//	delete cot;
	finalize_backend();
	for(int i = 0; i < 1; ++i)
		delete ios[i];
}

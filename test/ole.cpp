#include "backend/backend.h"
#include "backend/ole.h"
#include <iostream>

using namespace std;
using namespace emp;

int main(int argc, char** argv) {
/*	BIGNUM * out = BN_new();
	BN_zero(out);
	BN_set_bit(out, 0);
	BN_set_bit(out, 255);
	for(int i = 0; i < 300; ++i)
		cout <<i<<BN_is_bit_set(out, i)<<"\n";
	unsigned char arr[1000];
	int length = BN_bn2bin(out, arr);
	cout<<"!!"<< length<<"\n";
	for(int i = 0; i < length; ++i)
		cout <<uint32_t(arr[i])<<endl;
	return 0;
*/
	int port, party;
	const int num_ole = 6;
	parse_party_and_port(argv, &party, &port);
	NetIO* ios[1];
	for(int i = 0; i < 1; ++i)
		ios[i] = new NetIO(party == ALICE?nullptr:"127.0.0.1",port+i);


	setup_backend(ios[0], party);
	uint64_t q = (1ULL<<61)-1;

//	FerretCOT<NetIO> * cot = new FerretCOT<NetIO>(party, 1, ios, true, true, ferret_b13);
	
	auto prot = (PADOParty<NetIO>*)(ProtocolExecution::prot_exec);
	IKNP<NetIO> * cot = prot->ot;
	if (false){//uint64_t
		OLE<NetIO> ole(ios[0], cot, nullptr);
		vector<uint64_t> in, out;
		in.resize(num_ole);
		out.resize(num_ole);
		PRG prg;
		prg.random_data(in.data(), num_ole*8);
		for(int i = 0; i < num_ole; ++i)
			in[i] %= q;

		ole.compute(out, in, q);
		
		vector<uint64_t> tmp, tmp2;
		tmp.resize(num_ole);
		tmp2.resize(num_ole);
		if(party == ALICE) {
			ios[0]->send_data(in.data(), 80);
			ios[0]->send_data(out.data(), 80);
		} else{
			ios[0]->recv_data(tmp.data(), 80);
			ios[0]->recv_data(tmp2.data(), 80);

			for(int i = 0; i < num_ole; ++i) {
				__uint128_t a = in[i];
				a = a * tmp[i];
				if(uint64_t(a % q) != (out[i] +  tmp2[i]) % q)
					cout <<"wrong!\n";
			}
		}
	} 
	{//openssl
		vector<BIGNUM*> in, out;
		in.resize(num_ole);
		out.resize(num_ole);
		BIGNUM * q = BN_new(), *n19 = BN_new();
		BN_CTX * ctx = BN_CTX_new();
		BN_set_bit(q, 255);
		BN_set_word(n19, 19);
		BN_sub(q, q, n19);//2^255-19
		for(int i = 0; i < num_ole; ++i) {
			in[i] = BN_new();
			out[i] = BN_new();
			BN_rand(in[i], 256, 0, 0);
			BN_mod(in[i], in[i], q, ctx);
		}

		auto t1 = clock_start();
		OLE<NetIO> ole(ios[0], cot, q);
		cout<<"setup" << time_from(t1)<<endl;
		t1 = clock_start();
		ole.compute(out, in, q, 255);
		cout<<"execute" << time_from(t1)<<endl;
		
		BIGNUM* tmp = BN_new();
		BIGNUM* tmp2 = BN_new();
		unsigned char arr[1000];
		if(party == ALICE) {
			for (int i = 0; i < num_ole; ++i) {
				int length = BN_bn2bin(in[i], arr);
				ios[0]->send_data(&length, sizeof(int));
				ios[0]->send_data(arr, length);

				length = BN_bn2bin(out[i], arr);
				ios[0]->send_data(&length, sizeof(int));
				ios[0]->send_data(arr, length);
			}
		} else{
			for(int i = 0; i< num_ole; ++i) {
				int length = -1;
				ios[0]->recv_data(&length, sizeof(int));
				ios[0]->recv_data(arr, length);
				BN_bin2bn(arr, length, tmp);

				ios[0]->recv_data(&length, sizeof(int));
				ios[0]->recv_data(arr, length);
				BN_bin2bn(arr, length, tmp2);

				BN_mod_mul(tmp, tmp, in[i], q, ctx);
				BN_mod_sub(tmp, tmp, out[i], q, ctx);
				BN_mod_sub(tmp, tmp, tmp2, q, ctx);
				if(!BN_is_zero(tmp))
					cout <<"wrong!2\n";
			}
		}
	}
//	delete cot;
	finalize_backend();
	for(int i = 0; i < 1; ++i)
		delete ios[i];

}
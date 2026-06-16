#include "cipher/utils.h"
#include <typeinfo>
#include "backend/backend.h"
using namespace emp;
using namespace std;

const string circuit_file_location = macro_xstr(EMP_CIRCUIT_PATH)+string("bristol_format/");
const string circuit_file_location2 = macro_xstr(EMP_CIRCUIT_PATH)+string("bristol_fashion/");

int main(int argc, char** argv) {
	int port, party;
	parse_party_and_port(argv, &party, &port);
	NetIO * io = new NetIO(party==ALICE ? nullptr : "127.0.0.1", port);
	setup_backend(io, party);
	Integer a (128, 0, ALICE);
	Integer b (128, 0, BOB);
	Integer o (128, 0, PUBLIC);
	BristolFormat bf((circuit_file_location+"AES-non-expanded.txt").c_str());
	bristol_run(bf, o, a, b);
	cout << o.reveal<string>()<<endl;


	Integer a2 (256, 0, ALICE);
	Integer o2 (128, 0, PUBLIC);
	BristolFashion bf2((circuit_file_location2+"aes_128.txt").c_str());
	bristol_run(bf2, o2, a2);
	cout << o2.reveal<string>()<<endl;

	cout << (io->send_counter + io->recv_counter)<<endl;

	finalize_backend();
	delete io;
}

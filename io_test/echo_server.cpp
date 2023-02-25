#include "net_io_channel.h"


void run(int port) {
	emp::NetIO* io = new emp::NetIO(nullptr, port);
	const char* s = "hello world";
	while (1) {
		char buf[256];
		io->recv_data(buf, strlen(s));
		io->send_data(buf, strlen(s));
		io->flush();
	}
}
int main(int argc, char* argv[]) {
	run(atoi(argv[1]));
	return 0;
}

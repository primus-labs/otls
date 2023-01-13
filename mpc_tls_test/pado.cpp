#include<stdio.h>
#include<stdlib.h>


#include<openssl/mpc_tls.h>
#include<openssl/mpc_tls_meth.h>

void run_pado() {
	init_mpc(2);

}

int main(int argc, char* argv[]) {
	run_pado();
	return 0;
}

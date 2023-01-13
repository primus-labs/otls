#include<stdio.h>
#include<stdlib.h>


#include<openssl/mpc_tls.h>
#include<openssl/mpc_tls_meth.h>

void run_pado() {
    OPENSSL_init_MPC_METH(set_priv_key_mpc, EC_POINT_mul_mpc, get_client_pub_key_mpc, get_pms_mpc, tls1_prf_P_hash_mpc);
	init_mpc(1);
    
	EC_POINT* s_pub_key = EC_POINT_new_mpc();
	EC_POINT* z_pub_key = EC_POINT_new_mpc();
	printf("begin mul tls\n");
	EC_POINT_mul_tls(z_pub_key, s_pub_key);
	printf("end mul tls\n");
}

int main(int argc, char* argv[]) {
	run_pado();
	return 0;
}


#include<openssl/mpc_tls.h>
#include<openssl/mpc_tls_meth.h>
int main(int argc, char* argv[]) {
    OPENSSL_init_MPC_METH(EC_POINT_mul_mpc, get_client_pub_key_mpc, get_pms_mpc, tls1_prf_P_hash_mpc);
	return 0;
}

#include<stdio.h>
#include<stdlib.h>
#include<string.h>
#include<arpa/inet.h>
#include<unistd.h>
#include<errno.h>

#include<openssl/ssl.h>
#include<openssl/err.h>
int verify_callback(int ok, X509_STORE_CTX* ctx) {
	printf("server certificate: %d\n", ok);
	X509* cert = X509_STORE_CTX_get_current_cert(ctx);
	char* subject = X509_NAME_oneline(X509_get_subject_name(cert), 0, 0);
	char* issuer = X509_NAME_oneline(X509_get_issuer_name(cert), 0, 0);
	printf("subject: %s\n", subject);
	printf("issuer: %s\n", issuer);
	if (!ok) {
		int err = X509_STORE_CTX_get_error(ctx);
		printf("verify callback %s\n", X509_verify_cert_error_string(err));
	}
	return ok;
}
void run() {
	int fd = socket(AF_INET, SOCK_STREAM, 0);
	if (fd < 0) {
		printf("create socket error %s\n", strerror(errno));
		exit(1);
	}
	struct sockaddr_in server;
	memset(&server, 0, sizeof(server));
	server.sin_family = AF_INET;
	server.sin_addr.s_addr = htonl(INADDR_ANY);
	server.sin_port = htons(8080);

	int ret = bind(fd, (struct sockaddr*)&server, sizeof(server));
	if (ret < 0) {
		printf("bind error %s\n", strerror(errno));
		exit(1);
	}

	ret = listen(fd, 10);
	if (ret < 0) {
		printf("listen error %s\n", strerror(errno));
		exit(1);
	}
	struct sockaddr_in client;
	socklen_t socklen = 0;
	int cfd = accept(fd, (struct sockaddr*)&client, &socklen);
	if (cfd < 0) {
		printf("accept error %s\n", strerror(errno));
		exit(1);
	}


	const SSL_METHOD* tlsv12 = TLS_method();
	SSL_CTX* ssl_ctx = SSL_CTX_new(tlsv12);
	SSL_CTX_set_ecdh_auto(ssl_ctx, 1);
	/* SSL_CTX_set_verify(ssl_ctx, SSL_VERIFY_PEER | SSL_VERIFY_FAIL_IF_NO_PEER_CERT, verify_callback);
	SSL_CTX_set_client_CA_list(ssl_ctx, SSL_load_client_CA_file("client_ca.crt"));
	if(SSL_CTX_load_verify_locations(ssl_ctx, "client_ca.crt", NULL) <= 0) {
		ERR_print_errors_fp(stderr);
		exit(1);
	}*/
	if (SSL_CTX_use_certificate_chain_file(ssl_ctx, "server.crt") <= 0) {
		ERR_print_errors_fp(stderr);
		exit(1);
	}
	if (SSL_CTX_use_PrivateKey_file(ssl_ctx, "server.key", SSL_FILETYPE_PEM) <= 0) {
		ERR_print_errors_fp(stderr);
		exit(1);
	}
	if (!SSL_CTX_check_private_key(ssl_ctx)) {
		ERR_print_errors_fp(stderr);
		exit(1);
	}


	SSL* cssl = SSL_new(ssl_ctx);
	ret = SSL_set_fd(cssl, cfd);
	if (ret < 0) {
		printf("ssl set fd error\n");
		exit(1);
	}
	ret = SSL_accept(cssl);
	if (ret < 0) {
		ERR_print_errors_fp(stderr);
		exit(1);
	}

	while (1) {
		char buf[10240];
		// int len = recv(cfd, buf, sizeof(buf), 0);
		int len = SSL_read(cssl, buf, sizeof(buf));
		if (len < 0) {
			printf("recv error %s\n", strerror(errno));
			exit(1);
		}
		if (len == 0) exit(0);

		printf("server => recv %d %s\n", len, buf);
		// len = send(cfd, buf, len, 0);
		len = SSL_write(cssl, buf, len);
		if (len < 0) {
			printf("send error %s\n", strerror(errno));
		}
		printf("server => send %d %s\n", len, buf);
	}

	SSL_shutdown(cssl);
	SSL_CTX_free(ssl_ctx);
	SSL_free(cssl);

}
int main(int argc, char* argv[]) {
	printf("test\n");
	int ret = OPENSSL_init_ssl(OPENSSL_INIT_LOAD_CONFIG, NULL);
	if (ret < 0) {
		printf("init ssl error\n");
	}
	run();
	return 0;
}

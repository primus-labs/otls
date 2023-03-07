#include<stdio.h>
#include<stdlib.h>
#include<string.h>
#include<arpa/inet.h>
#include<unistd.h>
#include<errno.h>
#include<netdb.h>
#include<string>
using namespace std;

#include<openssl/ssl.h>
#include<openssl/err.h>
#include<openssl/mpc_tls_socket.h>

#ifdef __EMSCRIPTEN__
#include <emscripten.h>
#include <emscripten/websocket.h>
#include <emscripten/threading.h>
#include <emscripten/posix_socket.h>

static EMSCRIPTEN_WEBSOCKET_T bridgeSocket = 0;
#endif

int mpc_tls_send(int fd, const char* buf, int len, int flag) {
    printf("mpc tls send============%d\n", len);
    for (int i = 0; i < len; i++)
        printf("%02x ", (unsigned char)buf[i]);
    printf("\n");
    return send(fd, buf, len, flag);
}

int mpc_tls_recv(int fd, char* buf, int len, int flag) {
    int ret = recv(fd, buf, len, flag);
    printf("mpc tls recv=============%d\n", len);
    for (int i = 0; i < ret; i++)
        printf("%02x ", (unsigned char)buf[i]);
    printf("\n");
    return ret;
}

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

string lookup_host(const char *host) {
  struct addrinfo hints, *res;
  int errcode;
  char addrstr[100];
  void *ptr;

  memset(&hints, 0, sizeof (hints));
  hints.ai_family = PF_UNSPEC;
  hints.ai_socktype = SOCK_STREAM;
  hints.ai_flags |= AI_CANONNAME;

  errcode = getaddrinfo(host, NULL, &hints, &res);
  if (errcode != 0) {
    printf("getaddrinfo failed!\n");
    return "";
  }

  printf("Host: %s\n", host);
  while (res) {
    inet_ntop(res->ai_family, res->ai_addr->sa_data, addrstr, 100);

    switch (res->ai_family) {
    case AF_INET:
      ptr = &((struct sockaddr_in *)res->ai_addr)->sin_addr;
      break;
    case AF_INET6:
      ptr = &((struct sockaddr_in6 *)res->ai_addr)->sin6_addr;
      break;
    }
    inet_ntop(res->ai_family, ptr, addrstr, 100);
    printf("IPv%d address: %s (%s)\n", res->ai_family == PF_INET6 ? 6 : 4, addrstr, res->ai_canonname);
	if (res->ai_family != PF_INET6)
		return string(addrstr);
    res = res->ai_next;
  }

  return "";
}

void run_client() {
	printf("begin loopup host\n");
    string ip = lookup_host("api.binance.com");
	printf("api.binance.com:%s\n", ip.c_str());
    int fd = socket(AF_INET, SOCK_STREAM, 0);
    if (fd < 0) {
        printf("create socket error %s\n", strerror(errno));
        exit(1);
    }
    printf("create socket ok\n");
    struct sockaddr_in server;
    memset(&server, 0, sizeof(server));
    server.sin_family = AF_INET;
    server.sin_port = htons(443);
    if (inet_pton(AF_INET, ip.c_str(), &server.sin_addr) < 0) {
        printf("pton error\n");
        exit(1);
    }

    int ret = connect(fd, (struct sockaddr*)&server, sizeof(server));
    if (ret < 0) {
        printf("connect error %s\n", strerror(errno));
        exit(1);
    }
    printf("connect ok\n");


    const SSL_METHOD* tlsv12 = TLS_method();
    SSL_CTX* ssl_ctx = SSL_CTX_new(tlsv12);
    SSL_CTX_set_ecdh_auto(ssl_ctx, 1);

    // *********************************
    SSL_CTX_set_min_proto_version(ssl_ctx, TLS1_2_VERSION);
    SSL_CTX_set_max_proto_version(ssl_ctx, TLS1_2_VERSION);
    int min_ver = SSL_CTX_get_min_proto_version(ssl_ctx);
    int max_ver = SSL_CTX_get_max_proto_version(ssl_ctx);
    printf("min version: %d, max version: %d\n", min_ver, max_ver);
    // *********************************
    
    SSL_CTX_set_verify(ssl_ctx, SSL_VERIFY_PEER, verify_callback);
    printf("begin load ca file\n");
    if(SSL_CTX_load_verify_locations(ssl_ctx, "binance.crt", NULL) <= 0) {
        ERR_print_errors_fp(stderr);
        exit(1);
    }
    printf("end load ca file\n");
    
    if (SSL_CTX_set_cipher_list(ssl_ctx, "ECDHE-RSA-AES128-GCM-SHA256") <=0) {
        ERR_print_errors_fp(stderr);
        exit(1);
    }
    if (SSL_CTX_set1_groups_list(ssl_ctx, "P-256") <= 0) {
        ERR_print_errors_fp(stderr);
        exit(1);
    }

    SSL* ssl = SSL_new(ssl_ctx);
    ret = SSL_set_fd(ssl, fd);
    if (ret < 0) {
        printf("ssl set fd error\n");
        exit(1);
    }
    
    printf("begin connect fd:%d\n", fd);
    ret = SSL_connect(ssl);
    if (ret < 0) {
        printf("connect error %s\n", strerror(errno));
        ERR_print_errors_fp(stdout);
        fflush(stdout);
        exit(1);
    }
    printf("SSL connect success\n");
    // ==========================
    printf("ssl cipher %s\n", SSL_get_cipher(ssl));

    X509* server_cert = SSL_get_peer_certificate(ssl);
    printf("server certificate:\n");
    char* subject = X509_NAME_oneline(X509_get_subject_name(server_cert), 0, 0);
    char* issuer = X509_NAME_oneline(X509_get_issuer_name(server_cert), 0, 0);
    printf("subject: %s\n", subject);
    printf("issuer: %s\n", issuer);

    OPENSSL_free(subject);
    OPENSSL_free(issuer);
    X509_free(server_cert);
    // ==========================

///sapi/v1/asset/get-funding-asset
    int count = 0;
    if (1) {
        char httpMsg[] = "GET /sapi/v1/system/status HTTP/1.1\r\n"
        "Host: api.binance.com\r\n"
        "User-Agent: Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:109.0) Gecko/20100101 Firefox/110.0\r\n"
        "Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8\r\n"
        "Accept-Language: en-US,en;q=0.5\r\n"
        "Accept-Encoding: gzip, deflate, br\r\n"
        "Connection: keep-alive\r\n"
		"Content-Type: application/x-www-form-urlencoded\r\n"
        "Upgrade-Insecure-Requests: 1\r\n"
        "Sec-Fetch-Dest: document\r\n"
        "Sec-Fetch-Mode: navigate\r\n"
        "Sec-Fetch-Site: none\r\n"
        "Sec-Fetch-User: ?1\r\n"
        "\r\n";

        char buf[10240];
		int t = time(NULL);
        // snprintf(buf, sizeof(buf), "message from client, id: %d", count++);
        int l = snprintf(buf, sizeof(buf), httpMsg, t);
        // int len = send(fd, buf, strlen(buf), 0);
        int len = SSL_write(ssl, buf, l);
        printf("client => send %d %s\n", l, buf);

        // len = recv(fd, buf, sizeof(buf), 0);
        len = SSL_read(ssl, buf, sizeof(buf));
        printf("client => recv %d %s\n", len, buf);
        sleep(1);
    }

    SSL_shutdown(ssl);
    SSL_CTX_free(ssl_ctx);
    SSL_free(ssl);

}
int main(int argc, char* argv[]) {
#ifdef __EMSCRIPTEN__
  bridgeSocket = emscripten_init_websocket_to_posix_socket_bridge("ws://18.179.8.186:9000");
  // Synchronously wait until connection has been established.
  uint16_t readyState = 0;
  printf("begin readystate\n");
  do {
    emscripten_websocket_get_ready_state(bridgeSocket, &readyState);
    emscripten_thread_sleep(100);
  } while (readyState == 0);
  printf("end readystate\n");
#endif

    int ret = OPENSSL_init_ssl(OPENSSL_INIT_LOAD_CONFIG, NULL);
    if (ret < 0) {
        printf("init ssl error\n");
        exit(1);
    }
    SSL_load_error_strings();
    OPENSSL_init_MPC_SOCKET(mpc_tls_send, mpc_tls_recv);
    run_client();
    return 0;
}

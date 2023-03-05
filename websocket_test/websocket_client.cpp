#include<stdio.h>
#include<stdlib.h>
#include<string.h>
#include<arpa/inet.h>
#include<unistd.h>
#include<errno.h>
#include<netdb.h>

#include<openssl/ssl.h>
#include<openssl/err.h>
#include<openssl/mpc_tls_socket.h>
#include<vector>

#ifdef __EMSCRIPTEN__
#include <emscripten.h>
#include <emscripten/websocket.h>
#include <emscripten/threading.h>
#include <emscripten/posix_socket.h>

static pthread_mutex_t bridgeLock = PTHREAD_MUTEX_INITIALIZER;
static EMSCRIPTEN_WEBSOCKET_T bridgeSocket = 0;
#endif

#ifdef __EMSCRIPTEN__
// Uncomment to enable debug printing
// #define POSIX_SOCKET_DEBUG

// Uncomment to enable more verbose debug printing (in addition to uncommenting POSIX_SOCKET_DEBUG)
// #define POSIX_SOCKET_DEEP_DEBUG

#define MIN(a,b) (((a)<(b))?(a):(b))

static std::vector<uint8_t> recv_buffer;
static pthread_mutex_t recvLock = PTHREAD_MUTEX_INITIALIZER;
static int recvBufferFlag = 0;
static EM_BOOL
bridge_socket_on_message2(int eventType,
                         const EmscriptenWebSocketMessageEvent* websocketEvent,
                         void* userData) {
  pthread_mutex_lock(&recvLock);
  uint8_t *data = (uint8_t*)websocketEvent->data;
  recv_buffer.insert(recv_buffer.end(), data, data + websocketEvent->numBytes);
  recvBufferFlag = 1;
  pthread_mutex_unlock(&recvLock);
  emscripten_futex_wake(&recvBufferFlag, INT_MAX);

  return EM_TRUE;
}

EMSCRIPTEN_WEBSOCKET_T emscripten_init_websocket_to_posix_socket_bridge2(const char *bridgeUrl) {
#ifdef POSIX_SOCKET_DEBUG
  emscripten_log(EM_LOG_NO_PATHS | EM_LOG_CONSOLE | EM_LOG_JS_STACK, "emscripten_init_websocket_to_posix_socket_bridge(bridgeUrl=\"%s\")\n", bridgeUrl);
#endif
  pthread_mutex_lock(&bridgeLock); // Guard multithreaded access to 'bridgeSocket'
  if (bridgeSocket) {
#ifdef POSIX_SOCKET_DEBUG
    emscripten_log(EM_LOG_NO_PATHS | EM_LOG_CONSOLE | EM_LOG_WARN | EM_LOG_JS_STACK, "emscripten_init_websocket_to_posix_socket_bridge(bridgeUrl=\"%s\"): A previous bridge socket connection handle existed! Forcibly tearing old connection down.\n", bridgeUrl);
#endif
    emscripten_websocket_close(bridgeSocket, 0, 0);
    emscripten_websocket_delete(bridgeSocket);
    bridgeSocket = 0;
  }
  EmscriptenWebSocketCreateAttributes attr;
  emscripten_websocket_init_create_attributes(&attr);
  attr.url = bridgeUrl;
  bridgeSocket = emscripten_websocket_new(&attr);
  emscripten_websocket_set_onmessage_callback_on_thread(bridgeSocket, 0, bridge_socket_on_message2, EM_CALLBACK_THREAD_CONTEXT_MAIN_BROWSER_THREAD);

  pthread_mutex_unlock(&bridgeLock);
  return bridgeSocket;
}

ssize_t send2(int socket, const void *message, size_t length, int flags) {
#ifdef POSIX_SOCKET_DEBUG
  emscripten_log(EM_LOG_NO_PATHS | EM_LOG_CONSOLE | EM_LOG_ERROR | EM_LOG_JS_STACK, "send(socket=%d,message=%p,length=%zd,flags=%d)\n", socket, message, length, flags);
#endif
  emscripten_websocket_send_binary(bridgeSocket, (void *)message, length);

  return length;
}

ssize_t recv2(int socket, void *buffer, size_t length, int flags) {
#ifdef POSIX_SOCKET_DEBUG
  emscripten_log(EM_LOG_NO_PATHS | EM_LOG_CONSOLE | EM_LOG_ERROR | EM_LOG_JS_STACK, "recv(socket=%d,buffer=%p,length=%zd,flags=%d)\n", socket, buffer, length, flags);
#endif

  while (!recvBufferFlag)
	  emscripten_futex_wait(&recvBufferFlag, 0, 1e9);

  pthread_mutex_lock(&recvLock);
  ssize_t min_length = length < recv_buffer.size()? length: recv_buffer.size();
  memcpy(buffer, recv_buffer.data(), min_length);
  recv_buffer.erase(recv_buffer.begin(), recv_buffer.begin() + min_length);
  if (!recv_buffer.empty()) 
	  recvBufferFlag = 1;
  else
	  recvBufferFlag = 0;
  pthread_mutex_unlock(&recvLock);

  return min_length;
}

#endif
int mpc_tls_send(int fd, const char* buf, int len, int flag) {
    printf("mpc tls send============ %d\n", len);
	for (int i = 0; i < len; i++)
		printf("%02x ", (unsigned char)buf[i]);
	printf("\n");
    return send2(fd, buf, len, flag);
}

int mpc_tls_recv(int fd, char* buf, int len, int flag) {
    printf("mpc tls recv============= %d\n", len);
    return recv2(fd, buf, len, flag);
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

void run_client() {
	int fd = 20;
	int ret;

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
    if(SSL_CTX_load_verify_locations(ssl_ctx, "ca.crt", NULL) <= 0) {
        ERR_print_errors_fp(stderr);
        exit(1);
    }
    printf("end load ca file\n");
    
    if (SSL_CTX_set_cipher_list(ssl_ctx, "ECDHE-ECDSA-AES128-GCM-SHA256") <=0) {
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


    int count = 0;
    while (1) {
        char buf[10240];
        snprintf(buf, sizeof(buf), "message from client, id: %d", count++);
        // int len = send(fd, buf, strlen(buf), 0);
        int len = SSL_write(ssl, buf, strlen(buf));
        printf("client => send %d %s\n", len, buf);

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
  bridgeSocket = emscripten_init_websocket_to_posix_socket_bridge2("ws://localhost:9000");
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

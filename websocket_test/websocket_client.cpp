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

static void *memdup(const void *ptr, size_t sz) {
  if (!ptr) return 0;
  void *dup = malloc(sz);
  if (dup) memcpy(dup, ptr, sz);
  return dup;
}

// Each proxied socket call has at least the following data.
typedef struct SocketCallHeader {
  int callId;
  int function;
} SocketCallHeader;

// Each socket call returns at least the following data.
typedef struct SocketCallResultHeader {
  int callId;
  int ret;
  int errno_;
  // Buffer can contain more data here, conceptually:
  // uint8_t extraData[];
} SocketCallResultHeader;

typedef struct PosixSocketCallResult {
  struct PosixSocketCallResult *next;
  int callId;
  _Atomic uint32_t operationCompleted;

  // Before the call has finished, this field represents the minimum expected
  // number of bytes that server will need to report back.  After the call has
  // finished, this field reports back the number of bytes pointed to by data,
  // >= the expected value.
  int bytes;

  // Result data:
  SocketCallResultHeader *data;
} PosixSocketCallResult;
// Stores a linked list of all currently pending sockets operations (ones that
// are waiting for a reply back from the sockets proxy server)
static PosixSocketCallResult *callResultHead = 0;

static PosixSocketCallResult *allocate_call_result(int expectedBytes) {
  pthread_mutex_lock(&bridgeLock); // Guard multithreaded access to 'callResultHead' and 'nextId' below
  PosixSocketCallResult *b = (PosixSocketCallResult*)(malloc(sizeof(PosixSocketCallResult)));
  if (!b) {
#ifdef POSIX_SOCKET_DEBUG
    emscripten_log(EM_LOG_NO_PATHS | EM_LOG_CONSOLE | EM_LOG_ERROR | EM_LOG_JS_STACK, "allocate_call_result: Failed to allocate call result struct of size %d bytes!\n", (int)sizeof(PosixSocketCallResult));
#endif
    pthread_mutex_unlock(&bridgeLock);
    return 0;
  }
  static int nextId = 1;
  b->callId = nextId++;
#ifdef POSIX_SOCKET_DEEP_DEBUG
  emscripten_log(EM_LOG_NO_PATHS | EM_LOG_CONSOLE | EM_LOG_ERROR | EM_LOG_JS_STACK, "allocate_call_result: allocated call ID %d\n", b->callId);
#endif
  b->bytes = expectedBytes;
  b->data = 0;
  b->operationCompleted = 0;
  b->next = 0;

  if (!callResultHead) {
    callResultHead = b;
  } else {
    PosixSocketCallResult *t = callResultHead;
    while (t->next) t = t->next;
    t->next = b;
  }
  pthread_mutex_unlock(&bridgeLock);
  return b;
}

static void free_call_result(PosixSocketCallResult *buffer) {
#ifdef POSIX_SOCKET_DEEP_DEBUG
  if (buffer)
    emscripten_log(EM_LOG_NO_PATHS | EM_LOG_CONSOLE | EM_LOG_ERROR | EM_LOG_JS_STACK, "free_call_result: freed call ID %d\n", buffer->callId);
#endif

  if (buffer->data) free(buffer->data);
  free(buffer);
}

static PosixSocketCallResult *pop_call_result(int callId) {
  pthread_mutex_lock(&bridgeLock); // Guard multithreaded access to 'callResultHead'
  PosixSocketCallResult *prev = 0;
  PosixSocketCallResult *b = callResultHead;
  while (b) {
    if (b->callId == callId) {
      if (prev) prev->next = b->next;
      else callResultHead = b->next;
      b->next = 0;
#ifdef POSIX_SOCKET_DEEP_DEBUG
      emscripten_log(EM_LOG_NO_PATHS | EM_LOG_CONSOLE | EM_LOG_ERROR | EM_LOG_JS_STACK, "pop_call_result: Removed call ID %d from pending sockets call queue\n", callId);
#endif
      pthread_mutex_unlock(&bridgeLock);
      return b;
    }
    prev = b;
    b = b->next;
  }
  pthread_mutex_unlock(&bridgeLock);
#ifdef POSIX_SOCKET_DEBUG
  emscripten_log(EM_LOG_NO_PATHS | EM_LOG_CONSOLE | EM_LOG_ERROR | EM_LOG_JS_STACK, "pop_call_result: No such call ID %d in pending sockets call queue!\n", callId);
#endif
  return 0;
}

static void wait_for_call_result(PosixSocketCallResult *b) {
#ifdef POSIX_SOCKET_DEEP_DEBUG
  emscripten_log(EM_LOG_NO_PATHS | EM_LOG_CONSOLE | EM_LOG_ERROR | EM_LOG_JS_STACK, "wait_for_call_result: Waiting for call ID %d\n", b->callId);
#endif
  while (!b->operationCompleted) {
    emscripten_futex_wait(&b->operationCompleted, 0, 1e9);
  }
#ifdef POSIX_SOCKET_DEEP_DEBUG
  emscripten_log(EM_LOG_NO_PATHS | EM_LOG_CONSOLE | EM_LOG_ERROR | EM_LOG_JS_STACK, "wait_for_call_result: Waiting for call ID %d done\n", b->callId);
#endif
}


static EM_BOOL
bridge_socket_on_message2(int eventType,
                         const EmscriptenWebSocketMessageEvent* websocketEvent,
                         void* userData) {
  if (websocketEvent->numBytes < sizeof(SocketCallResultHeader)) {
    emscripten_log(EM_LOG_NO_PATHS | EM_LOG_CONSOLE | EM_LOG_ERROR | EM_LOG_JS_STACK, "Received corrupt WebSocket result message with size %d, not enough space for header, at least %d bytes!\n", (int)websocketEvent->numBytes, (int)sizeof(SocketCallResultHeader));
    return EM_TRUE;
  }

  SocketCallResultHeader *header = (SocketCallResultHeader *)websocketEvent->data;

#ifdef POSIX_SOCKET_DEEP_DEBUG
  emscripten_log(EM_LOG_NO_PATHS | EM_LOG_CONSOLE | EM_LOG_ERROR | EM_LOG_JS_STACK, "POSIX sockets bridge received message on thread %p, size: %d bytes, for call ID %d\n", (void*)pthread_self(), websocketEvent->numBytes, header->callId);
#endif

  PosixSocketCallResult *b = pop_call_result(header->callId);
  if (!b) {
    emscripten_log(EM_LOG_NO_PATHS | EM_LOG_CONSOLE | EM_LOG_ERROR | EM_LOG_JS_STACK, "Received WebSocket result message to unknown call ID %d!\n", (int)header->callId);
    // TODO: Craft a socket result that signifies a failure, and wake the listening thread
    return EM_TRUE;
  }

  if (websocketEvent->numBytes < b->bytes) {
    emscripten_log(EM_LOG_NO_PATHS | EM_LOG_CONSOLE | EM_LOG_ERROR | EM_LOG_JS_STACK, "Received corrupt WebSocket result message with size %d, expected at least %d bytes!\n", (int)websocketEvent->numBytes, b->bytes);
    // TODO: Craft a socket result that signifies a failure, and wake the listening thread
    return EM_TRUE;
  }

  b->bytes = websocketEvent->numBytes;
  b->data = (SocketCallResultHeader*)memdup(websocketEvent->data, websocketEvent->numBytes);

  if (!b->data) {
    emscripten_log(EM_LOG_NO_PATHS | EM_LOG_CONSOLE | EM_LOG_ERROR | EM_LOG_JS_STACK, "Out of memory, tried to allocate %d bytes!\n", websocketEvent->numBytes);
    return EM_TRUE;
  }

  if (b->operationCompleted != 0) {
    emscripten_log(EM_LOG_NO_PATHS | EM_LOG_CONSOLE | EM_LOG_ERROR | EM_LOG_JS_STACK, "Memory corruption(?): the received result for completed operation at address %p was expected to be in state 0, but it was at state %d!\n", &b->operationCompleted, (int)b->operationCompleted);
  }

  b->operationCompleted = 1;
  emscripten_futex_wake(&b->operationCompleted, INT_MAX);

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
#define POSIX_SOCKET_MSG_SOCKET 1
#define POSIX_SOCKET_MSG_SOCKETPAIR 2
#define POSIX_SOCKET_MSG_SHUTDOWN 3
#define POSIX_SOCKET_MSG_BIND 4
#define POSIX_SOCKET_MSG_CONNECT 5
#define POSIX_SOCKET_MSG_LISTEN 6
#define POSIX_SOCKET_MSG_ACCEPT 7
#define POSIX_SOCKET_MSG_GETSOCKNAME 8
#define POSIX_SOCKET_MSG_GETPEERNAME 9
#define POSIX_SOCKET_MSG_SEND 10
#define POSIX_SOCKET_MSG_RECV 11
#define POSIX_SOCKET_MSG_SENDTO 12
#define POSIX_SOCKET_MSG_RECVFROM 13
#define POSIX_SOCKET_MSG_SENDMSG 14
#define POSIX_SOCKET_MSG_RECVMSG 15
#define POSIX_SOCKET_MSG_GETSOCKOPT 16
#define POSIX_SOCKET_MSG_SETSOCKOPT 17
#define POSIX_SOCKET_MSG_GETADDRINFO 18
#define POSIX_SOCKET_MSG_GETNAMEINFO 19

int socket2(int domain, int type, int protocol) {
#ifdef POSIX_SOCKET_DEBUG
  emscripten_log(EM_LOG_NO_PATHS | EM_LOG_CONSOLE | EM_LOG_ERROR | EM_LOG_JS_STACK, "socket(domain=%d,type=%d,protocol=%d) on thread %p\n", domain, type, protocol, (void*)pthread_self());
#endif

  struct {
    SocketCallHeader header;
    int domain;
    int type;
    int protocol;
  } d;

  PosixSocketCallResult *b = allocate_call_result(sizeof(SocketCallResultHeader));
  d.header.callId = b->callId;
  d.header.function = POSIX_SOCKET_MSG_SOCKET;
  d.domain = domain;
  d.type = type;
  d.protocol = protocol;
  emscripten_websocket_send_binary(bridgeSocket, &d, sizeof(d));

  wait_for_call_result(b);
  int ret = b->data->ret;
  if (ret < 0) errno = b->data->errno_;
  free_call_result(b);
  return ret;
}

int connect2(int socket, const struct sockaddr *address, socklen_t address_len) {
#ifdef POSIX_SOCKET_DEBUG
  emscripten_log(EM_LOG_NO_PATHS | EM_LOG_CONSOLE | EM_LOG_ERROR | EM_LOG_JS_STACK, "connect(socket=%d,address=%p,address_len=%d)\n", socket, address, address_len);
#endif

  typedef struct Data {
    SocketCallHeader header;
    int socket;
    uint32_t/*socklen_t*/ address_len;
    uint8_t address[];
  } Data;
  int numBytes = sizeof(Data) + address_len;
  Data *d = (Data*)malloc(numBytes);

  PosixSocketCallResult *b = allocate_call_result(sizeof(SocketCallResultHeader));
  d->header.callId = b->callId;
  d->header.function = POSIX_SOCKET_MSG_CONNECT;
  d->socket = socket;
  d->address_len = address_len;
  if (address) memcpy(d->address, address, address_len);
  else memset(d->address, 0, address_len);
  emscripten_websocket_send_binary(bridgeSocket, d, numBytes);

  wait_for_call_result(b);
  int ret = b->data->ret;
  if (ret != 0) errno = b->data->errno_;
  free_call_result(b);

  free(d);
  return ret;
}

ssize_t send2(int socket, const void *message, size_t length, int flags) {
#ifdef POSIX_SOCKET_DEBUG
  emscripten_log(EM_LOG_NO_PATHS | EM_LOG_CONSOLE | EM_LOG_ERROR | EM_LOG_JS_STACK, "send(socket=%d,message=%p,length=%zd,flags=%d)\n", socket, message, length, flags);
#endif

  typedef struct MSG {
    SocketCallHeader header;
    int socket;
    uint32_t/*size_t*/ length;
    int flags;
    uint8_t message[];
  } MSG;
  size_t sz = sizeof(MSG)+length;
  MSG *d = (MSG*)malloc(sz);

  PosixSocketCallResult *b = allocate_call_result(sizeof(SocketCallResultHeader));
  d->header.callId = b->callId;
  d->header.function = POSIX_SOCKET_MSG_SEND;
  d->socket = socket;
  d->length = length;
  d->flags = flags;
  if (message) memcpy(d->message, message, length);
  else memset(d->message, 0, length);
  emscripten_websocket_send_binary(bridgeSocket, d, sz);

  wait_for_call_result(b);
  int ret = b->data->ret;
  if (ret < 0) errno = b->data->errno_;
  free_call_result(b);

  free(d);
  return ret;
}

ssize_t recv2(int socket, void *buffer, size_t length, int flags) {
#ifdef POSIX_SOCKET_DEBUG
  emscripten_log(EM_LOG_NO_PATHS | EM_LOG_CONSOLE | EM_LOG_ERROR | EM_LOG_JS_STACK, "recv(socket=%d,buffer=%p,length=%zd,flags=%d)\n", socket, buffer, length, flags);
#endif

  struct {
    SocketCallHeader header;
    int socket;
    uint32_t/*size_t*/ length;
    int flags;
  } d;

  PosixSocketCallResult *b = allocate_call_result(sizeof(SocketCallResultHeader));
  d.header.callId = b->callId;
  d.header.function = POSIX_SOCKET_MSG_RECV;
  d.socket = socket;
  d.length = length;
  d.flags = flags;
  emscripten_websocket_send_binary(bridgeSocket, &d, sizeof(d));

  wait_for_call_result(b);
  int ret = b->data->ret;
  if (ret >= 0) {
    typedef struct Result {
      SocketCallResultHeader header;
      uint8_t data[];
    } Result;
    Result *r = (Result*)b->data;
    if (buffer) memcpy(buffer, r->data, MIN(ret, length));
  } else {
    errno = b->data->errno_;
  }
  free_call_result(b);

  return ret;
}

#endif
int mpc_tls_send(int fd, const char* buf, int len, int flag) {
    printf("mpc tls send============ %d\n", len);
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

/*int lookup_host(const char *host) {
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
    return -1;
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
    res = res->ai_next;
  }

  return 0;
}*/

void run_client() {
    // lookup_host("bing.com");
    printf("begin socket\n");
    int fd = socket2(AF_INET, SOCK_STREAM, 0);
    printf("socket %d\n", fd);
    if (fd < 0) {
        printf("create socket error %s\n", strerror(errno));
        exit(1);
    }
    struct sockaddr_in server;
    memset(&server, 0, sizeof(server));
    server.sin_family = AF_INET;
    server.sin_port = htons(8080);
    if (inet_pton(AF_INET, "127.0.0.1", &server.sin_addr) < 0) {
        printf("pton error\n");
        exit(1);
    }

    int ret = connect2(fd, (struct sockaddr*)&server, sizeof(server));
    if (ret < 0) {
        printf("connect error %s\n", strerror(errno));
        exit(1);
    }


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
    
    /*int r = send2(fd, "hello world", strlen("hello world"), 0);
    char buffer[20];
    memset(buffer, 0, sizeof(buffer));
    r = recv2(fd, buffer, 11, 0);
    printf("recv: %s\n", buffer);*/
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
    if (1) {
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

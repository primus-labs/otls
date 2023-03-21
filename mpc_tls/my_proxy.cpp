// Alternative socket system implementation that gets compiled to
// libsockets_proxy.a and included when the `-sPROXY_POSIX_SOCKETS`
// is used.

#include <assert.h>
#include <errno.h>
#include <limits.h>
#include <netdb.h>
#include <stdio.h>
#include <stdlib.h>
#include <pthread.h>
#include <sys/socket.h>
#if defined(__APPLE__) || defined(__linux__)
#include <arpa/inet.h>
#endif

#include <string.h>
#include <unistd.h>
#include "ws.h"
#include "my_proxy.h"
// #include <emscripten/console.h>
// #include <emscripten/threading.h>
// #include <emscripten/websocket.h>

// Uncomment to enable debug printing
// #define POSIX_SOCKET_DEBUG

// Uncomment to enable more verbose debug printing (in addition to uncommenting POSIX_SOCKET_DEBUG)
// #define POSIX_SOCKET_DEEP_DEBUG

#define MIN(a,b) (((a)<(b))?(a):(b))

typedef int EM_BOOL;
#define EM_TRUE 1

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
  uint32_t operationCompleted;

  // Before the call has finished, this field represents the minimum expected
  // number of bytes that server will need to report back.  After the call has
  // finished, this field reports back the number of bytes pointed to by data,
  // >= the expected value.
  int bytes;

  // Result data:
  SocketCallResultHeader *data;
} PosixSocketCallResult;

// Shield multithreaded accesses to POSIX sockets functions in the program,
// namely the two variables 'bridgeSocket' and 'callResultHead' below.
static pthread_mutex_t bridgeLock = PTHREAD_MUTEX_INITIALIZER;

// Socket handle for the connection from browser WebSocket to the sockets bridge
// proxy server.
static int bridgeSocket = 0;

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

static EM_BOOL
bridge_socket_on_message(const char* data,
                         size_t numBytes) {
  if (numBytes < sizeof(SocketCallResultHeader)) {
    // emscripten_log(EM_LOG_NO_PATHS | EM_LOG_CONSOLE | EM_LOG_ERROR | EM_LOG_JS_STACK, "Received corrupt WebSocket result message with size %d, not enough space for header, at least %d bytes!\n", (int)numBytes, (int)sizeof(SocketCallResultHeader));
    return EM_TRUE;
  }

  SocketCallResultHeader *header = (SocketCallResultHeader *)data;

#ifdef POSIX_SOCKET_DEEP_DEBUG
  emscripten_log(EM_LOG_NO_PATHS | EM_LOG_CONSOLE | EM_LOG_ERROR | EM_LOG_JS_STACK, "POSIX sockets bridge received message on thread %p, size: %d bytes, for call ID %d\n", (void*)pthread_self(), numBytes, header->callId);
#endif

  PosixSocketCallResult *b = pop_call_result(header->callId);
  if (!b) {
    // emscripten_log(EM_LOG_NO_PATHS | EM_LOG_CONSOLE | EM_LOG_ERROR | EM_LOG_JS_STACK, "Received WebSocket result message to unknown call ID %d!\n", (int)header->callId);
    // TODO: Craft a socket result that signifies a failure, and wake the listening thread
    assert(false);
    return EM_TRUE;
  }

  if (numBytes < b->bytes) {
    // emscripten_log(EM_LOG_NO_PATHS | EM_LOG_CONSOLE | EM_LOG_ERROR | EM_LOG_JS_STACK, "Received corrupt WebSocket result message with size %d, expected at least %d bytes!\n", (int)numBytes, b->bytes);
    // TODO: Craft a socket result that signifies a failure, and wake the listening thread
    assert(false);
    return EM_TRUE;
  }

  b->bytes = numBytes;
  b->data = (SocketCallResultHeader*)memdup(data, numBytes);

  if (!b->data) {
    assert(false);
    // emscripten_log(EM_LOG_NO_PATHS | EM_LOG_CONSOLE | EM_LOG_ERROR | EM_LOG_JS_STACK, "Out of memory, tried to allocate %d bytes!\n", numBytes);
    return EM_TRUE;
  }

  if (b->operationCompleted != 0) {
    assert(false);
    // emscripten_log(EM_LOG_NO_PATHS | EM_LOG_CONSOLE | EM_LOG_ERROR | EM_LOG_JS_STACK, "Memory corruption(?): the received result for completed operation at address %p was expected to be in state 0, but it was at state %d!\n", &b->operationCompleted, (int)b->operationCompleted);
  }

  b->operationCompleted = 1;
  // emscripten_futex_wake(&b->operationCompleted, INT_MAX);

  return EM_TRUE;
}

static void wait_for_call_result(PosixSocketCallResult *b) {
#ifdef POSIX_SOCKET_DEEP_DEBUG
  emscripten_log(EM_LOG_NO_PATHS | EM_LOG_CONSOLE | EM_LOG_ERROR | EM_LOG_JS_STACK, "wait_for_call_result: Waiting for call ID %d\n", b->callId);
#endif
  while (!b->operationCompleted) {
      string s = GetMessageProxy(bridgeSocket, b->bytes, (uint64_t)b->callId, false);
      bridge_socket_on_message(s.data(), s.size());
  }
#ifdef POSIX_SOCKET_DEEP_DEBUG
  emscripten_log(EM_LOG_NO_PATHS | EM_LOG_CONSOLE | EM_LOG_ERROR | EM_LOG_JS_STACK, "wait_for_call_result: Waiting for call ID %d done\n", b->callId);
#endif
}

#ifndef __EMSCRIPTEN__
int emscripten_init_websocket_to_posix_socket_bridge(const char *address, int port) {
  struct sockaddr_in dest;
  memset(&dest, 0, sizeof(dest));
  dest.sin_family = AF_INET;
  dest.sin_addr.s_addr = inet_addr(address);
  dest.sin_port = htons(port);

  while(1) {
      bridgeSocket = socket(AF_INET, SOCK_STREAM, 0);

      if (connect(bridgeSocket, (struct sockaddr *)&dest, sizeof(struct sockaddr)) == 0) {
          break;
      }

      close(bridgeSocket);
      usleep(1000);
  }
  printf("to request handshake\n");
  RequestWebSocketHandshake(bridgeSocket);
  printf("to check handshake\n");
  CheckWebSocketHandshake(bridgeSocket);
  printf("handshake ok\n");
  return bridgeSocket;
}
#endif

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

#define MAX_SOCKADDR_SIZE 256
#define MAX_OPTIONVALUE_SIZE 16

static send_meth send_binary;
int init_proxy(send_meth send) {
    send_binary = send;
    return 0;
}

static int websocket_send_binary(int fd, const void* buf, int len, int id) {
    string s = GenWebSocketMessageProxy(buf, len, (uint64_t)id, false);
    return send_binary(fd, s.data(), s.size());
}

int socket3(int domain, int type, int protocol) {
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
  printf("begin send binary\n");
  websocket_send_binary(bridgeSocket, &d, sizeof(d), b->callId);
  printf("begin wait for call result\n");

  wait_for_call_result(b);
  printf("end wait for call result\n");
  int ret = b->data->ret;
  if (ret < 0) errno = b->data->errno_;
  free_call_result(b);
  return ret;
}

int connect3(int socket, const struct sockaddr *address, socklen_t address_len) {
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
  websocket_send_binary(bridgeSocket, d, numBytes, b->callId);

  wait_for_call_result(b);
  int ret = b->data->ret;
  if (ret != 0) errno = b->data->errno_;
  free_call_result(b);

  free(d);
  return ret;
}

ssize_t send3(int socket, const void *message, size_t length, int flags) {
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
  websocket_send_binary(bridgeSocket, d, sz, b->callId);

  wait_for_call_result(b);
  int ret = b->data->ret;
  if (ret < 0) errno = b->data->errno_;
  free_call_result(b);

  free(d);
  return ret;
}

ssize_t recv3(int socket, void *buffer, size_t length, int flags) {
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
  websocket_send_binary(bridgeSocket, &d, sizeof(d), b->callId);

  wait_for_call_result(b);
  int ret = b->data->ret;
  printf("recv3 result:%d\n", ret);
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


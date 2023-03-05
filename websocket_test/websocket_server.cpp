#include<stdio.h>
#include<stdlib.h>
#include<assert.h>
#include<string.h>
#include<arpa/inet.h>
#include<unistd.h>
#include<errno.h>

#include<openssl/ssl.h>
#include<openssl/err.h>
#include<openssl/mpc_tls_socket.h>
#include<vector>
#include "sha1.h"
#define WEBSOCKET
#define PROXY_DEEP_DEBUG

#ifdef WEBSOCKET
#if defined(__unix__) || defined(__APPLE__) || defined(__linux__)
#include <pthread.h>
#define THREAD_T pthread_t
#define CREATE_THREAD(threadPtr, threadFunc, threadArg) pthread_create(&threadPtr, 0, threadFunc, threadArg)
#define CREATE_THREAD_RETURN_T int
#define CREATE_THREAD_SUCCEEDED(x) (x == 0)
#define EXIT_THREAD(code) pthread_exit((void*)(uintptr_t)code)
#define THREAD_RETURN_T void*
#define MUTEX_T pthread_mutex_t
inline void CREATE_MUTEX(MUTEX_T *m)
{
    pthread_mutex_init(m, 0);
}
#define LOCK_MUTEX(m) pthread_mutex_lock(m)
#define UNLOCK_MUTEX(m) pthread_mutex_unlock(m)
#endif
#ifdef __cplusplus
extern "C" {
#endif

uint64_t ntoh64(uint64_t x);
#define hton64 ntoh64

#ifdef __cplusplus
}
#endif

#define SOCKET_T int
#define SHUTDOWN_READ SHUT_RD
#define SHUTDOWN_WRITE SHUT_WR
#define SHUTDOWN_BIDIRECTIONAL SHUT_RDWR
#define SETSOCKOPT_PTR_TYPE const int*
#define SEND_RET_TYPE ssize_t
#define SEND_FORMATTING_SPECIFIER "%ld"
#define CLOSE_SOCKET(x) close(x)

#define GET_SOCKET_ERROR() (errno)

#define PRINT_SOCKET_ERROR(errorCode) do { \
  printf("Call failed! errno: %s(%d)\n", strerror(errorCode), errorCode); \
  } while(0)

// thread-safe, re-entrant
uint64_t ntoh64(uint64_t x) {
  return ntohl(x>>32) | ((uint64_t)ntohl(x&0xFFFFFFFFu) << 32);
}
#ifdef _MSC_VER
#pragma pack(push,1)
#endif

typedef struct
#if defined(__GNUC__)
__attribute__ ((packed, aligned(1)))
#endif
WebSocketMessageHeader {
  unsigned opcode : 4;
  unsigned rsv : 3;
  unsigned fin : 1;
  unsigned payloadLength : 7;
  unsigned mask : 1;
} WebSocketMessageHeader;

#ifdef _MSC_VER
__pragma(pack(pop))
#endif
// #define PROXY_DEBUG

// #define PROXY_DEEP_DEBUG

static const unsigned char b64[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
static void base64_encode(void *dst, const void *src, size_t len) // thread-safe, re-entrant
{
  assert(dst != src);
  unsigned int *d = (unsigned int *)dst;
  const unsigned char *s = (const unsigned char*)src;
  const unsigned char *end = s + len;
  while(s < end)
  {
    uint32_t e = *s++ << 16;
    if (s < end) e |= *s++ << 8;
    if (s < end) e |= *s++;
    *d++ = b64[e >> 18] | (b64[(e >> 12) & 0x3F] << 8) | (b64[(e >> 6) & 0x3F] << 16) | (b64[e & 0x3F] << 24);
  }
  for (size_t i = 0; i < (3 - (len % 3)) % 3; i++) ((char *)d)[-1-i] = '=';
}

#define BUFFER_SIZE 1024
#define on_error(...) { fprintf(stderr, __VA_ARGS__); fflush(stderr); exit(1); }
#define MIN(a, b) ((a) <= (b) ? (a) : (b))

// Given a multiline string of HTTP headers, returns a pointer to the beginning of the value of given header inside the string that was passed in.
static int GetHttpHeader(const char *headers, const char *header, char *out, int maxBytesOut) // thread-safe, re-entrant
{
  const char *pos = strstr(headers, header);
  if (!pos) return 0;
  pos += strlen(header);
  const char *end = pos;
  while(*end != '\r' && *end != '\n' && *end != '\0') ++end;
  int numBytesToWrite = MIN((int)(end-pos), maxBytesOut-1);
  memcpy(out, pos, numBytesToWrite);
  out[numBytesToWrite] = '\0';
  return (int)(end-pos);
}

// Sends WebSocket handshake back to the given WebSocket connection.
void SendHandshake(int fd, const char *request)
{
  const char webSocketGlobalGuid[] = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11"; // 36 characters long
  char key[128+sizeof(webSocketGlobalGuid)];
  GetHttpHeader(request, "Sec-WebSocket-Key: ", key, sizeof(key)/2);
  strcat(key, webSocketGlobalGuid);

  char sha1[21];
  printf("hashing key: \"%s\"\n", key);
  SHA1(sha1, key, (int)strlen(key));

  char handshakeMsg[] = 
    "HTTP/1.1 101 Switching Protocols\r\n"
    "Upgrade: websocket\r\n"
    "Connection: Upgrade\r\n"
    "Sec-WebSocket-Accept: 0000000000000000000000000000\r\n"
    "\r\n";

  base64_encode(strstr(handshakeMsg, "Sec-WebSocket-Accept: ") + strlen("Sec-WebSocket-Accept: "), sha1, 20);

  int err = send(fd, handshakeMsg, (int)strlen(handshakeMsg), 0);
  if (err < 0) on_error("Client write failed\n");
  printf("Sent handshake:\n%s\n", handshakeMsg);
}

// Validates if the given, possibly partially received WebSocket message has enough bytes to contain a full WebSocket header.
static bool WebSocketHasFullHeader(uint8_t *data, uint64_t obtainedNumBytes)
{
  if (obtainedNumBytes < 2) return false;
  uint64_t expectedNumBytes = 2;
  WebSocketMessageHeader *header = (WebSocketMessageHeader *)data;
  if (header->mask) expectedNumBytes += 4;
  switch(header->payloadLength)
  {
    case 127: return expectedNumBytes += 8; break;
    case 126: return expectedNumBytes += 2; break;
    default: break;
  }
  return obtainedNumBytes >= expectedNumBytes;
}

// Computes the total number of bytes that the given WebSocket message will take up.
uint64_t WebSocketFullMessageSize(uint8_t *data, uint64_t obtainedNumBytes)
{
  assert(WebSocketHasFullHeader(data, obtainedNumBytes));

  uint64_t expectedNumBytes = 2;
  WebSocketMessageHeader *header = (WebSocketMessageHeader *)data;
  if (header->mask) expectedNumBytes += 4;
  switch(header->payloadLength)
  {
    case 127: return expectedNumBytes += 8 + ntoh64(*(uint64_t*)(data+2)); break;
    case 126: return expectedNumBytes += 2 + ntohs(*(uint16_t*)(data+2)); break;
    default: expectedNumBytes += header->payloadLength; break;
  }
  return expectedNumBytes;
}

// Tests the structure integrity of the websocket message length.
bool WebSocketValidateMessageSize(uint8_t *data, uint64_t obtainedNumBytes)
{
  uint64_t expectedNumBytes = WebSocketFullMessageSize(data, obtainedNumBytes);

  if (expectedNumBytes != obtainedNumBytes)
  {
    printf("Corrupt WebSocket message size! (got %llu bytes, expected %llu bytes)\n", obtainedNumBytes, expectedNumBytes);
    printf("Received data:");
    for(size_t i = 0; i < obtainedNumBytes; ++i)
      printf(" %02X", data[i]);
    printf("\n");
  }
  return expectedNumBytes == obtainedNumBytes;
}

uint64_t WebSocketMessagePayloadLength(uint8_t *data, uint64_t numBytes)
{
  WebSocketMessageHeader *header = (WebSocketMessageHeader *)data;
  switch(header->payloadLength)
  {
    case 127: return ntoh64(*(uint64_t*)(data+2));
    case 126: return ntohs(*(uint16_t*)(data+2));
    default: return header->payloadLength;
  }
}

uint32_t WebSocketMessageMaskingKey(uint8_t *data, uint64_t numBytes)
{
  WebSocketMessageHeader *header = (WebSocketMessageHeader *)data;
  if (!header->mask) return 0;
  switch(header->payloadLength)
  {
    case 127: return *(uint32_t*)(data+10);
    case 126: return *(uint32_t*)(data+4);
    default: return *(uint32_t*)(data+2);
  }
}

uint8_t *WebSocketMessageData(uint8_t *data, uint64_t numBytes)
{
  WebSocketMessageHeader *header = (WebSocketMessageHeader *)data;
  data += 2; // Two bytes of fixed size header
  if (header->mask) data += 4; // If there is a masking key present in the header, that takes up 4 bytes
  switch(header->payloadLength)
  {
    case 127: return data + 8; // 64-bit length
    case 126: return data + 2; // 16-bit length
    default: return data; // 7-bit length that was embedded in fixed size header.
  }
}

void CloseWebSocket(int client_fd)
{
  printf("Closing WebSocket connection %d\n", client_fd);
  // CloseAllSocketsByConnection(client_fd);
  shutdown(client_fd, SHUTDOWN_BIDIRECTIONAL);
  CLOSE_SOCKET(client_fd);
}

const char *WebSocketOpcodeToString(int opcode)
{
  static const char *opcodes[] = { "continuation frame (0x0)", "text frame (0x1)", "binary frame (0x2)", "reserved(0x3)", "reserved(0x4)", "reserved(0x5)",
    "reserved(0x6)", "reserved(0x7)", "connection close (0x8)", "ping (0x9)", "pong (0xA)", "reserved(0xB)", "reserved(0xC)", "reserved(0xD)", "reserved(0xE)", "reserved(0xF)" };
  return opcodes[opcode];
}

void DumpWebSocketMessage(uint8_t *data, uint64_t numBytes)
{
  bool goodMessageSize = WebSocketValidateMessageSize(data, numBytes);
  if (!goodMessageSize)
    return;

  WebSocketMessageHeader *header = (WebSocketMessageHeader *)data;
  uint64_t payloadLength = WebSocketMessagePayloadLength(data, numBytes);
  uint8_t *payload = WebSocketMessageData(data, numBytes);

  printf("Received: FIN: %d, opcode: %s, mask: 0x%08X, payload length: %llu bytes, unmasked payload:", header->fin, WebSocketOpcodeToString(header->opcode),
    WebSocketMessageMaskingKey(data, numBytes), payloadLength);
  for(uint64_t i = 0; i < payloadLength; ++i)
  {
    if (i%16 == 0) printf("\n");
    if (i%8==0) printf(" ");
    printf(" %02X", payload[i]);
    if (i >= 63 && payloadLength > 64)
    {
      printf("\n   ... (%llu more bytes)", payloadLength-i);
      break;
    }
  }
  printf("\n");
}

// thread-safe, re-entrant
void WebSocketMessageUnmaskPayload(uint8_t* payload,
                                   uint64_t payloadLength,
                                   uint32_t maskingKey) {
  uint8_t maskingKey8[4];
  memcpy(maskingKey8, &maskingKey, 4);
  uint32_t *data_u32 = (uint32_t *)payload;
  uint32_t *end_u32 = (uint32_t *)((uintptr_t)(payload + (payloadLength & ~3u)));

  while (data_u32 < end_u32)
    *data_u32++ ^= maskingKey;

  uint8_t *end = payload + payloadLength;
  uint8_t *data = (uint8_t *)data_u32;
  while (data < end) {
    *data ^= maskingKey8[(data-payload) % 4];
    ++data;
  }
}

static MUTEX_T webSocketSendLock;

void SendWebSocketMessage(int client_fd, void *buf, uint64_t numBytes) {
  // Guard send() calls to the client_fd socket so that two threads won't ever race to send to the
  // same socket. (This could be per-socket, currently global for simplicity)
  LOCK_MUTEX(&webSocketSendLock);
  uint8_t headerData[sizeof(WebSocketMessageHeader) + 8/*possible extended length*/] = {};
  WebSocketMessageHeader *header = (WebSocketMessageHeader *)headerData;
  header->opcode = 0x02;
  header->fin = 1;
  int headerBytes = 2;

  if (numBytes < 126) {
    header->payloadLength = numBytes;
  } else if (numBytes <= 65535) {
    header->payloadLength = 126;
    *(uint16_t*)(headerData+headerBytes) = htons((unsigned short)numBytes);
    headerBytes += 2;
  } else {
    header->payloadLength = 127;
    *(uint64_t*)(headerData+headerBytes) = hton64(numBytes);
    headerBytes += 8;
  }

#ifdef POSIX_SOCKET_DEEP_DEBUG
  printf("Sending %llu bytes message (%llu bytes of payload) to WebSocket\n", headerBytes + numBytes, numBytes);

  printf("Header:");
  for (int i = 0; i < headerBytes; ++i)
    printf(" %02X", headerData[i]);

  printf("\nPayload:");
  for (int i = 0; i < numBytes; ++i)
    printf(" %02X", ((unsigned char*)buf)[i]);
  printf("\n");
#endif

  send(client_fd, (const char*)headerData, headerBytes, 0); // header
  send(client_fd, (const char*)buf, (int)numBytes, 0); // payload
  UNLOCK_MUTEX(&webSocketSendLock);
}

#endif

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
void process_websocket_handshake(int client_fd) {
  // Waiting for connection upgrade handshake
  char buf[BUFFER_SIZE];
  int read = recv(client_fd, buf, BUFFER_SIZE, 0);

  if (!read)
  {
    CloseWebSocket(client_fd);
    EXIT_THREAD(0);
  }

  if (read < 0)
  {
    fprintf(stderr, "Client read failed\n");
    CloseWebSocket(client_fd);
    EXIT_THREAD(0);
  }

#ifdef PROXY_DEEP_DEBUG
  printf("Received:");
  for(int i = 0; i < read; ++i)
  {
    printf(" %02X", buf[i]);
  }
  printf("\n");
//  printf("In text:\n%s\n", buf);
#endif
  SendHandshake(client_fd, buf);

#ifdef PROXY_DEEP_DEBUG
  printf("Handshake received, entering message loop:\n");
#endif

}

int mpc_tls_process_websocket_message(int fd, char* buffer, int len, int flag) {
	static std::vector<uint8_t> fragmentData;
	static std::vector<uint8_t> tlsData;
	int min_len = 0;
	bool continueFlag = true;
	if (!tlsData.empty()) {
		int min_len = tlsData.size() < len? tlsData.size(): len;
		memcpy(buffer, tlsData.data(), min_len);
		tlsData.erase(tlsData.begin(), tlsData.begin() + min_len);
		return min_len;
	}

	while (continueFlag) {
		char buf[BUFFER_SIZE];

		int read = recv(fd, buf, BUFFER_SIZE, 0);
		if (!read) return 0;
        if (read < 0)
        {
          fprintf(stderr, "Client read failed\n");
          EXIT_THREAD(0);
        }

		fragmentData.insert(fragmentData.end(), buf, buf + read);

        // Process received fragments until there is not enough data for a full message
        while(!fragmentData.empty())
        {
          bool hasFullHeader = WebSocketHasFullHeader(&fragmentData[0], fragmentData.size());
          if (!hasFullHeader)
          {
#ifdef PROXY_DEEP_DEBUG
            printf("(not enough for a full WebSocket header)\n");
#endif
            break;
          }
          uint64_t neededBytes = WebSocketFullMessageSize(&fragmentData[0], fragmentData.size());
          if (fragmentData.size() < neededBytes)
          {
#ifdef PROXY_DEEP_DEBUG
            printf("(not enough for a full WebSocket message, needed %d bytes)\n", (int)neededBytes);
#endif
            break;
          }

          WebSocketMessageHeader *header = (WebSocketMessageHeader *)&fragmentData[0];
          uint64_t payloadLength = WebSocketMessagePayloadLength(&fragmentData[0], neededBytes);
          uint8_t *payload = WebSocketMessageData(&fragmentData[0], neededBytes);

          // Unmask payload
          if (header->mask)
            WebSocketMessageUnmaskPayload(payload, payloadLength, WebSocketMessageMaskingKey(&fragmentData[0], neededBytes));

#ifdef PROXY_DEEP_DEBUG
            DumpWebSocketMessage(&fragmentData[0], neededBytes);
#endif

          switch(header->opcode)
          {
          // case 0x02: /*binary message*/ ProcessWebSocketMessage(client_fd, payload, payloadLength); break;
          case 0x02: /*binary message*/ {
			  min_len = payloadLength < len? payloadLength : len;
			  printf("payload[%d] ", min_len);
			  for (int i = 0; i < min_len; i++)
				  printf("%02x ", (unsigned char)payload[i]);
			  printf("\n");
			  memcpy(buffer, payload, min_len);
			  continueFlag = false;
			  if (min_len < payloadLength)
				  tlsData.insert(tlsData.end(), payload + min_len, payload + payloadLength);
		  };
		  break;
          case 0x08: continueFlag = false; break;
          default:
            fprintf(stderr, "Unknown WebSocket opcode received %x!\n", header->opcode);
            continueFlag = false; // Kill connection
            break;
          }

          fragmentData.erase(fragmentData.begin(), fragmentData.begin() + (ptrdiff_t)neededBytes);
#ifdef PROXY_DEEP_DEBUG
          printf("Cleared used bytes, got %d left in fragment queue.\n", (int)fragmentData.size());
#endif
        }
	}
	return min_len;
}

int mpc_tls_send(int fd, const char* buf, int len, int flag) {
    printf("mpc tls send============%d\n", len);
	SendWebSocketMessage(fd, (void*)buf, len);
    return len;
}

int mpc_tls_recv(int fd, char* buf, int len, int flag) {
    int ret = mpc_tls_process_websocket_message(fd, buf, len, flag);
    printf("mpc tls recv=============%d\n", len);
	for (int i = 0; i < ret; i++)
		printf("%2x ", (unsigned char)buf[i]);
	printf("\n");
	return ret;
}

void process_msg(int client_fd, SSL* ssl) {
    while (1) {
        char buf[10240];
        // int len = recv(cfd, buf, sizeof(buf), 0);
        int len = SSL_read(ssl, buf, sizeof(buf));
        if (len < 0) {
            printf("recv error %s\n", strerror(errno));
            exit(1);
        }
        if (len == 0) exit(0);

        printf("server => recv %d %s\n", len, buf);
        // len = send(cfd, buf, len, 0);
        len = SSL_write(ssl, buf, len);
        if (len < 0) {
            printf("send error %s\n", strerror(errno));
        }
        printf("server => send %d %s\n", len, buf);
    }
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
    server.sin_port = htons(9000);

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
    printf("accept success\n");

    process_websocket_handshake(cfd);


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
    printf("end ssl accept\n");
    if (ret < 0) {
        printf("ssl accept %d %s\n", ret, strerror(ret));
        ERR_print_errors_fp(stderr);
        exit(1);
    }
    printf("SSL accept success\n");

    process_msg(cfd, cssl);

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
    OPENSSL_init_MPC_SOCKET(mpc_tls_send, mpc_tls_recv);
    run();
    return 0;
}

#include<stdio.h>
#include<stdlib.h>
#include<assert.h>
#include<string.h>
#include<arpa/inet.h>
#include<unistd.h>
#include<errno.h>

#include<vector>
#include<map>
#include<string>
#include "sha1.h"
using namespace std;

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
#endif
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

string GenWebSocketMessage(const void *buf2, uint64_t numBytes, uint64_t id, bool enable_id) {
  printf("send info id:%llu size:%llu\n", id, numBytes);
  unsigned char* buf = NULL;
  if (enable_id) {
    buf = new unsigned char[numBytes + sizeof(uint64_t)];
    memcpy(buf, &id, sizeof(uint64_t));
    memcpy(buf + sizeof(uint64_t), buf2, numBytes);
    numBytes += sizeof(uint64_t);
  }
  else
    buf = (unsigned char*)buf2;

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

  string result(headerBytes + numBytes, 0);
  memcpy(&result[0], headerData, headerBytes);
  memcpy((char*)&result[0] + headerBytes, buf, numBytes);

  if (buf != buf2)
    delete []buf;
  return result;
}

string GetMessage(int fd, int len, uint64_t id, bool enable_id) {
    static std::vector<uint8_t> fragmentData;
    static std::map<uint64_t, std::vector<uint8_t>> tlsData;
    bool continueFlag = true;
    string result;
    auto iter = tlsData.find(id);
    if (iter != tlsData.end()) {
        // int min_len = tlsData.size() < len? tlsData.size(): len;
        // result.insert(result.end(), tlsData.begin(), tlsData.begin() + min_len);
        // tlsData.erase(tlsData.begin(), tlsData.begin() + min_len);
        result.resize(iter->second.size());
        // if (len != iter->second.size()) 
            printf("recv error get message1 id:%llu need:%d actual:%d\n", id, len, iter->second.size());
        memcpy(&result[0], iter->second.data(), iter->second.size());
        tlsData.erase(iter);
        return result;
    }

    while (continueFlag) {
        char buf[BUFFER_SIZE];
        printf("begin recv ws id:%llu %d\n", id, len);

        int read = recv(fd, buf, BUFFER_SIZE, 0);
        printf("recv result:%d %d %s\n", read, errno, strerror(errno));
        if (!read) return "";
        if (read < 0)
        {
          fprintf(stderr, "Client read failed1 %d %s\n", errno, strerror(errno));
          // EXIT_THREAD(0);
          assert(false);
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
              printf("payload[%d] ", payloadLength);
              for (int i = 0; i < payloadLength; i++)
                  printf("%02x ", (unsigned char)payload[i]);
              printf("\n");
              // int min_len = payloadLength < len? payloadLength: len;
              // result.resize(min_len);
              // memcpy(&result[0], payload, min_len);
              // tlsData.insert(tlsData.end(), payload + min_len, payload + payloadLength);
              if (enable_id) {
                  uint64_t *p = (uint64_t*)payload;
                  uint8_t *d = (uint8_t*)(p + 1);
                  if (*p == id) {
                      result.resize(payloadLength - sizeof(uint64_t));
                      // if (len != payloadLength - sizeof(uint64_t))
                          printf("recv error get message2 id:%llu need:%d actual:%d\n", id, len, payloadLength - sizeof(uint64_t));
                      memcpy(&result[0], d, payloadLength - sizeof(uint64_t));
                      continueFlag = false;
                  }
                  else {
                      std::vector<uint8_t> tmp(payloadLength - sizeof(uint64_t), 0);
                      memcpy(&tmp[0], d, payloadLength - sizeof(uint64_t));
                      tlsData.insert(std::pair<uint64_t, std::vector<uint8_t>>(*p, tmp));
                  }
              }
              else {
                  result.resize(payloadLength);
                  memcpy(&result[0], payload, payloadLength);
                  continueFlag = false;
              }
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
    return result;
}
void RequestWebSocketHandshake(int fd) {
    char handshakeMsg[] = "GET / HTTP/1.1\r\n"
      "Host: localhost:9000\r\n"
      "User-Agent: Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:109.0) Gecko/20100101 Firefox/110.0\r\n"
      "Accept: */*\r\n"
      "Accept-Language: en-US,en;q=0.5\r\n"
      "Accept-Encoding: gzip, deflate, br\r\n"
      "Sec-WebSocket-Version: 13\r\n"
      "Origin: http://localhost:8001\r\n"
      "Sec-WebSocket-Extensions: permessage-deflate\r\n"
      "Sec-WebSocket-Key: I28w97h3i3dkMdxGpUF+sA==\r\n"
      "Connection: keep-alive, Upgrade\r\n"
      "Sec-Fetch-Dest: websocket\r\n"
      "Sec-Fetch-Mode: websocket\r\n"
      "Sec-Fetch-Site: same-site\r\n"
      "Pragma: no-cache\r\n"
      "Cache-Control: no-cache\r\n"
      "Upgrade: websocket\r\n";
    int ret = send(fd, handshakeMsg, strlen(handshakeMsg), 0);
    if (ret < 0) 
        EXIT_THREAD(0);
}

void ResponseWebSocketHandshake(int fd) {
  // Waiting for connection upgrade handshake
  char buf[BUFFER_SIZE];
  int read = recv(fd, buf, BUFFER_SIZE, 0);

  if (!read)
  {
    // CloseWebSocket(client_fd);
    EXIT_THREAD(0);
  }

  if (read < 0)
  {
    fprintf(stderr, "Client read failed2 %d %s\n", errno, strerror(errno));
    // CloseWebSocket(client_fd);
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
  SendHandshake(fd, buf);

#ifdef PROXY_DEEP_DEBUG
  printf("Handshake received, entering message loop:\n");
#endif

}

void CheckWebSocketHandshake(int fd) {
    char buf[BUFFER_SIZE];
    memset(buf, 0, sizeof(buf));
    int read = recv(fd, buf, BUFFER_SIZE, 0);
    if (read < 0) {
        printf("check websocket handshake:%d %s\n", errno, strerror(errno));
        EXIT_THREAD(0);
    }

    printf("check websocket handshake:%d %s\n", fd, buf);
}


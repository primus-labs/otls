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
#include "ws.h"
using namespace std;
#include "mpc_tls.h"

#define WEBSOCKET
//#define PROXY_DEEP_DEBUG

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
  printf("Sent handshake[%d]:\n%s\n", strlen(handshakeMsg), handshakeMsg);
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

static std::vector<uint8_t> send_buffer;
static uint64_t send_id = 0;
static string DoGenWebSocketMessage(const void* buf, uint64_t numBytes) {
  //printf("send info id:%llu size:%llu\n", id, numBytes);

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

  return result;
}
#define NETWORK_BUFFER_SIZE 1024*1024
string GenWebSocketMessage(const void *buf, uint64_t numBytes, uint64_t id, bool enable_id) {
  string result;
  if (send_buffer.empty()) {
    send_buffer.reserve(NETWORK_BUFFER_SIZE);
    send_buffer.resize(sizeof(uint64_t));
  }
  if (numBytes > 0 && send_buffer.size() + numBytes + 2 * sizeof(uint64_t) < send_buffer.capacity()) {
#if DEBUG_MSG_INFO
    send_buffer.insert(send_buffer.end(), (uint8_t*)&id, (uint8_t*)(&id + 1));
    send_buffer.insert(send_buffer.end(), (uint8_t*)&numBytes, (uint8_t*)(&numBytes + 1));
#endif
    send_buffer.insert(send_buffer.end(), (uint8_t*)buf, (uint8_t*)buf + numBytes);
    return result;
  }

  if (send_buffer.size() > sizeof(uint64_t)) {
    send_id++;
    *(uint64_t*)&send_buffer[0] = send_id;
    result = DoGenWebSocketMessage((void *)send_buffer.data(), send_buffer.size());
    // printf("send buffer info id:%llu len:%llu %llu\n", send_id, (uint64_t)send_buffer.size(), numBytes);
    if (send_id == 1 && send_buffer.size() == 25) assert(false);

    send_buffer.reserve(NETWORK_BUFFER_SIZE);
    send_buffer.resize(sizeof(uint64_t));
  }
  if (numBytes > 0) {
#if DEBUG_MSG_INFO
  //printf("debug msg info: send id: %llu length:%llu\n", id, numBytes);
    send_buffer.insert(send_buffer.end(), (uint8_t*)&id, (uint8_t*)(&id + 1));
    send_buffer.insert(send_buffer.end(), (uint8_t*)&numBytes, (uint8_t*)(&numBytes + 1));
#endif
    send_buffer.insert(send_buffer.end(), (uint8_t*)buf, (uint8_t*)buf + numBytes);
  }
  return result;
}
static std::map<uint64_t, vector<uint8_t>> recv_map;
static std::vector<uint8_t> recv_buffer;
static uint64_t recv_id = 0;
static std::vector<uint8_t> fragmentData;
static char *buf = new char[NETWORK_BUFFER_SIZE];
string GetMessage(int fd, int len, uint64_t id, bool enable_id) {
    bool continueFlag = true;
    string result;
    while (continueFlag) {
    // printf("need:%d recv buffer size:%lu\n", len, recv_buffer.size());
#if DEBUG_MSG_INFO
        if (recv_buffer.size() >= len + 2 * sizeof(uint64_t)) {
            uint64_t *actual_id = (uint64_t*)recv_buffer.data();
            uint64_t *actual_len = actual_id + 1;
            if (*actual_id != id || *actual_len != len) {
              printf("id actual:%llu expect: %llu length actual:%llu expect:%llu\n", *actual_id, id, *actual_len, (uint64_t)len);
              assert(false);
              exit(1);
            }

            result.resize(len);
            // printf("recv error get message1 id:%llu need:%d\n", id, len);
            memcpy(&result[0], recv_buffer.data() + 2 * sizeof(uint64_t), len);
            recv_buffer.erase(recv_buffer.begin(), recv_buffer.begin() + 2 * sizeof(uint64_t) + len);
            return result;
        }
#else
        if (recv_buffer.size() >= len) {
            result.resize(len);
            // printf("recv error get message1 id:%llu need:%d\n", id, len);
            memcpy(&result[0], recv_buffer.data(), len);
            recv_buffer.erase(recv_buffer.begin(), recv_buffer.begin() + len);
            return result;
        }
#endif

        // printf("begin recv ws id:%llu %d\n", id, len);

        int read = recv(fd, buf, NETWORK_BUFFER_SIZE, 0);
        //printf("recv data size: %llu\n", (uint64_t)read);
        // printf("recv result:%d %d %s\n", read, errno, strerror(errno));
        if (!read) return result;
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
              if (1) {
                  uint64_t *payload_id = (uint64_t*)payload;
                  uint8_t *data = (uint8_t*)(payload_id + 1);
                  uint64_t data_len = payloadLength - sizeof(uint64_t);
                  // printf("%s %d recv id: %llu current id: %llu\n", __FILE__, __LINE__, recv_id, *payload_id);
                  if (recv_id + 1 == *payload_id) {
                    recv_buffer.insert(recv_buffer.end(), data, data + data_len);
                    recv_id++;
            
                    auto iter = recv_map.find(recv_id + 1);
                    while (iter != recv_map.end()) {
                      recv_buffer.insert(recv_buffer.end(), iter->second.begin(), iter->second.end());
                      recv_map.erase(iter);
                      recv_id++;
              
                      iter = recv_map.find(recv_id + 1);
                    }
                    // printf("put to recv buffer, size:%llu\n", (uint64_t)recv_buffer.size());
                  }
                  else {
                      std::vector<uint8_t> tmp(data, data + data_len);
                      recv_map.insert(std::pair<uint64_t, std::vector<uint8_t>>(*payload_id, tmp));
                  }
              }
          };
          break;
          case 0x08: break;
          default:
            fprintf(stderr, "Unknown WebSocket opcode received %x!\n", header->opcode);
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

    printf("check websocket handshake[%d]:%d %s\n", strlen(buf), fd, buf);
}

string GenWebSocketMessageProxy(const void *buf, uint64_t numBytes, uint64_t id, bool enable_id) {
    return DoGenWebSocketMessage(buf, numBytes);
}

string GetMessageProxy(int fd, int len, uint64_t id, bool enable_id) {
static std::map<uint64_t, vector<uint8_t>> recv_map;
static std::vector<uint8_t> recv_buffer;
static uint64_t recv_id = 0;
static std::vector<uint8_t> fragmentData;
    bool continueFlag = true;
    string result;
    while (continueFlag) {
    // printf("need:%d recv buffer size:%lu\n", len, recv_buffer.size());
        auto iter = recv_map.find(id);
        if (iter != recv_map.end()) {
          result.resize(iter->second.size());
          memcpy(&result[0], iter->second.data(), iter->second.size());
          recv_map.erase(iter);
          return result;
        }

        char buf[BUFFER_SIZE];
        // printf("begin recv ws id:%llu %d\n", id, len);

        int read = recv(fd, buf, BUFFER_SIZE, 0);
        // printf("recv result:%d %d %s\n", read, errno, strerror(errno));
        if (!read) return result;
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
              print_mpc("payload", (const unsigned char*)payload, payloadLength);
              if (1) {
                  uint64_t *payload_id = (uint64_t*)&id;
                  uint8_t *data = (uint8_t*)(payload);
                  uint64_t data_len = payloadLength;
                  // printf("%s %d recv id: %llu current id: %llu\n", __FILE__, __LINE__, recv_id, *payload_id);
                  std::vector<uint8_t> tmp(data, data + data_len);
                  recv_map.insert(std::pair<uint64_t, std::vector<uint8_t>>(*payload_id, tmp));
              }
          };
          break;
          case 0x08: break;
          default:
            fprintf(stderr, "Unknown WebSocket opcode received %x!\n", header->opcode);
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

void dprint(const char* msg, const char* buf, int len) {
    printf("%s[%d] ", msg, len);
    for (int i = 0; i < len; i++)
        printf("%02x ", (unsigned char)buf[i]);
    printf("\n");
}

SendCtx* NewSendCtx(bool websocket) {
    SendCtx* ctx = new SendCtx();
    SendBuffer *buffer = new SendBuffer();
    
    ctx->buffer = buffer;
    ctx->websocket = websocket;
    return ctx;
}

void FreeSendCtx(SendCtx* ctx) {
    delete ctx->buffer;
    delete ctx;
}
    
size_t GenWebSocketHeader(uint8_t* headerData, size_t numBytes) {
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
    return headerBytes;
}

ssize_t DoSendMessage(SendCtx* ctx, const char* buf, size_t len, FILE* stream) {
    if (ctx->websocket) {
        uint8_t headerData[sizeof(WebSocketMessageHeader) + 8/*possible extended length*/] = {};
        memset(headerData, 0, sizeof(headerData));
        size_t headerBytes = GenWebSocketHeader(headerData, len);
        int ret = fwrite(headerData, 1, headerBytes, stream);
        if (ret != headerBytes) {
            printf("ret:%d errno:%d %s\n", ret, errno, strerror(errno));
            fflush(stdout);
            assert(false);
            return -1;
        }
    }
    if (fwrite(buf, 1, len, stream) != len) {
        assert(false);
        return -1;
    }
    // printf("do send message:%d\n", len);
    // fflush(stdout);
    return len;
}


ssize_t SendMessage(SendCtx* ctx, const char* buf, size_t len, uint64_t id, FILE* stream) {
    SendBuffer* &send_buffer = ctx->buffer;

    if (len > 0 && send_buffer->can_put(len)) {
        send_buffer->put(buf, len);
        return len;
    }

    if (!send_buffer->empty()) {
        send_buffer->pack();
        if (DoSendMessage(ctx, send_buffer->data(), send_buffer->size(), stream) < 0) {
            return -1;
        }

        send_buffer->reset();
    }

    if (len > 0 && send_buffer->can_put(len)) {
        send_buffer->put(buf, len);
        return len;
    }
    else if (len > 0) {
        assert(false);
    }
    return len == 0? 1: len;

}

RecvCtx* NewRecvCtx(bool websocket) {
    RecvCtx *ctx = new RecvCtx();
    ctx->info = NULL;
    ctx->list = NULL;
    ctx->websocket = websocket;
    return ctx;
}

void FreeRecvCtx(RecvCtx* ctx) {
    delete ctx->info;
    delete ctx->list;
    delete ctx;
}

void UnMaskData(char* buf, uint64_t len, uint32_t mask) {
    uint32_t *begin32 = (uint32_t*)buf;
    uint32_t *end32 = begin32 + len / sizeof(uint32_t);
    while (begin32 != end32) {
        *begin32++ ^= mask;
    }

    uint8_t *begin8 = (uint8_t*)end32;
    uint8_t *end8 = (uint8_t*)(buf + len);
    uint8_t *mask8 = (uint8_t*)&mask;
    while (begin8 != end8) {
        *begin8++ ^= *mask8++;
    }
}

void PutToRecvCtx(RecvCtx* ctx, RecvList* recv_chunk) {
    RecvList* &recv_list = ctx->list;
    RecvInfo* &recv_info = ctx->info;

    RecvBuffer* recv_buffer = (RecvBuffer*)recv_chunk->data;
    // printf("recv id:%llu length:%llu\n", recv_buffer->id, recv_buffer->length);
    // fflush(stdout);
    if (recv_list == NULL) {
        recv_list = recv_chunk;
    }
    else {
        RecvList *p_list = NULL;
        RecvList *q_list = recv_list;
        while (q_list != NULL) {
            RecvBuffer* b = (RecvBuffer*)q_list->data;

            if (recv_buffer->id < b->id) {
                recv_chunk->next = q_list;

                if (p_list == NULL) {
                    recv_list = recv_chunk;
                }
                else {
                    p_list->next = recv_chunk;
                }
                break;
            }

            p_list = q_list;
            q_list = q_list -> next;
        }

        if (q_list == NULL) {
            p_list->next = recv_chunk;
        }
    }

    if (recv_info == NULL) {
        recv_info = (RecvInfo*)malloc(sizeof(RecvInfo));
        recv_info->valid = false;
        recv_info->prev_id = 0;
    }
    if (!recv_info->valid) {
        RecvBuffer* b = (RecvBuffer*)recv_list->data;
        if (recv_info->prev_id + 1 == b->id) {
            recv_info->id = b->id;
            recv_info->length = b->length;
            recv_info->payload = b->payload;
            recv_info->offset = 0;
            recv_info->valid = true;
        }
    }
}

size_t RecvFromRecvCtx(RecvCtx* ctx, char* buf, size_t len) {
    RecvInfo* &recv_info = ctx->info;
    RecvList* &recv_list = ctx->list;

    size_t recv_bytes = 0;
    if (recv_info->offset < recv_info->length) {
        uint64_t min_len = min(recv_info->length - recv_info->offset, len - recv_bytes);
        memcpy(buf + recv_bytes, recv_info->payload + recv_info->offset, min_len);
        recv_info->offset += min_len;

        recv_bytes += min_len;
        // printf("recv %llu expect %llu\n", min_len, len);
        // fflush(stdout);

        if (recv_info->offset == recv_info->length) {
            RecvList *tmp = recv_list;
            recv_list = recv_list->next;

            RecvBuffer* p = (RecvBuffer*)tmp->data;
            if (recv_list != NULL) {
                RecvBuffer* q = (RecvBuffer*)recv_list->data;
                if (p->id + 1 == q->id) {
                    recv_info->id = q->id;
                    recv_info->length = q->length;
                    recv_info->payload = q->payload;
                    recv_info->offset = 0;
                }
                else {
                    recv_info->prev_id = p->id;
                    recv_info->valid = false;
                }
            }
            else {
                recv_info->prev_id = p->id;
                recv_info->valid = false;
            }

            free(tmp);
        }
    }
    return recv_bytes;
}
ssize_t RecvMessage(RecvCtx* ctx, char* buf, size_t len, uint64_t id, FILE* stream) {
    RecvList* &recv_list = ctx->list;
    RecvInfo* &recv_info = ctx->info;
    uint64_t recv_bytes = 0;
    while(1) {
        if (recv_info != NULL && recv_info->valid) {
            size_t ret = RecvFromRecvCtx(ctx, buf + recv_bytes, len - recv_bytes);

            recv_bytes += ret;
            if (recv_bytes == len)
                return len;
        }
    
        char headerData[sizeof(WebSocketMessageHeader) + 8 + 4];
        int ret = fread(headerData, 1, 2, stream);
        if (ret != 2) {
            printf("ret:%d expect:2\n", ret);
            fflush(stdout);
            assert(false);
            return -1;
        }
        // dprint("header2", headerData, 2);
        WebSocketMessageHeader* header = (WebSocketMessageHeader*)headerData;
        bool mask = header->mask? true: false;
        uint8_t payload_length = header->payloadLength;
        uint64_t mask_length = mask? 4: 0;
    
        uint64_t length_size;
        switch (payload_length) {
            case 126:
                length_size = 2;
                break;
            case 127:
                length_size = 8;
                break;
            default:
                length_size = 0;
        }
    
        uint32_t mask_data = 0;
        int mask_offset = 2;
        uint64_t data_len = payload_length;
        if (length_size + mask_length > 0) {
            if (fread(headerData + 2, 1, length_size + mask_length, stream) != length_size + mask_length) {
                assert(false);
                return -1;
            }
            switch (payload_length) {
                case 126:
                    data_len = ntohs(*(uint16_t*)(headerData + 2));
                    mask_offset += 2; 
                    break;
                case 127:
                    data_len = ntoh64(*(uint64_t*)(headerData + 2));
                    mask_offset += 8;
                    break;
            }
    
            if (mask) {
                mask_data = *(uint32_t*)(headerData + mask_offset);
            }
            // dprint("headerextra", headerData + 2, length_size + mask_length);
        }
    
    
        RecvList* recv_chunk = (RecvList*)malloc(sizeof(RecvList) + data_len); 
        // printf("data len:%llu\n", data_len);
        ret = fread(recv_chunk->data, 1, data_len, stream);
        if (mask) {
            UnMaskData(recv_chunk->data, data_len, mask_data);
        }
        // dprint("fread data", recv_chunk->data, data_len);
        if (ret != data_len) {
        printf("ret: %d expect: %llu\n", ret, data_len);
        fflush(stdout);
            assert(false);
            return -1;
        }
        recv_chunk->next = NULL;

        PutToRecvCtx(ctx, recv_chunk);
    
    }
    return 0;

}


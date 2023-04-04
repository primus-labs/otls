#include<string>
#include<stdio.h>
using namespace std;

#define DEBUG_MSG_INFO 0
void RequestWebSocketHandshake(int fd);

void ResponseWebSocketHandshake(int fd);

void CheckWebSocketHandshake(int fd);

string GenWebSocketMessage(const void *buf, uint64_t numBytes, uint64_t id, bool enable_id);

string GetMessage(int fd, int len, uint64_t id, bool enable_id);

string GenWebSocketMessageProxy(const void *buf, uint64_t numBytes, uint64_t id, bool enable_id);

string GetMessageProxy(int fd, int len, uint64_t id, bool enable_id);

#ifndef NETWORK_BUFFER_SIZE
#define NETWORK_BUFFER_SIZE 1024 * 1024
#endif

struct SendBuffer {
private:
    char buffer[NETWORK_BUFFER_SIZE];
    uint64_t offset;
    uint64_t send_id;
public:
    SendBuffer() {
        offset = 0;
        send_id = 0;
        memset(buffer, 0, sizeof(buffer));
        offset += 2 * sizeof(uint64_t);    
    }

    void pack() {
        set_send_id();
        set_length();
    }

    void set_send_id() {
        send_id++;
        *(uint64_t*)buffer = send_id;
    }

    void set_length() {
        uint64_t payloadLength = offset - 2 * sizeof(uint64_t);
        *((uint64_t*)buffer + 1) = payloadLength;
        // printf("send id:%llu length:%llu\n", send_id, payloadLength);
        // fflush(stdout);
    }

    bool can_put(uint64_t numBytes) {
        return offset + numBytes < NETWORK_BUFFER_SIZE;
    }

    void put(const char *buf, uint64_t len) {
        memcpy(buffer + offset, buf, len);
        offset += len;
    }

    bool empty() {
        return offset <= 2 * sizeof(uint64_t);
    }

    size_t size() {
        return offset;
    }
    const char* data() {
        return buffer;
    }

    void reset() {
        offset = 2 * sizeof(uint64_t);
    }

};
struct SendCtx {
    SendBuffer* buffer;
    bool websocket;
};

SendCtx* NewSendCtx(bool websocket);

void FreeSendCtx(SendCtx* ctx);
    
ssize_t SendMessage(SendCtx *ctx, const char* buf, size_t len, uint64_t id, FILE* stream);

struct RecvList {
    RecvList *next;
    char data[];
};
struct RecvBuffer {
    uint64_t id;
    uint64_t length;
    char payload[];
};
struct RecvInfo {
    uint64_t id;
    char *payload;
    uint64_t offset;
    uint64_t length;
    uint64_t prev_id;
    bool valid;
};

struct RecvCtx {
    RecvList* list;
    RecvInfo* info;
    bool websocket;
};

RecvCtx* NewRecvCtx(bool websocket);

void FreeRecvCtx(RecvCtx* ctx);

ssize_t RecvMessage(RecvCtx *ctx, char* buf, size_t len, uint64_t id, FILE* stream);


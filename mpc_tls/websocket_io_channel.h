#ifndef EMP_WEBSOCKET_IO_CHANNEL
#define EMP_WEBSOCKET_IO_CHANNEL

#include <iostream>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <string>
#include "emp-tool/io/io_channel.h"
using std::string;

#include <vector>
#include <map>
#include <mutex>
#include <condition_variable>
using namespace std;

#include <unistd.h>
#include <arpa/inet.h>
#include <sys/types.h>
#include <netinet/tcp.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include "ws.h"

#ifdef __EMSCRIPTEN__
#include <emscripten.h>
#include <emscripten/websocket.h>
#include <emscripten/threading.h>
#include <emscripten/posix_socket.h>

#endif

#ifdef __EMSCRIPTEN__
// Uncomment to enable debug printing
// #define POSIX_SOCKET_DEBUG

// Uncomment to enable more verbose debug printing (in addition to uncommenting POSIX_SOCKET_DEBUG)
// #define POSIX_SOCKET_DEEP_DEBUG

#define MIN(a,b) (((a)<(b))?(a):(b))

static std::map<uint64_t, vector<uint8_t>> recv_map;
static std::vector<uint8_t> recv_buffer;
static uint64_t recv_id = 0;
static mutex recvLock;
static condition_variable recvCond;

static EM_BOOL
bridge_socket_on_message2(int eventType,
                         const EmscriptenWebSocketMessageEvent* websocketEvent,
                         void* userData) {
  //printf("recv from network:%llu\n", websocketEvent->numBytes);
  RecvList* recv_chunk = (RecvList*)malloc(sizeof(RecvList) + websocketEvent->numBytes);
  recv_chunk->next = NULL;

  memcpy(recv_chunk->data, websocketEvent->data, websocketEvent->numBytes);
  RecvCtx* ctx = (RecvCtx*)userData;

  std::unique_lock<mutex> lck(recvLock);
  PutToRecvCtx(ctx, recv_chunk);

  recvCond.notify_one();

  return EM_TRUE;
}

EMSCRIPTEN_WEBSOCKET_T emscripten_init_websocket_to_posix_socket_bridge2(RecvCtx* ctx, const char *bridgeUrl) {
  EmscriptenWebSocketCreateAttributes attr;
  emscripten_websocket_init_create_attributes(&attr);
  attr.url = bridgeUrl;
  printf("bridgeUrl:%s\n", bridgeUrl);
  int webSocket = emscripten_websocket_new(&attr);
  emscripten_websocket_set_onmessage_callback_on_thread(webSocket, ctx, bridge_socket_on_message2, EM_CALLBACK_THREAD_CONTEXT_MAIN_BROWSER_THREAD);
  return webSocket;
}

inline void bprint(const char* msg, const void* buf, int len) {
    printf("%s[%d] ", msg, len);
    for (int i = 0; i < len; i++)
        printf("%02x ", ((unsigned char*)buf)[i]);
    printf("\n");
}

ssize_t SendEmscriptenMessage(SendCtx* ctx, const char* buf, size_t len, uint64_t id, int sock) {
    SendBuffer* &send_buffer = ctx->buffer;

    if (len > 0 && send_buffer->can_put(len)) {
        send_buffer->put(buf, len);
        return len;
    }

    if (!send_buffer->empty()) {
        send_buffer->pack();
        emscripten_websocket_send_binary(sock, (void*)send_buffer->data(), send_buffer->size());

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

ssize_t RecvEmscriptenMessage(RecvCtx* ctx, char* buf, size_t len, uint64_t id, int sock) {
  size_t recv_bytes = 0;
  while (recv_bytes < len) {
    std::unique_lock<mutex> lck(recvLock);

    while (ctx->info == NULL || !ctx->info->valid) {
        recvCond.wait(lck);
    }

    size_t ret = RecvFromRecvCtx(ctx, buf + recv_bytes, len - recv_bytes);
    recv_bytes += ret;
  }

  return recv_bytes;
}
#endif

#define RECORD_MSG_INFO 0
namespace emp {

class WebSocketIO: public IOChannel<WebSocketIO> { public:
    bool is_server;
    int mysocket = -1;
    int consocket = -1;
    FILE * stream = nullptr;
    char * buffer = nullptr;
    bool has_sent = false;
    string addr;
    int port;
    uint64_t send_id = 0;
    uint64_t recv_id = 0;
    SendCtx* send_ctx = nullptr;
    RecvCtx* recv_ctx = nullptr;
    int wssock;
#if RECORD_MSG_INFO
    FILE* debug_file = nullptr;
#endif
    WebSocketIO(const char * address, int port, bool quiet = false) {
        if (port <0 || port > 65535) {
            throw std::runtime_error("Invalid port number!");
        }

        this->port = port;
        is_server = (address == nullptr);
#ifndef __EMSCRIPTEN__
        send_ctx = NewSendCtx(true);
        recv_ctx = NewRecvCtx(true);
#else
        send_ctx = NewSendCtx(false);
        recv_ctx = NewRecvCtx(false);
#endif
        if (address == nullptr) {
#ifndef __EMSCRIPTEN__
            printf("begin listen to %d\n", port);
            struct sockaddr_in dest;
            struct sockaddr_in serv;
            socklen_t socksize = sizeof(struct sockaddr_in);
            memset(&serv, 0, sizeof(serv));
            serv.sin_family = AF_INET;
            serv.sin_addr.s_addr = htonl(INADDR_ANY); /* set our address to any interface */
            serv.sin_port = htons(port);           /* set the server port number */
            mysocket = socket(AF_INET, SOCK_STREAM, 0);
            int reuse = 1;
            setsockopt(mysocket, SOL_SOCKET, SO_REUSEADDR, (const char*)&reuse, sizeof(reuse));
            if(bind(mysocket, (struct sockaddr *)&serv, sizeof(struct sockaddr)) < 0) {
                perror("error: bind");
                exit(1);
            }
            if(listen(mysocket, 1) < 0) {
                perror("error: listen");
                exit(1);
            }
            consocket = accept(mysocket, (struct sockaddr *)&dest, &socksize);
            close(mysocket);
            ResponseWebSocketHandshake(consocket);
#if RECORD_MSG_INFO
            debug_file = fopen("websocket_server.log", "w");
#endif        
#endif
        }
        else {
#ifndef __EMSCRIPTEN__
            struct sockaddr_in dest;
            memset(&dest, 0, sizeof(dest));
            dest.sin_family = AF_INET;
            dest.sin_addr.s_addr = inet_addr(address);
            dest.sin_port = htons(port);

            while(1) {
                consocket = socket(AF_INET, SOCK_STREAM, 0);

                if (connect(consocket, (struct sockaddr *)&dest, sizeof(struct sockaddr)) == 0) {
                    break;
                }

                close(consocket);
                usleep(1000);
            }
            RequestWebSocketHandshake(consocket);
            CheckWebSocketHandshake(consocket);
#if RECORD_MSG_INFO
            debug_file = fopen("websocket_client.log", "w");
#endif
#else
            char wsaddr[256];
            snprintf(wsaddr, sizeof(wsaddr), "ws://%s:%d", address, port);
            wssock = emscripten_init_websocket_to_posix_socket_bridge2(recv_ctx, wsaddr);
            // Synchronously wait until connection has been established.
            uint16_t readyState = 0;
            do {
              emscripten_websocket_get_ready_state(wssock, &readyState);
              emscripten_thread_sleep(100);
            } while (readyState == 0);
#endif
        }
#ifndef __EMSCRIPTEN__
        set_nodelay();
        stream = fdopen(consocket, "wb+");
        buffer = new char[NETWORK_BUFFER_SIZE];
        memset(buffer, 0, NETWORK_BUFFER_SIZE);
        setvbuf(stream, buffer, _IOFBF, NETWORK_BUFFER_SIZE);
#endif
        if(!quiet)
            std::cout << "websocketio connected\n";
    }

    void sync() {
        int tmp = 0;
        if(is_server) {
            send_data_internal(&tmp, 1);
            recv_data_internal(&tmp, 1);
        } else {
            recv_data_internal(&tmp, 1);
            send_data_internal(&tmp, 1);
            flush(true);
        }
    }

    ~WebSocketIO(){
        flush(true);
#ifndef __EMSCRIPTEN__
        fclose(stream);
        delete[] buffer;
#endif
    }

    void set_nodelay() {
        const int one=1;
        setsockopt(consocket,IPPROTO_TCP,TCP_NODELAY,&one,sizeof(one));
    }

    void set_delay() {
        const int zero = 0;
        setsockopt(consocket,IPPROTO_TCP,TCP_NODELAY,&zero,sizeof(zero));
    }

    void flush(bool flag = false) {
        if (!flag) return;
#ifndef __EMSCRIPTEN__
        send_data_internal(NULL, 0);
        fflush(stream);
#else
        send_data_internal(NULL, 0);
#endif
    }

    //void flush() {}

    void send_data_internal(const void * data, size_t len) {
        size_t sent = 0;
        if (len > 0) {
            send_id++;
        }
#ifndef __EMSCRIPTEN__
#if RECORD_MSG_INFO
        if (len > 0) {
            fprintf(debug_file, "send data id:%llu len:%llu\n", (uint64_t)send_id, (uint64_t)len);
            fflush(debug_file);
        }
#endif
#endif

#ifndef __EMSCRIPTEN__
        size_t res = SendMessage(send_ctx, sent + (char*)data, len - sent, send_id, stream);
#else
        size_t res = SendEmscriptenMessage(send_ctx, sent + (char*)data, len - sent, send_id, wssock);
#endif
        has_sent = true;
    }

    void recv_data_internal(void  * data, size_t len) {
        if(has_sent)
            flush(true);
        has_sent = false;
        size_t sent = 0;
        recv_id++;
#ifndef __EMSCRIPTEN__
#if RECORD_MSG_INFO
        fprintf(debug_file, "recv data id: %llu len:%llu\n", (uint64_t)recv_id, (uint64_t)len);
        fflush(debug_file);
#endif
        size_t res = RecvMessage(recv_ctx, sent + (char*)data, len - sent, recv_id, stream);
#else
        size_t res = RecvEmscriptenMessage(recv_ctx, sent + (char*)data, len - sent, recv_id, wssock);
#endif
    }
};

}

#endif  //WEBSOCKET_IO_CHANNEL

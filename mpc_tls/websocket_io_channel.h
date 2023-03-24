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

static pthread_mutex_t bridgeLock = PTHREAD_MUTEX_INITIALIZER;
static EMSCRIPTEN_WEBSOCKET_T bridgeSocket = 0;
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
static pthread_mutex_t recvLock = PTHREAD_MUTEX_INITIALIZER;
static int recvBufferFlag = 0;
static EM_BOOL
bridge_socket_on_message2(int eventType,
                         const EmscriptenWebSocketMessageEvent* websocketEvent,
                         void* userData) {
  pthread_mutex_lock(&recvLock);
  uint64_t *id = (uint64_t*)websocketEvent->data;
  uint64_t data_len = websocketEvent->numBytes - sizeof(uint64_t);
  uint8_t *data = (uint8_t*)(id + 1);
  // printf("%s %d recv id: %llu current id: %llu\n", __FILE__, __LINE__, recv_id, *id);
  if (recv_id + 1 == *id) {
    // printf("recv buffer init: %llu\n", (uint64_t)recv_buffer.size());
    recv_buffer.insert(recv_buffer.end(), data, data + data_len);
    recv_id++;
    auto iter = recv_map.find(recv_id + 1);
    while (iter != recv_map.end()) {
      recv_buffer.insert(recv_buffer.end(), iter->second.begin(), iter->second.end());
      // printf("add buffer: %llu\n", iter->second.size());
      recv_map.erase(iter);

      recv_id++;
      iter = recv_map.find(recv_id + 1);
    }
    recvBufferFlag = 1;
    // printf("put to recv buffer: %llu data len: %llu\n", (uint64_t)recv_buffer.size(), data_len);
  }
  else {
    vector<uint8_t> tmp(data, data + data_len);
    recv_map.insert(std::pair<uint64_t, std::vector<uint8_t>>(*id, tmp));
  }
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
  printf("bridgeUrl:%s\n", bridgeUrl);
  bridgeSocket = emscripten_websocket_new(&attr);
  // printf("bridgeSocket\n");
  emscripten_websocket_set_onmessage_callback_on_thread(bridgeSocket, 0, bridge_socket_on_message2, EM_CALLBACK_THREAD_CONTEXT_MAIN_BROWSER_THREAD);
  // printf("set onmessage\n");
  pthread_mutex_unlock(&bridgeLock);
  return bridgeSocket;
}

static std::vector<uint8_t> send_buffer;
static uint64_t send_id = 0;
static uint64_t origin_id = 0;
ssize_t send2(int socket, const void *message, size_t length, int flags, uint64_t id) {
  if (id > 0) origin_id = id;
#ifdef POSIX_SOCKET_DEBUG
  emscripten_log(EM_LOG_NO_PATHS | EM_LOG_CONSOLE | EM_LOG_ERROR | EM_LOG_JS_STACK, "send(socket=%d,message=%p,length=%zd,flags=%d)\n", socket, message, length, flags);
#endif
  if (length > 0 && send_buffer.size() + length + 2 * sizeof(uint64_t) < send_buffer.capacity()) {
#if DEBUG_MSG_INFO
    send_buffer.insert(send_buffer.end(), (uint8_t*)&id, (uint8_t*)(&id + 1));
    uint64_t len = length;
    send_buffer.insert(send_buffer.end(), (uint8_t*)&len, (uint8_t*)(&len + 1));
#endif
    send_buffer.insert(send_buffer.end(), (uint8_t*)message, (uint8_t*)message + length);
    return length;
  }

  // printf("send info id:%llu len:%d\n", id, length);
  
  if (send_buffer.size() > sizeof(uint64_t)) {
    send_id++;
    *(uint64_t*)&send_buffer[0] = send_id;
    emscripten_websocket_send_binary(bridgeSocket, (void *)send_buffer.data(), send_buffer.size());
    // printf("send buffer info id:%llu len:%llu origin id:%llu\n", send_id, (uint64_t)send_buffer.size(), length > 0? origin_id - 1: origin_id);

    send_buffer.reserve(NETWORK_BUFFER_SIZE);
    send_buffer.resize(sizeof(uint64_t));
  }
  if (length > 0) {
#if DEBUG_MSG_INFO
    send_buffer.insert(send_buffer.end(), (uint8_t*)&id, (uint8_t*)(&id + 1));
    uint64_t len = length;
    send_buffer.insert(send_buffer.end(), (uint8_t*)&len, (uint8_t*)(&len + 1));
#endif
    send_buffer.insert(send_buffer.end(), (uint8_t*)message, (uint8_t*)message + length);
  }

  return length;
}

ssize_t recv2(int socket, void *buffer, size_t length, int flags, uint64_t id) {
#ifdef POSIX_SOCKET_DEBUG
  emscripten_log(EM_LOG_NO_PATHS | EM_LOG_CONSOLE | EM_LOG_ERROR | EM_LOG_JS_STACK, "recv(socket=%d,buffer=%p,length=%zd,flags=%d)\n", socket, buffer, length, flags);
#endif
  size_t len = 0;
  // printf("begin recv2 id:%lu size:%lu\n", id, length);
  while (len == 0) {
    while (!recvBufferFlag)
        emscripten_futex_wait(&recvBufferFlag, 0, 1e9);
  
    pthread_mutex_lock(&recvLock);
    // printf("need: %lu recv buffer size:%lu\n", length, recv_buffer.size());
  #if DEBUG_MSG_INFO
    if (recv_buffer.size() >= length + 2 * sizeof(uint64_t)) {
      uint64_t *actual_id = (uint64_t*)recv_buffer.data();
      uint64_t *actual_len = actual_id + 1;
      // printf("debug id actual:%llu expect:%llu  length: actual:%llu expect:%llu\n", *actual_id, id, *actual_len, (uint64_t)length);
      if (*actual_id != id || *actual_len != length) {
        printf("id actual:%llu expect:%llu  length: actual:%llu expect:%llu\n", *actual_id, id, *actual_len, (uint64_t)length);
        assert(false);
      }
  
      memcpy(buffer, recv_buffer.data() + 2 * sizeof(uint64_t), length);
      recv_buffer.erase(recv_buffer.begin(), recv_buffer.begin() + 2 * sizeof(uint64_t) + length);
      len = length;
      recvBufferFlag = recv_buffer.empty() ? 0: 1;
    }
  #else
    if (recv_buffer.size() >= length) {
      memcpy(buffer, recv_buffer.data(), length);
      recv_buffer.erase(recv_buffer.begin(), recv_buffer.begin() + length);
      len = length;
      recvBufferFlag = recv_buffer.empty() ? 0: 1;
    }
  #endif
    else {
      recvBufferFlag = 0;
    }
    pthread_mutex_unlock(&recvLock);
  }

  return len;
}
#endif

#define RECORD_MSG_INFO 1
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
#if RECORD_MSG_INFO
    FILE* debug_file = nullptr;
#endif
    WebSocketIO(const char * address, int port, bool quiet = false) {
        if (port <0 || port > 65535) {
            throw std::runtime_error("Invalid port number!");
        }

        this->port = port;
        is_server = (address == nullptr);
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
            bridgeSocket = emscripten_init_websocket_to_posix_socket_bridge2(wsaddr);
            // Synchronously wait until connection has been established.
            uint16_t readyState = 0;
            // printf("begin readystate\n");
            do {
              emscripten_websocket_get_ready_state(bridgeSocket, &readyState);
              emscripten_thread_sleep(100);
            } while (readyState == 0);
            // printf("end readystate\n");
            send_buffer.reserve(NETWORK_BUFFER_SIZE);
            send_buffer.resize(sizeof(uint64_t));
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
            flush();
        }
    }

    ~WebSocketIO(){
        flush();
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

    void flush() {
#ifndef __EMSCRIPTEN__
        send_data_internal(NULL, 0);
        fflush(stream);
#else
        send2(0, NULL, 0, 0, 0);
#endif
    }

    void send_data_internal(const void * data, size_t len) {
        size_t sent = 0;
        void* d = (void*)data;
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
        string websocket_data = GenWebSocketMessage(data, len, send_id, true);
        d = &websocket_data[0];
        len = websocket_data.size();
#endif

        while(sent < len) {
#ifndef __EMSCRIPTEN__
            size_t res = fwrite(sent + (char*)d, 1, len - sent, stream);
#else
            size_t res = send2(0, sent + (char*)d, len - sent, 0, send_id);
#endif
            if (res > 0)
                sent+=res;
            else
                error("net_send_data\n");
        }
        has_sent = true;
    }

    void recv_data_internal(void  * data, size_t len) {
        if(has_sent)
            flush();
        has_sent = false;
        size_t sent = 0;
        recv_id++;
        while(sent < len) {
#ifndef __EMSCRIPTEN__
#if RECORD_MSG_INFO
            fprintf(debug_file, "recv data id: %llu len:%llu\n", (uint64_t)recv_id, (uint64_t)len);
            fflush(debug_file);
#endif
            string d = GetMessage(consocket, len - sent, recv_id, true);
            size_t res = d.size();
            memcpy(sent + (char*)data, d.data(), res);
#else
            size_t res = recv2(0, sent + (char*)data, len - sent, 0, recv_id);
#endif
            if (res > 0)
                sent += res;
            else
                error("net_recv_data\n");
        }
    }
};

}

#endif  //WEBSOCKET_IO_CHANNEL

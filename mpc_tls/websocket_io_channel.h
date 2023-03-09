#ifndef EMP_WEBSOCKET_IO_CHANNEL
#define EMP_WEBSOCKET_IO_CHANNEL

#include <iostream>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <string>
#include "emp-tool/io/io_channel.h"
using std::string;


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
  printf("bridgeUrl:%s\n", bridgeUrl);
  bridgeSocket = emscripten_websocket_new(&attr);
  printf("bridgeSocket\n");
  emscripten_websocket_set_onmessage_callback_on_thread(bridgeSocket, 0, bridge_socket_on_message2, EM_CALLBACK_THREAD_CONTEXT_MAIN_BROWSER_THREAD);
  printf("set onmessage\n");
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
#endif

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
#endif
        }
        else {
#ifdef __EMSCRIPTEN__
            char wsaddr[256];
            snprintf(wsaddr, sizeof(wsaddr), "ws://%s:%d", address, port);
            bridgeSocket = emscripten_init_websocket_to_posix_socket_bridge2(wsaddr);
            // Synchronously wait until connection has been established.
            uint16_t readyState = 0;
            printf("begin readystate\n");
            do {
              emscripten_websocket_get_ready_state(bridgeSocket, &readyState);
              emscripten_thread_sleep(100);
            } while (readyState == 0);
            printf("end readystate\n");
#endif


            /*struct sockaddr_in dest;
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
            CheckWebSocketHandshake(consocket);*/
        }
        if (is_server) {
            set_nodelay();
            stream = fdopen(consocket, "wb+");
            buffer = new char[NETWORK_BUFFER_SIZE];
            memset(buffer, 0, NETWORK_BUFFER_SIZE);
            setvbuf(stream, buffer, _IOFBF, NETWORK_BUFFER_SIZE);
        }
        if(!quiet)
            std::cout << "connected\n";
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
        if (is_server) {
            flush();
            fclose(stream);
            delete[] buffer;
        }
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
        if (is_server)
            fflush(stream);
    }

    void send_data_internal(const void * data, size_t len) {
        size_t sent = 0;
        void* d = (void*)data;
#ifndef __EMSCRIPTEN__
        string websocket_data = GenWebSocketMessage(data, len);
        d = &websocket_data[0];
        len = websocket_data.size();
#endif

        while(sent < len) {
#ifndef __EMSCRIPTEN__
            size_t res = fwrite(sent + (char*)d, 1, len - sent, stream);
#else
            size_t res = send2(0, sent + (char*)d, len - sent, 0);
#endif
            if (res > 0)
                sent+=res;
            else
                error("net_send_data\n");
        }
        flush();
        has_sent = true;
    }

    void recv_data_internal(void  * data, size_t len) {
        if (is_server) {
            if(has_sent)
                fflush(stream);
            has_sent = false;
        }
        size_t sent = 0;
        while(sent < len) {
#ifndef __EMSCRIPTEN__
            // size_t res = fread(sent + (char*)data, 1, len - sent, stream);
            string d = GetMessage(consocket, len - sent);
            size_t res = d.size();
            memcpy(sent + (char*)data, d.data(), res);
#else
            size_t res = recv2(0, sent + (char*)data, len - sent, 0);
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

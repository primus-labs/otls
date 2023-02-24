#include"net_io_channel.h"
#ifdef __EMSCRIPTEN__
#include <emscripten.h>
#include <emscripten/websocket.h>
#include <emscripten/threading.h>
#include <emscripten/posix_socket.h>

static EMSCRIPTEN_WEBSOCKET_T bridgeSocket = 0;
#endif
emp::NetIO *io = nullptr;
void run_client() {
    char buf[1024];
    int count = 0;
    for (int count = 0; ; count++) {
        snprintf(buf, sizeof(buf), "test %d", count);
        int l = strlen(buf);
        printf("begin send: %s\n", buf);
        io->send_data(buf, l);
        io->flush();
        printf("end send: %s\n", buf);
        //count++;

        char recv[256];
        memset(recv, 0, sizeof(recv));
        printf("begin recv %d\n", l);
        io->recv_data(recv, l);
        printf("recv: %s\n", recv);
    }
}

void run_server() {
    char buf[1024];
    while (1) {
        memset(buf, 0, sizeof(buf));
        io->recv_data(buf, 100);
        printf("recv: %s\n", buf);
    }
}
int main(int argc, char* argv[]) {
#ifdef __EMSCRIPTEN__
  bridgeSocket = emscripten_init_websocket_to_posix_socket_bridge("ws://localhost:8080");
  // Synchronously wait until connection has been established.
  uint16_t readyState = 0;
  printf("begin readystate\n");
  do {
    emscripten_websocket_get_ready_state(bridgeSocket, &readyState);
    emscripten_thread_sleep(100);
  } while (readyState == 0);
  printf("end readystate\n");
#endif
    printf("test\n");
    io = new emp::NetIO("127.0.0.1", 7777);
    run_client();
    return 0;
}

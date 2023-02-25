#include"net_io_channel.h"
#include <chrono>
using std::chrono::time_point;
using std::chrono::high_resolution_clock;

#ifdef __EMSCRIPTEN__
#include <emscripten.h>
#include <emscripten/websocket.h>
#include <emscripten/threading.h>
#include <emscripten/posix_socket.h>

static EMSCRIPTEN_WEBSOCKET_T bridgeSocket = 0;
#endif
emp::NetIO *io = nullptr;
inline time_point<high_resolution_clock> clock_start() { 
    return high_resolution_clock::now();
}

inline double time_from(const time_point<high_resolution_clock>& s) {
    return std::chrono::duration_cast<std::chrono::microseconds>(high_resolution_clock::now() - s).count();
}
void run_client() {
    char buf[1024];
    int count = 0;
    time_t begin = time(NULL);
    auto begin2 = clock_start();
    double sum = 0;
    for (int count = 1; ; count++) {
        snprintf(buf, sizeof(buf), "hello world");
        int l = strlen(buf);
        //printf("begin send: %s\n", buf);
        io->send_data(buf, l);
        io->flush();
        auto send_time = clock_start();
        //printf("end send: %s\n", buf);
        //count++;

        char recv[256];
        memset(recv, 0, sizeof(recv));
        //printf("begin recv %d\n", l);
        io->recv_data(recv, l);
        sum += time_from(send_time);
        //printf("recv: %s\n", recv);
        time_t end = time(NULL);
        double t = time_from(begin2);
        if (end - begin > 120) {
            printf("%lld %lld\n", begin, end);
            printf("%f %d %f\n", t, count, (count / t)* 1e6);
            printf("%f %f\n", sum, sum /  count / 1e3);
            break;
        }
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

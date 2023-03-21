
#ifdef __cplusplus
extern "C" {
#endif

typedef int (*send_meth)(int fd, const void* buf, size_t len);
int init_proxy(send_meth send);
int emscripten_init_websocket_to_posix_socket_bridge(const char *address, int port);
int socket3(int domain, int type, int protocol);
int connect3(int socket, const struct sockaddr *address, socklen_t address_len);
ssize_t send3(int socket, const void *message, size_t length, int flags);
ssize_t recv3(int socket, void *buffer, size_t length, int flags);

#ifdef __cplusplus
}
#endif

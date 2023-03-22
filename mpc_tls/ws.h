#include<string>
using namespace std;

#define DEBUG_MSG_INFO 0
void RequestWebSocketHandshake(int fd);

void ResponseWebSocketHandshake(int fd);

void CheckWebSocketHandshake(int fd);

string GenWebSocketMessage(const void *buf, uint64_t numBytes, uint64_t id, bool enable_id);

string GetMessage(int fd, int len, uint64_t id, bool enable_id);

string GenWebSocketMessageProxy(const void *buf, uint64_t numBytes, uint64_t id, bool enable_id);

string GetMessageProxy(int fd, int len, uint64_t id, bool enable_id);

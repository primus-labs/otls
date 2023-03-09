#include<string>
using namespace std;

void RequestWebSocketHandshake(int fd);

void ResponseWebSocketHandshake(int fd);

void CheckWebSocketHandshake(int fd);

string GenWebSocketMessage(const void *buf, uint64_t numBytes, uint64_t id);

string GetMessage(int fd, int len, uint64_t id);

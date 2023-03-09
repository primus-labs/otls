#include<string>
using namespace std;

void RequestWebSocketHandshake(int fd);

void ResponseWebSocketHandshake(int fd);

void CheckWebSocketHandshake(int fd);

string GenWebSocketMessage(const void *buf, uint64_t numBytes);

string GetMessage(int fd, int len);

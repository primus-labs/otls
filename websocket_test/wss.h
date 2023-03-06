#include<string>
#include<openssl/ssl.h>
using namespace std;

void RequestWebSocketHandshake(SSL* ssl);

void ResponseWebSocketHandshake(SSL* ssl);

void CheckWebSocketHandshake(SSL* ssl);

string GenWebSocketMessage(const void *buf, uint64_t numBytes);

string GetMessage(SSL* ssl);

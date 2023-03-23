#include <stdlib.h>
#include <stdio.h>
#ifdef __cplusplus
extern "C" {
#endif

struct hostent *gethostbyname(const char *name) {
    printf("gethostbyname: %s\n", name);
    return NULL;
}
struct hostent *gethostbyaddr(const char *addr, int length, int type) {
    printf("gethostbyaddr: %s %d %d\n", addr, length, type);
    return NULL;
}
/*struct servent *getservbyname(const char *name, const char *proto) {
    return NULL;
}*/

#ifdef __cplusplus
}
#endif

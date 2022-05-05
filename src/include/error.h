#include <stdio.h>

typedef enum _error_code{
    ARGUMENT,
    SOCKET,
    BIND,
    LISTEN,
    ACCEPT,
    CONNECT,
    READ
}ERROR_CODE;

void errorHandler(int errorType);

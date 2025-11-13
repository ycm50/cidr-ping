#ifndef CIDR_PING_H
#define CIDR_PING_H

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <errno.h>



#ifdef _WIN32
#include <winsock2.h>
#include <ws2tcpip.h>
#include <windows.h>
#pragma comment(lib, "ws2_32.lib")
#else // POSIX
#include <sys/socket.h>
#include <netdb.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <sys/time.h>
#endif

#if defined(_WIN32) && defined(CIDR_PING_SHARED)
    #ifdef CIDR_PING_EXPORTS
        #define CIDR_PING_API __declspec(dllexport)
    #else
        #define CIDR_PING_API __declspec(dllimport)
    #endif
#elif defined(__GNUC__) && defined(CIDR_PING_SHARED)
    #define CIDR_PING_API __attribute__((visibility("default")))
#else
    #define CIDR_PING_API
#endif

#ifdef __cplusplus
extern "C" {
#endif 
CIDR_PING_API int cidr_ping_main(int argc, char *argv[]);
#ifdef __cplusplus
}
#endif

#endif // CIDR_PING_H
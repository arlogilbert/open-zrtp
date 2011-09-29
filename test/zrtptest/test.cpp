#include <stdio.h>

#ifdef _WIN32
#include "stdafx.h"
#endif

extern void test_hello();
extern void test_helloack();
extern void test_endpointinfo();
extern void test_zrecord();
extern void test_ping();
extern void test_main();

int main(int argc, char* argv[])
{
    printf("zrtptest begin");

#ifdef _WIN32
	WORD wVersionRequested(MAKEWORD(2,2));
	WSADATA wsaData;
	if (WSAStartup(wVersionRequested, &wsaData))
	{
		perror("Windows socket library initialization error.");
		exit(1);
	}
#endif

    test_main();
    //test_hello();
    //test_helloack();

#ifdef _WIN32
	WSACleanup();
#endif

    printf("zrtptest end");

    return 0;
}

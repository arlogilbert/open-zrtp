/*

Copyright 2010-2011 iCall, Inc.

This file is part of Open ZRTP.

Open ZRTP is free software: you can redistribute it and/or modify it under the terms of the GNU Lesser General Public License as published bythe Free Software Foundation, either version 3 of the License, or(at your option) any later version.

Open ZRTP is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU Lesser General Public License for more details.

You should have received a copy of the GNU Lesser General Public Licensealong with Open ZRTP. If not, see http://www.gnu.org/licenses/.

*/

#pragma once

#ifndef _WIN32_WINNT
#define _WIN32_WINNT 0x0600
#endif

#define WIN32_LEAN_AND_MEAN

#include <stddef.h>
#include <assert.h>
#include <ctype.h>
#include <errno.h>
#include <string.h>
#include <math.h>
#include <time.h>

#include <network.h>

#include <string>
#include <iostream>
#include <list>

#include <openssl/aes.h>
#include <openssl/bio.h>
#include <openssl/bn.h>
#include <openssl/crypto.h>
#include <openssl/dh.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/hmac.h>
#include <openssl/rand.h>
#include <openssl/sha.h>

#include <pthread.h>

#include <int.h>

inline int gettimeofday (struct timeval *tv, void* tz) 
{ 
	union { 
		long long ns100; /*time since 1 Jan 1601 in 100ns units */ 
		FILETIME ft; 
	} now;

	::GetSystemTimeAsFileTime (&now.ft); 

	tv->tv_usec = (long) ((now.ns100 / 10LL) % 1000000LL); 
	tv->tv_sec = (long) ((now.ns100 - 116444736000000000LL) / 10000000LL); 
	return (0); 
}

// stdafx.h : include file for standard system include files,
// or project specific include files that are used frequently, but
// are changed infrequently
//

#pragma once

// The following macros define the minimum required platform.  The minimum required platform
// is the earliest version of Windows, Internet Explorer etc. that has the necessary features to run 
// your application.  The macros work by enabling all features available on platform versions up to and 
// including the version specified.

// Modify the following defines if you have to target a platform prior to the ones specified below.
// Refer to MSDN for the latest info on corresponding values for different platforms.
#ifndef _WIN32_WINNT            // Specifies that the minimum required platform is Windows Vista.
#define _WIN32_WINNT 0x0600     // Change this to the appropriate value to target other versions of Windows.
#endif

#define WIN32_LEAN_AND_MEAN             // Exclude rarely-used stuff from Windows headers

#include <stddef.h>
#include <assert.h>
#include <ctype.h>
#include <errno.h>
#include <string.h>
#include <math.h>
#include <time.h>
#include <network.h>
#include <iostream>
#include <map>

#include <pthread.h>
#include "../../int.h"

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

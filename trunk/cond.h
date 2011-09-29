/*

Copyright 2010-2011 iCall, Inc.

This file is part of Open ZRTP.

Open ZRTP is free software: you can redistribute it and/or modify it under the terms of the GNU Lesser General Public License as published bythe Free Software Foundation, either version 3 of the License, or(at your option) any later version.

Open ZRTP is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU Lesser General Public License for more details.

You should have received a copy of the GNU Lesser General Public Licensealong with Open ZRTP. If not, see http://www.gnu.org/licenses/.

*/

#ifndef COND_H_INCLUDED
#define COND_H_INCLUDED

#include "synch.h"
#include <time.h>

#ifdef _WIN32
#include "stdafx.h"
#endif

class Cond : public Sync
{
public:
	Cond()
	{
		pthread_cond_init(&cond, NULL);
	}

	~Cond()
	{
		pthread_cond_destroy(&cond);
	}

	int Wait(uint32_t waiting_time)
	{
		struct timeval tp;

		struct timespec ts;

		int rc;

		gettimeofday(&tp, NULL);

		ts.tv_sec =tp.tv_sec;
		ts.tv_nsec = tp.tv_usec * 1000;
		ts.tv_sec += (waiting_time/1000);

		Enter();
		rc = pthread_cond_timedwait(&cond, _GetRawMutex(),&ts);
		Leave();

		return rc;
	}

	void Signal()
	{
		Enter();

		pthread_cond_signal(&cond);

		Leave();
	}

private:
	pthread_cond_t cond;
};

#endif // COND_H_INCLUDED

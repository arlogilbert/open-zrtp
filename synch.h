/*

Copyright 2010-2011 iCall, Inc.

This file is part of Open ZRTP.

Open ZRTP is free software: you can redistribute it and/or modify it under the terms of the GNU Lesser General Public License as published bythe Free Software Foundation, either version 3 of the License, or(at your option) any later version.

Open ZRTP is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU Lesser General Public License for more details.

You should have received a copy of the GNU Lesser General Public Licensealong with Open ZRTP. If not, see http://www.gnu.org/licenses/.

*/

#ifndef __synch_h__
#define __synch_h__

#include <pthread.h>

class Sync
{
public:
	Sync()
	{
		pthread_mutex_init(&mutex, NULL);
	}

	void Enter()
	{
		pthread_mutex_lock(&mutex);
	}

	void Leave()
	{
		pthread_mutex_unlock(&mutex);
	}

	~Sync()
	{
		pthread_mutex_destroy(&mutex);
	}

protected:
	pthread_mutex_t* _GetRawMutex()
	{
		return &mutex;
	}

private:
	pthread_mutex_t mutex;
};

#endif // __synch_h__

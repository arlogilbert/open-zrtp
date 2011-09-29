/*

Copyright 2010-2011 iCall, Inc.

This file is part of Open ZRTP.

Open ZRTP is free software: you can redistribute it and/or modify it under the terms of the GNU Lesser General Public License as published bythe Free Software Foundation, either version 3 of the License, or(at your option) any later version.

Open ZRTP is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU Lesser General Public License for more details.

You should have received a copy of the GNU Lesser General Public Licensealong with Open ZRTP. If not, see http://www.gnu.org/licenses/.

*/

#ifndef BASICQUEUE_H_INCLUDED
#define BASICQUEUE_H_INCLUDED

#include <pthread.h>
#include <string.h>
#include <list>
#include <errno.h>
#include "cond.h"

using namespace std;

/*
A : is element which will be inserted in the queue
B : TObserver is the observer which will be notified when any element is added in the list
*/
template<typename A, typename TObserver>
class BasicQueue
{
private:
	std::list<A*> packets;
	TObserver* observer;
	Sync mutex;

public:
	BasicQueue(TObserver* observer)//:observer(observer)
	{
		this->observer = observer;
	}

	uint32_t getQueueSize()
	{
		uint32_t n;
		mutex.Enter();
		n = packets.size();
		mutex.Leave();
		return n;
	}

	uint16_t getSizeOfNextPacket()
	{
		uint16_t size;
		A* packet;

		mutex.Enter();
		packet = packets.front();
		mutex.Leave();

		if(packet!=NULL)
		{
			size = packet->getSize();
		}
		else
			size = 0;

		return size;
	}

	A* getNextPacket()
	{
		A* packet;
		mutex.Enter();
		packet = packets.front();
		packets.pop_front();
		mutex.Leave();

		return packet;
	}

	void putPacket(A* packet)
	{

		mutex.Enter();
		packets.push_back(packet);
		mutex.Leave();

		if(observer!=NULL) observer->informNewPacket();
	}
};

template<typename TWorker>
class Observer
{
private:
	Cond cond;
	TWorker* worker;
	pthread_t thread;
	bool stop;
	int32_t default_wait_time;
	list<int> event_queue;
	Sync event_queue_lock;

public:
	Observer(TWorker* worker):worker(worker),stop(false)
	{
		default_wait_time = 3600000L;
	}

	void begin()
	{
		pthread_create(&thread, NULL, &Observer<TWorker>::run, (void*) this);
	}

	void end()
	{
		 if(!stop)
		 {
			 stop = true;

			 cond.Signal();

			 pthread_join(thread, NULL);
		 }
	}

	void informNewPacket()
	{
		event_queue_lock.Enter();
		event_queue.push_back(1);
		event_queue_lock.Leave();
		cond.Signal();
	}

	static void* run(void* nothing)
	{
		Observer<TWorker>* instance = (Observer<TWorker>*)nothing;
		int rc;
		bool empty;
		while(!(instance->stop))
		{
			rc=0;

			instance->event_queue_lock.Enter();
			empty = instance->event_queue.empty();
			instance->event_queue_lock.Leave();

			while(!(instance->stop) && !empty)
			{
				if(!(instance->stop) && rc != ETIMEDOUT) {
					instance->worker->process_packet();

					if(!(instance->stop))
					{
						instance->event_queue_lock.Enter();
						instance->event_queue.pop_front();
						instance->event_queue_lock.Leave();
					}

					if(!(instance->stop))
					{
						instance->event_queue_lock.Enter();
						empty = instance->event_queue.empty();
						instance->event_queue_lock.Leave();
					}
				}
			}

			if(!(instance->stop)) rc=instance->cond.Wait(instance->default_wait_time);
		}
		return 0;
	}
};

#endif // BASICQUEUE_H_INCLUDED

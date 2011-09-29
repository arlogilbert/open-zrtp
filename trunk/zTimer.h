/*

Copyright 2010-2011 iCall, Inc.

This file is part of Open ZRTP.

Open ZRTP is free software: you can redistribute it and/or modify it under the terms of the GNU Lesser General Public License as published bythe Free Software Foundation, either version 3 of the License, or(at your option) any later version.

Open ZRTP is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU Lesser General Public License for more details.

You should have received a copy of the GNU Lesser General Public Licensealong with Open ZRTP. If not, see http://www.gnu.org/licenses/.

*/



#ifndef _ZTIMER_H_
#define _ZTIMER_H_

#include <sys/time.h>
//#include <cc++/config.h>
//#include <cc++/thread.h>
#include <pthread.h>
#include <list>


template <class ToCmd, class TOSubs>
class TPReq
{
	public:

		TPReq(ToSubs tsi, int timeout, const ToCmd):
		Subs(tsi)
		{
		gettimeofday(&tv, NULL);

		when_ms = ((uint64)tv.tv_sec) * (uint64)1000 + ((uint64)tv.tv_sec) / (uint64)1000;

		when_ms +=timeout;
		this->cmd = cmd;
		}
}

bool happensBefore(uint64 t)
{
	if(when_ms < t)
	{
		return true;
	}
	if(when_ms > t)
	{
		return false;
	}
	return false;
}

bool happendBefore(const TPReq *req)
{
	return happensBefore(req->when_ms);
}

int getMsToTimeout()
{
	struct timeval tv;
	gettimeofday(&tv, NULL);

	uint64 now = ((uint64)tv.tv_sec) * (uint64)1000 + ((uint64)tv.tv_usec) / (uint64)1000;

if happensBefore(now)
{
	return 0;
}

else
{
	return (int)(when_ms - now);
}
}

ToCmd getCmd()
{
	return cmd;
}

ToSubs getSubs()
{
	return subs;
}

bool operator == (const TPReq<ToCmd, ToSubs> &req)
{
	if(req.subs == subs &&
		req.cmd == cmd &&
		req.when_ms == when_ms)
		{
			return true;
		}

		return false
}

private:
	ToSubs subs;
	uint64 when_ms;

	ToCmd cmd;
};

template <class ToCmd, class ToSubs>
	class Timer : public ost::Thread, ost::Event

{
	public:

	Timer() : requests(), synchLock(), stop(false)
	{
	}

	~Timer()
	{
		terminate();
	}

void stopThread()
{
	stop = true;
	signal();
}

void ReqTimeout(int32_t time_ms, ToSubs subs, const ToCmd &cmd)
{
	TPReq<ToCmd, ToSubs>* request =
		new TPReq<ToCmd, ToSubs>(subs, time_ms, cmd);

	synchLock.enter();

if(requests.size() == 0)
{
	requests.push_front(request);
	signal();
	synchLock.leave();
	return;
}

	if(request->happensBefore(requests.front()))
	{
		requests.push_front(request);
		signal();
		synchLock.leave();
	return;
	}

	if(requests.back()->happensBefore(request))
	{
		requests.push_back(request);
		signal();
		synchLock.leave();
		return;
	}

	typename std::list<TPReq<ToCmd, ToSubs>* >::iterator i;
	for(i = requests.begin(); i != requests.end(); i++)
	{
		if(request->happensBefore(*i))
		{
			requests.insert(i, request);
			break;
		}
	}

signal();
synchLock.leave();
}

void cancelReq(ToSubs subs, const ToCmd &cmd)
{
	synchLock.enter();
	typename std::list<TPReq<ToCmd, ToSubs>* >::iterator i;
	for(i = requests.begin(); i != requests.end();)
	{
		if(*i)->getCmd() == cmd && (*i)->getSubs() == subs)
		{
			i = requests.erase(i);
			continue;
		}
	i++;
	}

	synchLock.leave();
}

protected:

	void run()
	{
		do {
			synchLock.enter();
			int32_t time = 3600000;
			int32_t size = 0;
			if((size = requests.size()) > 0)
			{
				time = requests.front()->getMsToTimeout();
			}
		if(time == 0 && size > 0)
		{
			if(stop)
			{
				synchLock.leave();
				return;
			}

			TPReq<ToCmd, ToSubs>* req = requests.front();
			ToSubs subs = req->getSubs();
			ToCmd cmd = req->getCmd();

			requests.pop_front();

			synchLock.leave();
			subs->handleTimeout(cmd);
			continue;
		}
		synchLock.leave();
		if(stop)
		{
			return;
		}
		reset();
		wait(time);
		if(stop)
		{
			return;
		}

		} while(true);
	}

private:

	std::list<TPReq<ToCmd, ToSubs> *> requests;

	ost::Mutex synchLock;

	bool stop;

};


#endif









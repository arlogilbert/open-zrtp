/*

Copyright 2010-2011 iCall, Inc.

This file is part of Open ZRTP.

Open ZRTP is free software: you can redistribute it and/or modify it under the terms of the GNU Lesser General Public License as published bythe Free Software Foundation, either version 3 of the License, or(at your option) any later version.

Open ZRTP is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU Lesser General Public License for more details.

You should have received a copy of the GNU Lesser General Public Licensealong with Open ZRTP. If not, see http://www.gnu.org/licenses/.

*/


#ifndef ZTIMER_2_H
#define ZTIMER_2_H

//extern "C" {
#include <pthread.h>
#include <iostream>
#include <stdio.h>
#include <stdlib.h>
#include <list>
#include "int.h"

#ifdef _WIN32
#include <time.h>
#else
#include <sys/time.h>
#endif

//#define DEBUG_1

typedef void*(*THREAD_FUNC)(void*);

template <class ToCmd, class ToSubs>
class TPReq
{


	public:

		TPReq(ToSubs tsi, int timeout, const ToCmd cmd):subs(tsi)
		{

		struct timeval tv;
		gettimeofday(&tv, NULL);

		when_ms = ((uint64_t)tv.tv_sec) * (uint64_t)1000 + ((uint64_t)tv.tv_usec) / (uint64_t)1000;

		#ifdef DEBUG_1
		std::cout << "TPReq when_ms "<<when_ms << std::endl;
		#endif

		when_ms +=timeout;

		#ifdef DEBUG_1
		std::cout << "TPReq timeout "<<timeout << std::endl;


		std::cout << "TPReq when_ms "<<when_ms << std::endl;
		 #endif

		this->cmd = cmd;

		}


		bool happensBefore(uint64_t t)
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

		bool happensBefore(const TPReq *req)
		{
			return happensBefore(req->when_ms);
		}

		int getMsToTimeout()
		{
			struct timeval tv;
			gettimeofday(&tv, NULL);

			uint64_t now = ((uint64_t)tv.tv_sec) * (uint64_t)1000 + ((uint64_t)tv.tv_usec) / (uint64_t)1000;

			#ifdef DEBUG_1
			std::cout << "getMsToTimeout when_ms "<<when_ms << std::endl;
			std::cout << "getMsToTimeout now "<<now << std::endl;
			#endif

			if (happensBefore(now))
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

				return false;
		}

		private:
			ToSubs subs;
			uint64_t when_ms;

			ToCmd cmd;
};

//Global declaration
class Lock
{
	private:
			static pthread_mutex_t mutex;

	public:
			Lock()
			{
				//pthread_mutex_init(&mutex, NULL);
				pthread_mutex_lock(&mutex);
			}

			~Lock()
			{
				pthread_mutex_unlock(&mutex);
				//pthread_mutex_destroy(&mutex);
			}
};

template <class ToCmd, class ToSubs>
class Timer
{
	private:

			 std::list<TPReq<ToCmd, ToSubs>*> requests;
			//std::list<int> requests;

			 bool stop;

			// pthread_mutex_t create_mutex;

			pthread_mutex_t mutex, cond_mutex ;

			pthread_t timer_thread;

			pthread_cond_t cond;

			void terminate()
			{
				pthread_join(timer_thread, NULL);
			}

			void lock()
			{
				int rc = 0;

				rc = pthread_mutex_lock(&mutex);

			}

			void unlock()
			{
				int rc = 0;

				rc = pthread_mutex_unlock(&mutex);
			}

			void wait(int32_t time)
			{
				struct timeval tp;

				struct timespec ts;

				gettimeofday(&tp, NULL);

				ts.tv_sec =tp.tv_sec;
				ts.tv_nsec = tp.tv_usec * 1000;
				ts.tv_sec += (time/1000);

				pthread_mutex_lock(&cond_mutex);
				pthread_cond_timedwait(&cond, &cond_mutex,&ts);
				pthread_mutex_unlock(&cond_mutex);
			}

			void signal()
			{
				pthread_mutex_lock(&cond_mutex);
				pthread_cond_signal(&cond);
				pthread_mutex_unlock(&cond_mutex);
			}




	public:
			Timer()
			{
				pthread_mutex_init(&mutex, NULL);
				pthread_mutex_init(&cond_mutex, NULL);

				pthread_cond_init(&cond, NULL);

			}
			//static Timer<ToCmd,ToSubs> * instance ;

			/*static Timer* get_instance()
			{

				if(instance == NULL)
				{
						instance = new Timer();
				}
				return instance;
			}*/

			void print_time()
			{
				struct timeval tv;
				gettimeofday(&tv, NULL);
				std::cout << "Timestamp : "<<tv.tv_sec << std::endl;

			}

			~Timer()
			{
			   stopThread();

			   pthread_mutex_destroy(&mutex);
			   pthread_mutex_destroy(&cond_mutex);
			   pthread_cond_destroy(&cond);

			   pthread_exit(&timer_thread);

			}

			void init()
			{
				int rc = 0;

				stop = false;


				//void* ptr = reinterpret_cast<void*>(&(Timer<ToCmd, ToSubs>::thread_run));

				rc = pthread_create(&timer_thread, NULL, &Timer<ToCmd, ToSubs>::thread_run, (void*) this);
				//rc = pthread_create(&timer_thread, NULL, NULL, NULL);

			}

			void destroy()
			{

			}

			void stopThread()
			{
				if(stop == false)
				{
					stop = true;
					signal();
					//pthread_join(timer_thread, NULL);
					terminate();
				}
			}


			void ReqTimeout(int32_t time_ms, ToSubs subs, const ToCmd &cmd)
			{
			TPReq<ToCmd, ToSubs>* request =
					new TPReq<ToCmd, ToSubs>(subs, time_ms, cmd);

			lock();

			if(requests.size() == 0)
			{
			requests.push_front(request);
			signal();
			unlock();
			return;
			}

			if(request->happensBefore(requests.front()))
			{
			requests.push_front(request);
			signal();

			unlock();

			return;
			}

			if(requests.back()->happensBefore(request))
			{
			requests.push_back(request);
			signal();
			unlock();
			//synchLock.leave();
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
			//synchLock.leave();
			unlock();
			}


			void cancelReq(ToSubs subs, const ToCmd &cmd)
			{
			//synchLock.enter();
			lock();

			typename std::list<TPReq<ToCmd, ToSubs>* >::iterator i;
			for(i = requests.begin(); i != requests.end();)
			{
			if((*i)->getCmd() == cmd && (*i)->getSubs() == subs)
			{
				i = requests.erase(i);
				continue;
			}
			i++;
			}
			unlock();
			//synchLock.leave();
			}

			static void* thread_run(void* nothing)
			{

			Timer* instance = (Timer*) nothing;
			do {
			instance->lock();
			//synchLock.enter();
			int32_t time = 1000;
			int32_t size = 0;
			if((size = instance->requests.size()) > 0)
			{
				time = instance->requests.front()->getMsToTimeout();
				#ifdef DEBUG_1
				std::cout << "time remaining " <<time << std::endl;
				#endif
			}
			if(time == 0 && size > 0)
			{
			if(instance->stop)
			{
				instance->unlock();
				//synchLock.leave();
				return NULL;
			}

			TPReq<ToCmd, ToSubs>* req = instance->requests.front();
			ToSubs subs = req->getSubs();
			ToCmd cmd = req->getCmd();

			instance->requests.pop_front();

			instance->unlock();
			//synchLock.leave();
			subs.handleTimeout(cmd);
			continue;
			}
			instance->unlock();
			////synchLock.leave();
			if(instance->stop)
			{
			return NULL;
			}
			//reset();
			instance->wait(time);
			if(instance->stop)
			{
				return NULL;
			}
			//instance->print_time();
			} while(true);

			return NULL;
	}

};

/*template<class ToCmd, class ToSubs> Timer<ToCmd,ToSubs>* Timer<ToCmd,ToSubs>::instance;
template<class ToCmd, class ToSubs> bool Timer<ToCmd,ToSubs>::stop;
template<class ToCmd, class ToSubs> pthread_mutex_t Timer<ToCmd,ToSubs>::create_mutex;
template<class ToCmd, class ToSubs> std::list<TPReq<ToCmd,ToSubs>*> Timer<ToCmd,ToSubs>::requests;*/

#endif

#include <iostream>
#include "../../zTimer2.h"
#include "../../basicqueue.h"

using namespace std;

class Worker;
//class Packet;

namespace {
void doSleep(int ms)
{
#ifdef _WIN32
	::Sleep(ms);
#else
	sleep(ms);
#endif
}
}


typedef Observer<Worker> OBSERVER;


class Packet
{
    private:
           int n;
    public:
           Packet(int n):n(n)
           {
           }

           int getPacketNumber()
           {
               return n;
           }
};



class Worker
{

    BasicQueue<Packet, OBSERVER> *queue;
    public:
            Worker():queue(NULL)
            {
            }

            void setQueue(BasicQueue<Packet, OBSERVER>* q)
            {
                queue = q;
            }

            void process_packet()
            {
                cout<<"Process packet called"<<endl;
                if(queue!=NULL)
                {
                    Packet* p = queue->getNextPacket();
                    cout<<"Packet Number"<<p->getPacketNumber()<<endl;
                }
            }
};
class IntWrap
{
    public :
            int cmd;

            IntWrap():cmd(0)
            {
            }

            IntWrap(int cmd1) : cmd(cmd1)
            {
            }

            bool operator == (const IntWrap &req)
            {

                return (cmd == req.cmd);

            }
}
;

class TimeoutHandle
{
    public :

    void handleTimeout(IntWrap cmd)
    {
        cout << "Timeout called " << cmd.cmd << endl;
    }

    bool operator == (const TimeoutHandle &req)
    {
        return true;
    }

};

template<typename A, typename B>
class Gen
{
    private:
            static Gen* instance ;

            Gen()
            {
            }
    public:
            static Gen* get_instance()
            {
                if(instance == NULL)
                {
                    instance = new Gen();
                }
                return instance;
            }
};

template<typename A, typename B> Gen<A,B>* Gen<A,B>::instance;

IntWrap wrap1(1), wrap2(2), wrap3(3), wrap4(4) ;
//template<> Timer<IntWrap, TimeoutHandle> Timer<IntWrap, TimeoutHandle>::instance = NULL;
//template<> IntWrap Gen<IntWrap, TimeoutHandle>::a = wrap1;

//template<> TimeoutHandle Gen<
void* run(void* no)
{
	return 0;
}

int main2()
{
    Worker worker;
    //Packet packet;
    OBSERVER *observer=new OBSERVER(&worker);
    BasicQueue<Packet,OBSERVER> queue(observer);
    worker.setQueue(&queue);
    observer->begin();
    //doSleep(1);
    queue.putPacket(new Packet(1));
    //doSleep(1);
    queue.putPacket(new Packet(2));
    queue.putPacket(new Packet(3));
    queue.putPacket(new Packet(4));
    queue.putPacket(new Packet(5));
    doSleep(2);
    queue.putPacket(new Packet(6));
    queue.putPacket(new Packet(7));
    queue.putPacket(new Packet(8));

    queue.putPacket(new Packet(9));
    queue.putPacket(new Packet(10));
    queue.putPacket(new Packet(11));
    doSleep(1);
    observer->end();

    return 0;
}

int main1()
{
    cout << "Hello world!" << endl;

    //Timer<class IntWrap, class TimeoutHandle>* ztimer = new Timer<class IntWrap, class TimeoutHandle>();
    TimeoutHandle handle;
    IntWrap wrap1(1), wrap2(2), wrap3(3), wrap4(4) ;
    Timer<IntWrap, TimeoutHandle> *ztimer = new Timer<IntWrap,TimeoutHandle>();
    Gen<int, float> *gen = Gen<int, float>::get_instance();

    //pthread_t thrd;

    //pthread_create(&thrd, NULL, run, NULL);


    //Gen<IntWrap, TimeoutHandle> gen(handle);
    //template<typename A, typename B> A gen::a = wrap1;//Gen<IntWrap, TimeoutHandle>::a = wrap1;
    //gen.b = handle;

    cout << "before init" << endl;
    ztimer->init();

    cout << "before 1" << endl;
    ztimer->ReqTimeout(4000, handle,wrap1);

    cout << "before 2" << endl;
    ztimer->ReqTimeout(3100, handle,wrap2);

    cout << "before 3" << endl;
    ztimer->ReqTimeout(2000, handle,wrap3);

    ztimer->cancelReq(handle, wrap2);

    cout << "before 4" << endl;
    ztimer->ReqTimeout(1000, handle,wrap4);

    doSleep(5);
    ztimer->print_time();
    ztimer->stopThread();
    ztimer->print_time();
    //ztimer->stopThread();

    return 0;
}

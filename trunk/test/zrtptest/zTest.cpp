#include <cstdlib>
#include <map>
#include "../../zCallback.h"
#include "../../rtp.h"

#ifdef CCXX_NAMESPACES
using namespace ost;
using namespace std;
using namespace zCodes;
#endif
/*
class PatternPkt
{
    public:

    uint32_t getPktNumber() const
    {
        return PktNumber;
    }

    inline const tpport_t
    getDestPort() const
    {
        return destPort;
    }

    inline const InetHostAdd & getDestAdd() const
    {
        return destAdd;
    }

    uint32 getSsrc() const
    {
        return 0xdeadbeef;
    }

    const unsigned char* getPktData(uint32 i)
    {
        return data[i%2];
    }

    const size_t getPktSize(uint32 i)
    {
        return strlen((char*)data[i%2] + 1;
    }

private:

    static const unsigned char* data[];
    static const uint16 destPort = 5002;
    static const uint32 PktNumber = 10;
    static const InetHostAdd destAdd;
    static const uint32 PktSize = 12;
};

const InetHostAdd PatternPkt::destAdd = InetHostAdd("localHost");

const unsigned char* PatternPkt::data[] = {
    (unsigned char*)"0123456789\n",
    (unsigned char*)"987654321\n"
};

PatternPkt pattern;


//Security mode ZRTP session
class zPacketSendTransTest: public Thread, public TimerPort
{
    public:

    void run()
    {
        Test();
    }

    int Test()
    {
        zSymmSession tx(pattern.getSsrc(), pattern.getDestAdd(), pattern.getDestPort() + 2);

        tx.initialize("test_t.ZID");
        tx.setSchedulingTimeout(10000);
        tx.setExpireTimeout(1000000);

        tx.startRunning();
        tx.setPayloadFormat(StaticPayloadFormat(sptPCMU));
        if(!tx.addDest(pattern.getDestAdd(), pattern.getDestPort()))
        {
            return 1;
        }
        tx.startZrtp();

        uint32 period = 500;
        uint16 inc = tx.getCurrentRTPClockRate()/2;
        TimerPort::setTimer(period);
        uint32 i;
        for(i = 0; i < pattern.getPktNumber(); i++)
        {
            tx.putData(i*inc, pattern.getPktData(i), pattern.getPktSize(i));
            cout << "Sent some data: " << i << endl;
            Thread::sleep(TimerPort::getTimer());
            TimerPort::incTimer(period);
        }
        tx.putData(i*inc, (unsigned char*)"exit", 5);
        Thread::sleep(200);
        return 0;
    }
};

class zPacketReceiveTransTest: public Thread
{
    public:
        void run()
        {
            Test();
        }

        int Test()
        {
            zSymmSession rx(pattern.getSsrc() + 1, pattern.getDestAdd(), pattern.getDestPort());

            rx.initialize("test_r.ZID");
            rx.setSchedulingTimeout(10000);
            rx.setExpireTimeout(1000000);

            rx.startRunning();
            rx.setPayloadFormat(StaticPayloadFormat(sptPCMU));

            if(!rx.addDest(pattern.getDestAdd(), pattern.getDestPort() + 2))
            {
                return 1;
            }
            rx.startZrtp();
            for(int i = 0; i < 5000; i++)
            {
                const UnitAppData* uad;
                while((uad = rx.getData(rx.getFirstTimestamp())))
                {
                    cerr << "got some data: " << uad->getData() << endl;
                    if(*uad->getData() == 'e')
                    {
                        delete uad;
                        return 0;
                    }
                    delete uad;
                }
                Thread::sleep(70);
            }
            return 0;
        }
};

// Non-Security mode

class zPacketSendTransTest: public Thread, public TimerPort
{
    public:
     void run()
     {
         Test();
     }

     int Test();
     {
         zSymmSession tx(pattern.getSsrc(), InetHostAdd("localhost"));
         tx.setSchedulingTimeout(10000);
         tx.setExpireTimeout(1000000);

         tx.startRunning();

         tx.setPayloadFormat(StaticPayloadFormat(sptPCMU));
         if(!tx.addDest(pattern.getDestAdd(), pattern.getDestPort()))
         {
             return 1;
         }

         uint32 period = 500;
         uint16 inc = tx.getCurrentRTPlockRate()/2;
         TimerPort::setTimer(period);
         uint32 i;
         for(i = 0; i < pattern.getPktNumber(); i++)
         {
             tx.putData(i*inc, pattern.getPktData(i), pattern.getPktSize(i));
             cout << "Sent some data:" << i << endl;
             Thread::sleep(TimerPort::getTimer());
             TimerPort::incTimer(period);
         }

         tx.putData(i*inc, (unsigned char*)"exit", 5);
         Thread::sleep(TimerPort::getTimer());
         return 0;
     }
};

class zPacketReceiveTransTest: public Thread
{
    public:
     void run()
     {
         Test();
     }

     int Test()
     {
         zSymmSession rx(pattern.getSsrc() + 1, pattern.getDestAdd(), pattern.getDestPort());

         rx.setSchedulingTimeout(10000);
         rx.setExpireTimeout(1000000);

         rx.startRunning();
         rx.setPayloadFormat(StaticPayloadFormat(sptPCMU));

         if(!rx.addDest(pattern.getDestAdd(), pattern.getDestPort() + 2))
         {
             return 1;
         }

         for(int i = 0; i < 5000; i++)
         {
             const UnitAppData* uad;
             while((uad = rx.getData(rx.getFirstTimeStamp())))
             {
                 cerr << "got some data: " << uad->getData() << endl;
                 if(*uad->getData() == 'e')
                 {
                     delete uad;
                     return 0;
                 }
                 delete uad;
             }
             Thread::sleep(70);
         }
         return 0;
     }

};

//Sample user call back class

class SampleUserCallback: public zUserCallback

{
    static map<int32, std:string*> infoMap;
    static map<int32, std:string*> warningMap;
    static map<int32, std:string*> FatalMap;
    static map<int32, std:string*> zrtpMap;

    static bool initialized;

    zSymmSession* session;

public:
    SampleUserCallback(zSymmSession* s)
    {
        session = s;
    if(initialized)
    {
        return;
    }

    infoMap.insert(pair<int32, std::string*>(HELLO_RECEIVE_INFO, new string("Hello received, preparing a commit")));
    infoMap.insert(pair<int32, std::string*>(COMMITDH_GEN_INFO, new string("Commit: generated a public DH key")));
    infoMap.insert(pair<int32, std::string*>(RESPCOMMIT_REC_INFO, new string("Responder: commit received, preparing DHPart1")));
    infoMap.insert(pair<int32, std::string*>(DH1DH_GEN_INFO, new string("DH1Part: generated a public DH key")));
    infoMap.insert(pair<int32, std::string*>(INITDH1_REC_INFO, new string("Initiator: DHPart1 received, preparing DHPart2")));
    infoMap.insert(pair<int32, std::string*>(RESPDH2_REC_INFO, new string("Responder: DHPart2 received, preparing Confirm1")));
    infoMap.insert(pair<int32, std::string*>(INITCONF1_REC_INFO, new string("Initiator: Confirm1 received, prepaing confirm2")));
    infoMap.insert(pair<int32, std::string*>(RESPCONF2_REC_INFO, new string("Responder: Confirm2 received, preparing Conf2Ack")));
    infoMap.insert(pair<int32, std::string*>(RSMATCH_FOUND_INFO, new string("At least one retained secrets matches - security OK")));
    infoMap.insert(pair<int32, std::string*>(SECURESTATE_ON_INFO, new string("Entered secure state")));
    infoMap.insert(pair<int32, std::string*>(SECURESTATE_OFF_INFO, new string("No more security for this session")));

    warningMap.insert(pair<int32, std::string*>(DHAES_MISMATCH_WARNING, new string("Commit contains an AES256 cipher but does not offer a Diffie-Hellman 4096")));
    warningMap.insert(pair<int32, std::string*>(GOCLEAR_REC_WARNING, new string("Received a GoClear message")));
    warningMap.insert(pair<int32, std::string*>(DHSHORT_WARNING, new string("Hello offers an AES256 cipher but does not offer a Diffie-hellman 4096")));
    warningMap.insert(pair<int32, std::string*>(NO_RSMATCH_WARNING, new string("No retained secrets matches-verify SAS")));
    warningMap.insert(pair<int32, std::string*>(CRC_MISMATCH_WARNING, new string("Internal ZRTP packet checksum mismatch - packet dropped")));
    warningMap.insert(pair<int32, std::string*>(SRTP_AUTHERROR_WARNING, new string("Dropping packet because SRTP authentication failed!")));
    warningMap.insert(pair<int32, std::string*>(SRTP_REPLAYERROR_WARNING, new string("Dropping packet because SRTP replay check failed!")));

    fatalMap.insert(pair<int32, std::string*>(HELLOHMAC_FAIL_FATAL, new string("Hash HMAC check of Hello failed!")));
    fatalMap.insert(pair<int32, std::string*>(COMMITHMAC_FAIL_FATAL, new string("Hash HMAC check of commit failed!")));
    fatalMap.insert(pair<int32, std::string*>(DH1HMAC_FAIL_FATAL, new string("Hash HMAC check of DHPart1 failed!")));
    fatalMap.insert(pair<int32, std::string*>(DH2HMAC_FAIL_FATAL, new string("Hash HMAC check of DHPart2 failed!")));
    fatalMap.insert(pair<int32, std::string*>(CANNOT_SEND_FATAL, new string("cannot send data - connection or peer down?")));
    fatalMap.insert(pair<int32, std::string*>(PROTOCOL_ERROR_FATAL, new string("Internet protocol error occurred!")));
    fatalMap.insert(pair<int32, std::string*>(NO_TIMER_FATAL, new string("cannot start a timer - internal resource exhausted?")));
    fatalMap.insert(pair<int32, std::string*>(RETRY_SATURATION_FATAL, new string("Too much retries during ZRTP negotiation - connection or peer down?")));

    zrtpMap.insert(pair<int32, std::string*>(MalformedPacket, new string("Malformed packet (CRC OK, but wrong structure)")));
    zrtpMap.insert(pair<int32, std::string*>(CriticalInternalError, new string("Critical software error")));
    zrtpMap.insert(pair<int32, std::string*>(UnsupportedZrtpVersion, new string("Unsupported ZRTP version")));
    zrtpMap.insert(pair<int32, std::string*>(HelloMismatch, new string("Hello components mismatch")));
    zrtpMap.insert(pair<int32, std::string*>(UnsupportedHashType, new string("Hash type not supported")));
    zrtpMap.insert(pair<int32, std::string*>(UnsupportedCipherType, new string("Cipher type not supported")));
    zrtpMap.insert(pair<int32, std::string*>(UnsupportedPublicKeyExchange, new string("Public key exchange not supported")));
    zrtpMap.insert(pair<int32, std::string*>(UnsupportedSRTPAuthTag, new string("SRTP auth tag not supported")));
    zrtpMap.insert(pair<int32, std::string*>(UnsupportedSASRenderScheme, new string("SAS scheme not supported")));
    zrtpMap.insert(pair<int32, std::string*>(UnavailableSharedSecret, new string("DH Error: BadPviOrPvR")));
    zrtpMap.insert(pair<int32, std::string*>(MismatchHviAndHash, new string("DH Error: hvi != hashed data")));
    zrtpMap.insert(pair<int32, std::string*>(RelayedSASFromUntrustedMiTM, new string("Received relayed SAS from untrusted MiTM")));
    zrtpMap.insert(pair<int32, std::string*>(BadConfirmPktMAC, new string("Auth Error Bad Confirm pkt HMAC")));
    zrtpMap.insert(pair<int32, std::string*>(NonceReuse, new string("Nonce reuse")));
    zrtpMap.insert(pair<int32, std::string*>(SameZIDinHello, new string("Equal ZIDs in Hello")));
    zrtpMap.insert(pair<int32, std::string*>(UnallowedGoClear, new string("GoClear packet received, but not allowed")));

    initialized = true;
    }

    void showMessage(zCodes::MsgSeverity sev, int32_t subCode)
    {
        string* msg;
        if(sev == INFO)
        {
            msg = infoMap[subCode];
            if(msg != NULL)
            {
                cout << *msg << endl;
            }
        }
        if(sev == WARNING)
        {
            msg = warningMap[subCode];
            if(msg != NULL)
            {
                cout << *msg << endl;
            }
        }

        if(sev == FATAL)
        {
            msg = fatalMap[subCode];
            if(msg != NULL)
            {
                cout << *msg << endl;
            }
        }

        if(sev == zError)
        {
            if(subCode < 0)
            {
                subCode *= -1;
                cout << "Received error packet:";
            }
            else{
                cout << "Sent error packet:";
            }

            msg = zrtpMap[subCode];
            if(msg != NULL)
            {
                cout << *msg << endl;
            }
        }
    }

    void zNegotiatioFail(zCodes::MsgSeverity sev, int32_t subCode)
    {
        string* msg;
        if(sev == zError)
        {
            if(subCode < 0)
            {
                subCode *= -1;
                cout << "Received error packet:";
            }
            else{
                cout << "Sent Error packet:";
            }
            msg = zrtpMap[subCode];
            if(msg != NULL)
            {
                cout << *msg << endl;
            }
        }
        else
        {
            msg = fatalMap[subCode];
            cout << *msg << endl;
        }
    }

    void SECURE_STATE(std::string cipher)
    {
        cout << "Using cipher:" << cipher << endl;
    }

    void showSAS(std::string sas, bool verified)
    {
        cout << "SAS is: " << sas << endl;
    }
};

map<int32, std::string*>SampleUserCallback::infoMap;
map<int32, std::string*>SampleUserCallback::warningMap;
map<int32, std::string*>SampleUserCallback::fatalMap;
map<int32, std::string*>SampleUserCallback::zrtpMap;

bool SampleUserCallback::initialized = false;

class zPacketSendTransTestCB : public Thread, public TimerPort
{
    public:
        void run()
        {
            Test();
        }

        int Test()
        {
            zSymmSession tx(pattern.getDestAdd(), pattern.getDestPort() + 2);

            tx.initialize("test_t.ZID");
            cout << "TX Hello Hash: " << tx.getHelloHash() << endl;
            cout << "TX Hello hash length: " << tx.getHelloHash().length() << endl;

            tx.setUserCallback(new SampleUserCallback(&tx));

            tx.setSchedulingTimeout(10000);
            tx.setExpireTimeout(1000000);

            tx.startRunning();

            tx.setPauloadFormat(StaticPayloadFormat(sptPCMU));
            if(!tx.addDest(pattern.getDestAdd(), pattern.getDestPort()))
            {
                return i;
            }
            tx.startZrtp();

            uint32 period = 500;
            uint16 inc = tx.getCurrentRTPlockRate()/2;
            TimerPort::setTimer(period);
            uint32 i;
            for(i = 0; i < pattern.getPktNumber(); i++)
            {
                tx.putData(i*inc, pattern.getPktData(i), pattern.getPktSize(i));
                cout << "Sent some data: " << i << endl;
                Thread::sleep(TimerPort::getTimer());
                TimerPort::incTimer(period);
            }
            tx.putData(i*inc, (unsigned char*)"exit", 5);
            Thread::sleep(TimerPort::getTimer());
            return 0;
        }
};

class zPacketReceiveTransTest: public threadLockCleanup{

    public:
        void run()
        {
            Test();
        }

        int Test()
        {
            zSymmSession rx(pattern.getDestAdd(), pattern.getDestPort());

            rx.initialise("test_r.ZID");

            cout << "RX Hello Hash: " << rx.getHelloHash() << endl;
            cout << "RX Hello Hash length: " << rx.getHelloHash().length() << endl;

            rx.setUserCallback(new SampleUserCallback(&rx));

            rx.setSchedulingTimeout(10000);
            rx.setExpireTimeout(1000000);

            rx.startRunning();
            rx.setPayloadFormat(StartPayloadFormat(sptPCMU));

            if(!rx.addDest(pattern.getDestAdd(), pattern.getDestPort() + 2))
            {
                return 1;
            }

            rx.startZrtp();

            for(int i = 0; i < 5000; i++)
            {
                const UnitAppData* uad;
                while((uad = rx.getData(rx.getFirstTimeStamp())))
                {
                    cerr << "got some data: " << uad->getData() << endl;
                    if(*uad->getData() == 'e')
                    {
                        delete uad;
                        return 0;
                    }
                    delete uad;
                }
                Thread::sleep(70);
            }
            return 0;
        }
};

int main(int argc, char *argv[])
{
    int result = 0;
    bool send = false;
    bool receive = false;

    char c;

    while(1)
    {
        c = getopt(argc, argv, "rs");
        if(c == -1)
        {
            break;
        }
        switch (c){
            case 'r':
                receive = true;
                break;
            case 's':
                send = true;
                break;
            default:
                cerr << "Wrong Arguments, only -s and -r are accepted" << endl;
        }
    }

    if(send || receive)
    {
        if(send)
        {
            cout << "Running as sender" << endl;
        }
        else{
            cout << "Running as receiver" << endl;
        }
    }
    else{
        cerr << "No Send or Receive argument specified" << endl;
        exit(1);
    }

    if 0
        PacketSendTransTest *tx;
        PacketReceiveTransTest *rx;

        if(send)
        {
            tx = new PacketSendTransTest();
            tx->start();
            tx->join();
        }
        else if(receive)
        {
            rx = new PacketReceiveTransTest();
            rx->start();
            rx->join();
        }

        zPacketReceiveTransTest *zrx;
        zPacketSendTransTest *ztx;

        if(send)
        {
            ztx = new zPacketSendTransTest();
            ztx->start();
            ztx->join();
        }
        else if(receive)
        {
            zrx = new zPacketReceiveTransTest();
            zrx->start();
            zrx->join();
        }


    zPacketReceiveTransTestCB *zrxcb;
    zPacketSendTransTestCB *ztxcb;

    if(send)
    {
        ztxcb = new zPacketSendTransTestCB();
        ztxcb->start();
        ztxcb->join();
    }
    else if(receive)
    {
        zrxcb = new zPacketReceiveTransTest();
        zrxcb->start();
        zrxcb->join();
    }

    exit(result);
}

*/

































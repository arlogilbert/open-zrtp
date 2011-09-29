#include "../../zRtpEngine.h"
#include "../../zQueue.h"
#include "../../cond.h"
#include "../../UserCallback.h"
#include "../../network.h"

#include <pthread.h>

#include <stdio.h>
#include <string.h>
#include <stdlib.h>

#include <errno.h>
#include <fcntl.h>
#include <cstdlib>
#include <map>
using namespace std;

#define HELLO_PKT "1000b27d5a525450b72a7104505a001d48656c6c6f202020312e313057696e205a666f6e65454320302e39327e3ac60576cd8f535104d0fb869a4ed256533a2d054d497300bdd2861b5a9cc7727d0b5eca31530f42b6bc69000111225332353641455331485333324d756c744448336b4232353642333220b545a8f5b85b894a3163e478"
zQueue queue;
zQueue otherqueue;
Cond send_cond, recv_cond;
Sync send_sync, recv_sync;int running=1;
uint8_t send_buffer[1024], recv_buffer[1024];
uint32_t send_len, recv_len;

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

class SampleUserCallback: public UserCallback

{
    static std::map<int32_t, std::string*> infoMap;
    static std::map<int32_t, std::string*> warningMap;
    static std::map<int32_t, std::string*> fatalMap;
    static std::map<int32_t, std::string*> zrtpMap;

    static bool initialized;



public:
    SampleUserCallback()
    {

    if(initialized)
    {
        return;
    }

    infoMap.insert(std::pair<int32_t, std::string*>(zCodes::InfoHelloReceive, new std::string("Hello received, preparing a commit")));
    infoMap.insert(std::pair<int32_t, std::string*>(zCodes::InfoCommitDHGenerate, new std::string("Commit: generated a public DH key")));
    infoMap.insert(std::pair<int32_t, std::string*>(zCodes::InfoRespCommitReceive, new std::string("Responder: commit received, preparing DHPart1")));
    infoMap.insert(std::pair<int32_t, std::string*>(zCodes::InfoDH1DHGenerate, new std::string("DH1Part: generated a public DH key")));
    infoMap.insert(std::pair<int32_t, std::string*>(zCodes::InfoInitDH1Receive, new std::string("Initiator: DHPart1 received, preparing DHPart2")));
    infoMap.insert(std::pair<int32_t, std::string*>(zCodes::InfoRespDH2Receive, new std::string("Responder: DHPart2 received, preparing Confirm1")));
    infoMap.insert(std::pair<int32_t, std::string*>(zCodes::InfoInitConf1Receive, new std::string("Initiator: Confirm1 received, prepaing confirm2")));
    infoMap.insert(std::pair<int32_t, std::string*>(zCodes::InfoRespConf2Receive, new std::string("Responder: Confirm2 received, preparing Conf2Ack")));
    infoMap.insert(std::pair<int32_t, std::string*>(zCodes::InfoRSMatchFound, new std::string("At least one retained secrets matches - security OK")));
    infoMap.insert(std::pair<int32_t, std::string*>(zCodes::InfoSecureStateOn, new std::string("Entered secure state")));
    infoMap.insert(std::pair<int32_t, std::string*>(zCodes::InfoSecureStateOff, new std::string("No more security for this session")));

    warningMap.insert(std::pair<int32_t, std::string*>(zCodes::WarningDHAESmismatch, new std::string("Commit contains an AES256 cipher but does not offer a Diffie-Hellman 4096")));
    warningMap.insert(std::pair<int32_t, std::string*>(zCodes::WarningGoClear, new std::string("Received a GoClear message")));
    warningMap.insert(std::pair<int32_t, std::string*>(zCodes::WarningDHShort, new std::string("Hello offers an AES256 cipher but does not offer a Diffie-hellman 4096")));
    warningMap.insert(std::pair<int32_t, std::string*>(zCodes::WarningNoRSMatch, new std::string("No retained secrets matches-verify SAS")));
    warningMap.insert(std::pair<int32_t, std::string*>(zCodes::WarningCRCMismatch, new std::string("Internal ZRTP packet checksum mismatch - packet dropped")));
    warningMap.insert(std::pair<int32_t, std::string*>(zCodes::WarningSRTPAuthFail, new std::string("Dropping packet because SRTP authentication failed!")));
    warningMap.insert(std::pair<int32_t, std::string*>(zCodes::WarningSRTPReplayFail, new std::string("Dropping packet because SRTP replay check failed!")));

    fatalMap.insert(std::pair<int32_t, std::string*>(zCodes::FatalHelloHMAC, new std::string("Hash HMAC check of Hello failed!")));
    fatalMap.insert(std::pair<int32_t, std::string*>(zCodes::FatalCommitHMAC, new std::string("Hash HMAC check of commit failed!")));
    fatalMap.insert(std::pair<int32_t, std::string*>(zCodes::FatalDH1HMAC, new std::string("Hash HMAC check of DHPart1 failed!")));
    fatalMap.insert(std::pair<int32_t, std::string*>(zCodes::FatalDH2HMAC, new std::string("Hash HMAC check of DHPart2 failed!")));
    fatalMap.insert(std::pair<int32_t, std::string*>(zCodes::FatalCannotSend, new std::string("cannot send data - connection or peer down?")));
    fatalMap.insert(std::pair<int32_t, std::string*>(zCodes::FatalProtocolError, new std::string("Internet protocol error occurred!")));
    fatalMap.insert(std::pair<int32_t, std::string*>(zCodes::FatalNoTimer, new std::string("cannot start a timer - internal resource exhausted?")));
    fatalMap.insert(std::pair<int32_t, std::string*>(zCodes::FatalRetrySaturation, new std::string("Too much retries during ZRTP negotiation - connection or peer down?")));

    zrtpMap.insert(std::pair<int32_t, std::string*>(zCodes::MalformedPacket, new std::string("Malformed packet (CRC OK, but wrong structure)")));
    zrtpMap.insert(std::pair<int32_t, std::string*>(zCodes::CriticalSoftwareError, new std::string("Critical software error")));
    zrtpMap.insert(std::pair<int32_t, std::string*>(zCodes::UnsupportedZrtpVersion, new std::string("Unsupported ZRTP version")));
    zrtpMap.insert(std::pair<int32_t, std::string*>(zCodes::HelloComponentsMismatch, new std::string("Hello components mismatch")));
    zrtpMap.insert(std::pair<int32_t, std::string*>(zCodes::UnsupportedHashType, new std::string("Hash type not supported")));
    zrtpMap.insert(std::pair<int32_t, std::string*>(zCodes::UnsupportedCipherType, new std::string("Cipher type not supported")));
    zrtpMap.insert(std::pair<int32_t, std::string*>(zCodes::UnsupportedPublicKeyExchange, new std::string("Public key exchange not supported")));
    zrtpMap.insert(std::pair<int32_t, std::string*>(zCodes::UnsupportedSRTPAuthTag, new std::string("SRTP auth tag not supported")));
    zrtpMap.insert(std::pair<int32_t, std::string*>(zCodes::UnsupportedSASRenderScheme, new std::string("SAS scheme not supported")));
    zrtpMap.insert(std::pair<int32_t, std::string*>(zCodes::UnavailableSharedSecret, new std::string("DH Error: BadPviOrPvR")));
    zrtpMap.insert(std::pair<int32_t, std::string*>(zCodes::MismatchHviAndHash, new std::string("DH Error: hvi != hashed data")));
    zrtpMap.insert(std::pair<int32_t, std::string*>(zCodes::RelayedSASFromUntrustedMiTM, new std::string("Received relayed SAS from untrusted MiTM")));
    zrtpMap.insert(std::pair<int32_t, std::string*>(zCodes::BadConfirmPktMAC, new std::string("Auth Error Bad Confirm pkt HMAC")));
    zrtpMap.insert(std::pair<int32_t, std::string*>(zCodes::NonceReuse, new std::string("Nonce reuse")));
    zrtpMap.insert(std::pair<int32_t, std::string*>(zCodes::EqualZidsInHello, new std::string("Equal ZIDs in Hello")));
    zrtpMap.insert(std::pair<int32_t, std::string*>(zCodes::UnallowedGoClearMessage, new std::string("GoClear packet received, but not allowed")));

    initialized = true;
    }

    void showMessage(zCodes::ZRTPMessageLevel sev, int32_t subCode)
    {
        std::string* msg;
        if(sev == zCodes::MsgLevelInfo)
        {
            msg = infoMap[subCode];
            if(msg != NULL)
            {
                std::cout << *msg << std::endl;
            }
        }
        if(sev == zCodes::MsgLevelWarning)
        {
            msg = warningMap[subCode];
            if(msg != NULL)
            {
                std::cout << *msg << std::endl;
            }
        }

        if(sev == zCodes::MsgLevelFatal)
        {
            msg = fatalMap[subCode];
            if(msg != NULL)
            {
                std::cout << *msg << std::endl;
            }
        }

        if(sev == zCodes::MsgLevelZrtpError)
        {
            if(subCode < 0)
            {
                subCode *= -1;
                std::cout << "Received error packet:";
            }
            else{
                std::cout << "Sent error packet:";
            }

            msg = zrtpMap[subCode];
            if(msg != NULL)
            {
                std::cout << *msg << std::endl;
            }
        }
    }

    void zNegotiatioFail(zCodes::ZRTPMessageLevel sev, int32_t subCode)
    {
        string* msg;
		if(sev == zCodes::MsgLevelZrtpError)
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

std::map<int32_t, std::string*>SampleUserCallback::infoMap;
std::map<int32_t, std::string*>SampleUserCallback::warningMap;
std::map<int32_t, std::string*>SampleUserCallback::fatalMap;
std::map<int32_t, std::string*>SampleUserCallback::zrtpMap;

bool SampleUserCallback::initialized = false;


void print_char_array(uint8_t* buf,int len)
{
    int i=0;
    printf("\n---------------------------------------\n");
    for(;i<len;i++)
    {
        if(len%24 ==0) printf("\n");
        printf("%x",buf[i]);

    }
    printf("\n");
    for(i=0;i<len;i++)
    {
        if(len%24 ==0) printf("\n");
        printf("%c",buf[i]);

    }
    printf("\n---------------------------------------\n");
}
void dispatch(uint8_t* buffer, uint32_t len)
{

    printf("\n ---> buffer length %d",len);
    print_char_array(buffer,len);
    memcpy(send_buffer, buffer,len);
    //send_buffer = buffer;
    send_len = len;
    send_cond.Signal();
}

void inform_recv_data()
{
    printf("\n <--- Received data len = %d",recv_len);
    print_char_array(recv_buffer, recv_len);
    queue.setNextDataPacket(recv_buffer,recv_len);
    queue.TakeDataPacket();
}

void* recv_run(void* nothing)
{
    int sock = *((int*)nothing);

    while(running)
    {
        //printf("\n blokced on recv packet");
        int rc = recv_cond.Wait(2000);
        if(running)
        {
            int flag = -1;//recv_len =0;

            recv_len = recv(sock, (char*)recv_buffer,1024,0);
            flag = recv_len;

            if(flag!=-1)inform_recv_data();
        }
        //sleep(1);
    }
	return 0;
}

#define SND_BUF 64000

void* run_sender(void* nothing)
{
    int sock = -1, bytes_received = 0;
	struct timeval tv = {0, 0};
    int send_buffer_size = SND_BUF;
    char send_data[1024], recv_data[1024];
    struct hostent *host;
    struct sockaddr_in server_addr;
    int flag=1;
    int nFlag = 0;
    pthread_t recv_thread;

	memset(send_data, 0, 1024);
	memset(recv_data, 0, 1024);
    host = gethostbyname("127.0.0.1");

    if((sock = socket(AF_INET, SOCK_STREAM, 0)) == -1)
    {
        perror("Socket");
        exit(1);
    }

    server_addr.sin_family = AF_INET;
    server_addr.sin_port = htons(5000);
    server_addr.sin_addr = *((struct in_addr *)host->h_addr);
	memset(&(server_addr.sin_zero), 0, 8);

    if(setsockopt(sock, SOL_SOCKET, SO_SNDBUF,(char*)&send_buffer_size, sizeof(send_buffer_size))==-1)
    {
        perror("setsockopt snd_buf");
        exit(1);
    }

    if(setsockopt(sock, IPPROTO_TCP, TCP_NODELAY, (char*)&flag, sizeof(flag))==-1)
    {
        perror("setsockopt nagle ");
        exit(1);
    }



#ifdef _WIN32
	/* */
#else
	tv.tv_sec = 5;
	tv.tv_usec = 0;
	if(setsockopt(sock, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof(tv))==-1)
	{
		perror("setsockopt send timeout ");
		exit(1);
	}
#endif

    if(connect(sock, (struct sockaddr *)&server_addr, sizeof(struct sockaddr)) == -1)
    {
        perror("Connect");
        exit(1);
    }

#ifdef _WIN32
	u_long iMode = 1;
	if (ioctlsocket(sock, FIONBIO, &iMode) != NO_ERROR)
	{
		perror("ioctlsocket FIONBIO failed");
		exit(1);
	}
#else
	nFlag = fcntl(sock, F_GETFL,0);
	nFlag |= O_NONBLOCK;

	if(fcntl(sock, F_SETFL, nFlag)==-1)
	{
		perror("fcntl");
		exit(1);
	}
#endif

    pthread_create(&recv_thread, NULL, recv_run, &sock);
    while(running)
    {
        printf("\n waiting for packet send sigal");
        int rc = send_cond.Wait(3600000);

        if(rc == ETIMEDOUT||send_len <= 0 ) continue;

        //printf("\n sending packet size = %d",send_len);
        //if(running) rc=send(sock, send_buffer, send_len, 0);
        if(running)
        {
			#ifdef _WIN32
			rc = send(sock, (const char*)send_buffer, send_len, 0);
			#else
			rc = write(sock,send_buffer, send_len);
			#endif

			doSleep(3);
        }
        if(rc == -1) perror("sent problem");

        recv_cond.Signal();
        /*printf("\n blokced on recv packet");
        if(running)
        recv_len = recv(sock,recv_buffer,1024,0);

        printf("\n informing packet received");
        if(running)
        inform_recv_data();*/

    }
    pthread_join(recv_thread, NULL);

	#ifdef _WIN32
	  closesocket(sock);
	#else
	  close(sock);
	#endif

	return 0;
}


void test_main()
{

    pthread_t thread;
    AVPQueue::dispatch_cb = (void*)&dispatch;
    //zMain main((unsigned char*)"123456789123",&queue,"1111222233334444");
    pthread_create(&thread, NULL, run_sender, NULL);
    doSleep(1);

    queue.setClientID("1234567887654321");
    queue.setUserCallback(new SampleUserCallback());
    queue.initialize("zrtp.zid",true);

    queue.StartZRTP();


    doSleep(3000);
    running = 0;
    send_cond.Signal();
    recv_cond.Signal();
    pthread_join(thread, NULL);
    pthread_exit(&thread);
    //otherqueue.initialize("otherzrtp.zid",true);
    //otherqueue.StartZRTP();
    //sleep(10);
    //queue.
}

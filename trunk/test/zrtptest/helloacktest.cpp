#include "../../zHelloAck.h"

void test_helloack()
{
    zHelloAck ack;
    printf("\n Hell Ack Length %d",ack.GetLength());
    printf("\n Hell Ack Message Type %s",ack.GetMsgType());
    printf("\n Hell Ack Header %s",ack.GetHeaderBase());

}

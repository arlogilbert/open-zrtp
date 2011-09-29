#include "../../zHello.h"

void test_hello()
{
    zHello hello;

    printf("\n hello getVersion %s",hello.GetVersion());
    printf("\n hello getHMAC %s",hello.GetHMAC());
    printf("\n hello getClientId %s",hello.GetClientID());
    printf("\n hello getH3 %s",hello.GetH3());
    printf("\n hello getZID %s",hello.GetZID());
    printf("\n hello isPassive %d",hello.IsPassive());
    printf("\n hello getNumAuth() %d",hello.GetNumAuth());
    printf("\n hello getNumCiphers %d",hello.GetNumCiphers());
    printf("\n hello getNumHashes %d",hello.GetNumHashes());
    printf("\n hello getNumSas %d",hello.GetNumSAS());
    printf("\n hello getNumPubKeys %d",hello.GetNumPubKeys());
}

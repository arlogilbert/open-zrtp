#include "../../zEndpointInfo.h"

#define FILENAME "zrtp.zid"

void test_endpointinfo()
{
    zEndpointInfo* endpoint = zEndpointInfo::Instance();
    const unsigned char* identifier = (const unsigned char*)"123456789123";
    zRecord rec(identifier);

    if(endpoint->IsOpen())
        printf("\n Endpoint info is Open");
    else
        printf("\n Endpoint info is not Open");

    if(!endpoint->IsOpen())
    {
        int status = endpoint->Open(FILENAME);
        printf("\n Endpoint info Open : status =%d",status);
    }

    if(endpoint->IsOpen())
        printf("\n Endpoint info is Open");
    else
        printf("\n Endpoint info is not Open");


    //to do test

    rec.SetNewRs1Value((const unsigned char*)"434324355544354355",3324243L);
    rec.SetNewRs1Value((const unsigned char*)"434324355544354356",3324243L);
    rec.SetRs1Valid();
    rec.SetRs2Valid();

    endpoint->SaveRecord(&rec);
    endpoint->GetRecord(&rec);

    printf("\nzRecord is OWN ZID %d",rec.IsOwnZIDRecord());
    printf("\nzRecord is Rs1 %s",rec.GetRs1());
    printf("\nzRecord is Rs2 %s",rec.GetRs2());
    //unsigned int getRecord(zRecord *zidRec);

    //Save ZID record into an open Endpoint file

    //unsigned int saveRecord(zRecord *zidRec);

    //Get the ZID associated with this Endpoint info file

    /*const unsigned char* getZID()
    {
        return ZID_ASSOCIATED;
    };
    */
    if(endpoint->IsOpen()) endpoint->Close();


}

void test_zrecord()
{
    const unsigned char* identifier = (const unsigned char*)"123456789123";
    zRecord rec(identifier);

    printf("test_zrecord");
    rec.SetMITMData((const unsigned char*)"mitmdata");
    rec.SetMITMKeyAvail();
    printf("\nzRecord identifier %s",rec.GetIdentfr());
    printf("\nzRecord MITM %s",rec.GetMITMData());
    printf("\nzRecord MITM key available %d",rec.IsMITMKeyAvail());
    printf("\nzRecord is OWN ZID %d",rec.IsOwnZIDRecord());

    rec.SetOwnZIDRecord();
    printf("\nzRecord is OWN ZID %d",rec.IsOwnZIDRecord());
    printf("\nzRecord is Rs1 %s",rec.GetRs1());
    printf("\nzRecord is Rs2 %s",rec.GetRs2());

    rec.SetNewRs1Value((const unsigned char*)"434324355544354355",3324243L);
    rec.SetNewRs1Value((const unsigned char*)"434324355544354356",3324243L);
    rec.SetRs1Valid();
    rec.SetRs2Valid();
    printf("\nzRecord is Rs1 %s",rec.GetRs1());
    printf("\nzRecord is Rs2 %s",rec.GetRs2());
    printf("\nzRecord is Rs1 Expired %d",rec.IsRs1NotExpired());
    printf("\nzRecord is Rs2 Expired %d",rec.IsRs2NotExpired());
    printf("\nzRecord is Rs1 Valid %d",rec.IsRs1Valid());
    printf("\nzRecord is Rs2 Valid %d",rec.IsRs2Valid());
    //printf("zRecord
}

int main4(int argc, char* argv[])
{
    //test_zrecord();
    //test_endpointinfo();
    //test_hello();
    return 0;
}

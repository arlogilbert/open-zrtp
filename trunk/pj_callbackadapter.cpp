/*

Copyright 2010-2011 iCall, Inc.

This file is part of Open ZRTP.

Open ZRTP is free software: you can redistribute it and/or modify it under the terms of the GNU Lesser General Public License as published bythe Free Software Foundation, either version 3 of the License, or(at your option) any later version.

Open ZRTP is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU Lesser General Public License for more details.

You should have received a copy of the GNU Lesser General Public Licensealong with Open ZRTP. If not, see http://www.gnu.org/licenses/.

*/


#include <stdio.h>
#include <string.h>
#include "pj_callbackadapter.h"

pj_CallbackAdapter::pj_CallbackAdapter (
	zrtp_Callbacks* cb,
	zZrtpAdapterCtx* ctx)
 : c_callbacks(cb)
 , zrtpCtx(ctx)
{
	init();
}

void pj_CallbackAdapter::init()
{
}

int32_t pj_CallbackAdapter::SendPacketThroughRTP (
	const unsigned char* data,
	int32_t length )
{
	return c_callbacks->SendDataZRTP(zrtpCtx, data, length);
}

int32_t pj_CallbackAdapter::TimerActive(int32_t time)
{
	c_callbacks->ActivateTimer(zrtpCtx, time);
	return 1;
}

int32_t pj_CallbackAdapter::TimerCancel()
{
	c_callbacks->CancelTimer(zrtpCtx);
	return 0;
}

void pj_CallbackAdapter::SendInformationToTheHost (zCodes::ZRTPMessageLevel severity, int32_t subCode)
{
	c_callbacks->SendInfo(zrtpCtx, (int32_t)severity, subCode);
}

bool pj_CallbackAdapter::SecretsReady(SRTPSecrets_t* secrets, EnableSecurity part)
{
	c_srtp_secrets_t* cs = new c_srtp_secrets_t;
	cs->initKeyLen = secrets->initKeyLen;
	cs->initSaltLen = secrets->initSaltLen;
	cs->keyInit = secrets->keyInit;
	cs->keyResp = secrets->keyResp;
	cs->respKeyLen = secrets->respKeyLen;
	cs->respSaltLen = secrets->respSaltLen;
	cs->role = (int32_t)secrets->role;
	cs->saltInit = secrets->saltInit;
	cs->saltResp = secrets->saltResp;
	cs->sas = new char [secrets->sas.size()+1];
	strcpy(cs->sas, secrets->sas.c_str());
	cs->srtpAuthTagLen = secrets->srtpAuthTagLen;

	bool retval = (c_callbacks->SrtpSecretsReady(zrtpCtx, cs, (int32_t)part) == 0) ? false : true ;

	delete cs->sas;
	delete cs;

	return retval;
}

void pj_CallbackAdapter::SecretsOff (EnableSecurity part )
{
	c_callbacks->SrtpSecretsOff(zrtpCtx, (int32_t)part);
}

void pj_CallbackAdapter::SecretsOn ( std::string c, std::string s, bool verified )
{
	char* cc = new char [c.size()+1];
	char* cs = new char [s.size()+1];

	strcpy(cc, c.c_str());
	if(!s.empty())
		strcpy(cs, s.c_str());
	else
		*cs = '\0';

	c_callbacks->RtpSecretsOn(zrtpCtx, cc, cs, verified?1:0);

	delete[] cc;
	delete[] cs;
}

void pj_CallbackAdapter::HandleGoClear()
{
}

void pj_CallbackAdapter::HandleNegotiationFail(zCodes::ZRTPMessageLevel severity, int32_t subCode)
{
	c_callbacks->NegotiationFailed(zrtpCtx, (int32_t)severity, subCode);
}

void pj_CallbackAdapter::HandleNoSupportOther()
{
	c_callbacks->NotSuppOther(zrtpCtx);
}

void pj_CallbackAdapter::EnterSynch()
{
	c_callbacks->SynchEnter(zrtpCtx);
}

void pj_CallbackAdapter::LeaveSynch()
{
	c_callbacks->SynchLeave(zrtpCtx);
}

void pj_CallbackAdapter::InformAboutPBXEnrollRequest(std::string info)
{
	char* cc = new char [info.size()+1];

	strcpy(cc, info.c_str());
	c_callbacks->AskEnrollment(zrtpCtx, cc);

	delete[] cc;
}

void pj_CallbackAdapter::InformAboutPBXEnrollResult(std::string info)
{
	char* cc = new char [info.size()+1];

	strcpy(cc, info.c_str());
	c_callbacks->InformEnrollment(zrtpCtx, cc);

	delete[] cc;
}

void pj_CallbackAdapter::RequestSASSignature(std::string sas)
{
	char* cc = new char [sas.size()+1];

	strcpy(cc, sas.c_str());
	c_callbacks->SignSAS(zrtpCtx, cc);

	delete[] cc;
}

bool pj_CallbackAdapter::CheckSASSignature(std::string sas )
{
	char* cc = new char [sas.size()+1];

	strcpy(cc, sas.c_str());
	bool retval = (c_callbacks->CheckSASSignature(zrtpCtx, cc) == 0) ? false : true;

	delete[] cc;

	return retval;
}

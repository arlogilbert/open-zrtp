/*

Copyright 2010-2011 iCall, Inc.

This file is part of Open ZRTP.

Open ZRTP is free software: you can redistribute it and/or modify it under the terms of the GNU Lesser General Public License as published bythe Free Software Foundation, either version 3 of the License, or(at your option) any later version.

Open ZRTP is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU Lesser General Public License for more details.

You should have received a copy of the GNU Lesser General Public Licensealong with Open ZRTP. If not, see http://www.gnu.org/licenses/.

*/

#ifndef __pj_callbackadapter_h__
#define __pj_callbackadapter_h__

#include "zCallback.h"
#include "pj_zrtpadapter.h"

struct pj_CallbackAdapter : public zCallback
{
public:
	pj_CallbackAdapter(zrtp_Callbacks* cb, zZrtpAdapterCtx* ctx);

	int32_t SendPacketThroughRTP(const unsigned char* data, int32_t length);
	int32_t TimerActive(int32_t time);
	int32_t TimerCancel();
	void SendInformationToTheHost(zCodes::ZRTPMessageLevel severity, int32_t subCode);
	bool SecretsReady(SRTPSecrets_t* secrets, EnableSecurity part);
	void SecretsOff(EnableSecurity part);
	void SecretsOn(std::string c, std::string s, bool verified);
	void HandleGoClear();
	void HandleNegotiationFail(zCodes::ZRTPMessageLevel severity, int32_t subCode);
	void HandleNoSupportOther();
	void EnterSynch();
	void LeaveSynch();
	void InformAboutPBXEnrollRequest(std::string info);
	void InformAboutPBXEnrollResult(std::string info);
	void RequestSASSignature(std::string sas);
	bool CheckSASSignature(std::string sas);

private:
	void init();
	zrtp_Callbacks *c_callbacks;
	zZrtpAdapterCtx* zrtpCtx;
};

#endif // __pj_callbackadapter_h__
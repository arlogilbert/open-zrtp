/*

Copyright 2010-2011 iCall, Inc.

This file is part of Open ZRTP.

Open ZRTP is free software: you can redistribute it and/or modify it under the terms of the GNU Lesser General Public License as published bythe Free Software Foundation, either version 3 of the License, or(at your option) any later version.

Open ZRTP is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU Lesser General Public License for more details.

You should have received a copy of the GNU Lesser General Public Licensealong with Open ZRTP. If not, see http://www.gnu.org/licenses/.

*/


#ifndef __zCallback_h__
#define __zCallback_h__

#include <string>
#include "int.h"
#include "zCodes.h"
#include "sRtpSecrets.h"

class zCallback
{
	friend struct zRtpEngine;

public:
	virtual ~zCallback(){};

	virtual int32_t SendPacketThroughRTP(const uint8_t* data, int32_t length) = 0;
	virtual int32_t TimerActive(int32_t time) = 0;
	virtual int32_t TimerCancel() = 0;
	virtual void SendInformationToTheHost(zCodes::ZRTPMessageLevel severity, int32_t subCode) = 0;
	virtual bool SecretsReady(SRTPSecrets_t* secrets, EnableSecurity part) = 0;
	virtual void SecretsOff(EnableSecurity part) = 0;
	virtual void SecretsOn(std::string c, std::string s, bool verified) = 0;
	virtual void HandleGoClear() = 0;
	virtual void HandleNegotiationFail(zCodes::ZRTPMessageLevel severity, int32_t subCode) = 0;
	virtual void HandleNoSupportOther() = 0;
	virtual void EnterSynch() = 0;
	virtual void LeaveSynch() = 0;
	virtual void InformAboutPBXEnrollRequest(std::string info) = 0;
	virtual void InformAboutPBXEnrollResult(std::string info) = 0;
	virtual void RequestSASSignature(std::string sas) = 0;
	virtual bool CheckSASSignature(std::string sas) = 0;
};

#endif // __zCallback_h__

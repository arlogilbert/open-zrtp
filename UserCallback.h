/*

Copyright 2010-2011 iCall, Inc.

This file is part of Open ZRTP.

Open ZRTP is free software: you can redistribute it and/or modify it under the terms of the GNU Lesser General Public License as published bythe Free Software Foundation, either version 3 of the License, or(at your option) any later version.

Open ZRTP is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU Lesser General Public License for more details.

You should have received a copy of the GNU Lesser General Public Licensealong with Open ZRTP. If not, see http://www.gnu.org/licenses/.

*/

#ifndef _USERCALLBACK_H_
#define _USERCALLBACK_H_

#include "int.h"

#include <string.h>
#include "zCodes.h"


class UserCallback
{
	public:
		UserCallback() {}

		virtual ~UserCallback() {};

	//When the sender and receiver both are in secure mode
	virtual void SecureOn(std::string cipher)
	{
		return;
	}

	//Infrom UI that Security is not on
	virtual void SecureOff()
	{
		return;
	}

	// Show SAS on UI
	virtual void ShowSAS(std::string sas, bool verified)
	{
		return;
	}

	//ZRTP received "GO CLEAR" message from its peer
	virtual void ConfirmGoClear()
	{
		return;
	}

	// Show some information to the user via UI
	virtual void ShowMsg(zCodes::ZRTPMessageLevel sev, int32_t subCode)
	{
		return;
	}

	//When negotiation fails
	virtual void zNegotiationFail(zCodes::ZRTPMessageLevel severity, int32_t subCode)
	{
		return;
	}

	// ZRTPQueue calls this method when other endpoint does not support ZRTP
	virtual void zNoSupportOther()
	{
		return;
	}

	//ZRTP queue call this to inform about PBX enrollment request
	virtual void zAskEnroll(std::string info)
	{
		return;
	}

	//Enrollment result
	virtual void zInfoEnroll(std::string info)
	{
		return;
	}

	// ZRTP queue requests a SAS signature
	virtual void signSAS(std::string sas)
	{
		return;
	}

	//ZRTP Queue requests a SAS signature check
	virtual bool checkSASSignature(std::string sas)
	{
		return true;
	}

};

#endif



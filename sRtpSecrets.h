/*

Copyright 2010-2011 iCall, Inc.

This file is part of Open ZRTP.

Open ZRTP is free software: you can redistribute it and/or modify it under the terms of the GNU Lesser General Public License as published bythe Free Software Foundation, either version 3 of the License, or(at your option) any later version.

Open ZRTP is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU Lesser General Public License for more details.

You should have received a copy of the GNU Lesser General Public Licensealong with Open ZRTP. If not, see http://www.gnu.org/licenses/.

*/

#ifndef __sRtpSecrets_h__
#define __sRtpSecrets_h__

typedef enum
{
	Responder = 1,
	Initiator
} Role;

typedef enum
{
	ForReceiver =	1,
	ForSender =		2
} EnableSecurity;

typedef struct SRTPSecrets
{
	const uint8_t* keyInit;
	int32_t initKeyLen;
	const uint8_t* saltInit;
	int32_t initSaltLen;
	const uint8_t* keyResp;
	int32_t respKeyLen;
	const uint8_t* saltResp;
	int32_t respSaltLen;
	int32_t srtpAuthTagLen;
	std::string sas;
	Role  role;
} SRTPSecrets_t;

#endif // __sRtpSecrets_h__
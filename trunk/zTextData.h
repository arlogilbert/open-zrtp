/*

Copyright 2010-2011 iCall, Inc.

This file is part of Open ZRTP.

Open ZRTP is free software: you can redistribute it and/or modify it under the terms of the GNU Lesser General Public License as published bythe Free Software Foundation, either version 3 of the License, or(at your option) any later version.

Open ZRTP is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU Lesser General Public License for more details.

You should have received a copy of the GNU Lesser General Public Licensealong with Open ZRTP. If not, see http://www.gnu.org/licenses/.

*/


#ifndef __zTextData_h__
#define __zTextData_h__

#include "int.h"

extern const char* ZID;
extern const char* zrtpVersion;
extern const char* clientID;
extern const char* HelloMsg;
extern const char* HelloAckMsg;
extern const char* DHPart1Msg;
extern const char* DHPart2Msg;
extern const char* CommitMsg;
extern const char* Confirm1Msg;
extern const char* Confirm2Msg;
extern const char* Conf2AckMsg;
extern const char* ErrorMsg;
extern const char* ErrorAckMsg;
extern const char* PingMsg;
extern const char* PingAckMsg;
extern const char* GoClearMsg;
extern const char* ClearAckMsg;

extern const char* initiator;
extern const char* responder;
extern const char* iniMasterKey;
extern const char* iniMasterSalt;
extern const char* resMasterKey;
extern const char* resMasterSalt;
extern const char* iniHmacKey;
extern const char* resHmacKey;
extern const char* retainedSec;

extern const char* iniZrtpKey;
extern const char* resZrtpKey;

extern const char* sasString;

extern const char* KDFString;
extern const char* zrtpSessKey;
extern const char* zrtpMsk;

#endif // __zTextData_h__




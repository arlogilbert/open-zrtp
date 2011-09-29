/*

Copyright 2010-2011 iCall, Inc.

This file is part of Open ZRTP.

Open ZRTP is free software: you can redistribute it and/or modify it under the terms of the GNU Lesser General Public License as published bythe Free Software Foundation, either version 3 of the License, or(at your option) any later version.

Open ZRTP is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU Lesser General Public License for more details.

You should have received a copy of the GNU Lesser General Public Licensealong with Open ZRTP. If not, see http://www.gnu.org/licenses/.

*/


#include <stdio.h>
#include "zTextData.h"

// Words:					  1   2   3   4   5   6   7   8
//							 ---+---+---+---+---+---+---+---+

const char *ZID =			"ZRTP 1.0";
const char *zrtpVersion =	"1.10";
const char *clientID =		"ICAll ZRTP 1.0  ";

//							 ---+---+---+---+---+---+---+---+

const char* HelloMsg =		"Hello   ";
const char* HelloAckMsg =	"HelloACK";
const char* DHPart1Msg =	"DHPart1 ";
const char* DHPart2Msg =	"DHPart2 ";
const char* CommitMsg =		"Commit  ";
const char* Confirm1Msg =	"Confirm1";
const char* Confirm2Msg =	"Confirm2";
const char* Conf2AckMsg =	"Conf2ACK";
const char* ErrorMsg =		"Error   ";
const char* ErrorAckMsg =	"ErrorACK";
const char* GoClearMsg =	"GoClear ";
const char* ClearAckMsg =	"ClearACK";
const char* PingMsg =		"Ping	   ";
const char* PingAckMsg =	"PingACK ";

//							 ---+---+---+---+---+---+---+---+

const char* initiator =		"Initiator";
const char* responder =		"Responder";
const char* iniMasterKey =	"Initiator SRTP master Key";
const char* iniMasterSalt =	"Initiator SRTP master salt";
const char* resMasterKey =	"Responder SRTP master Key";
const char* resMasterSalt =	"Responder SRTP master Salt";

//							 ---+---+---+---+---+---+---+---+

const char* iniHmacKey =	"Initiator HMAC key";
const char* resHmacKey =	"Responder HMAC key";
const char* retainedSec =	"retained secret";
const char* iniZrtpKey =	"Initiator ZRTP key";
const char* resZrtpKey =	"Responder ZRTP key";

//							 ---+---+---+---+---+---+---+---+

const char* sasString =		"SAS";
const char* KDFString =		"ZRTP-HMAC-KDF";
const char* zrtpSessKey =	"ZRTP Session Key";
const char* zrtpMsk =		"ZRTP MSK";

//							 ---+---+---+---+---+---+---+---+

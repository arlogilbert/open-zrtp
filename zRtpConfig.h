/*

Copyright 2010-2011 iCall, Inc.

This file is part of Open ZRTP.

Open ZRTP is free software: you can redistribute it and/or modify it under the terms of the GNU Lesser General Public License as published bythe Free Software Foundation, either version 3 of the License, or(at your option) any later version.

Open ZRTP is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU Lesser General Public License for more details.

You should have received a copy of the GNU Lesser General Public Licensealong with Open ZRTP. If not, see http://www.gnu.org/licenses/.

*/


#ifndef __zRtpConfig_h__
#define __zRtpConfig_h__

#define USEPJPROJECTLOGGER

#define ZRTP_PACKET_ID				0x505A
#define ZRTP_MAGIC					0x5A525450

#define ZRTP_WORD_SIZE				4

#define CRC_SIZE					(ZRTP_WORD_SIZE * 1)

#define ZRECORD_TIMEINTERVAL_LENGTH	(ZRTP_WORD_SIZE * 2)
#define ZID_LENGTH					(ZRTP_WORD_SIZE * 3)
#define ZRECORD_IDENTIFIER_LENGTH	(ZRTP_WORD_SIZE * 3)
#define SRTP_BLOCK_SIZE				(ZRTP_WORD_SIZE * 4)
#define ZRECORD_RS_LENGTH			(ZRTP_WORD_SIZE * 8)
#define RANDOM_INITIAL_VECTOR_LEN	(ZRTP_WORD_SIZE * 4)

#define REPLAY_WINDOW_SIZE			(ZRTP_WORD_SIZE * 16)
#define ZDHPART_DATA_SIZE			(ZRTP_WORD_SIZE * 192)
#define MAX_ZRTP_SIZE				(ZRTP_WORD_SIZE * 768)
#define MAX_RTP_BUFFER_LEN			(ZRTP_WORD_SIZE * 256)

#define TYPE_SIZE					(ZRTP_WORD_SIZE * 2)
#define HMAC_SIZE					(ZRTP_WORD_SIZE * 2)
#define ID_SIZE			 			(ZRTP_WORD_SIZE * 2)
#define PING_HASH_SIZE	 			(ZRTP_WORD_SIZE * 2)

#define ZID_SIZE		 			(ZRTP_WORD_SIZE * 3)

#define CLIENT_ID_SIZE	 			(ZRTP_WORD_SIZE * 4)
#define IV_SIZE			 			(ZRTP_WORD_SIZE * 4)

#define HASH_IMAGE_SIZE	 			(ZRTP_WORD_SIZE * 8)
#define HVI_SIZE		 			(ZRTP_WORD_SIZE * 8)

typedef enum SrtpAuthentication
{
	SrtpAuthenticationNull		= 0,
	SrtpAuthenticationSha1Hmac	= 1,
} SrtpAuthentication_t;

typedef enum SrtpEncryption
{
	SrtpEncryptionNull	= 0,
	SrtpEncryptionAESCM = 1,
	SrtpEncryptionAESF8 = 2,
} SrtpEncryption_t;

#	ifdef _DEBUG
#		ifdef USEPJPROJECTLOGGER
#			include <pj/log.h>
#			define DBGLOGLINE(line) PJ_LOG(3,("zrtplib", line))
#			define DBGLOGLINEFORMAT1(format, arg) PJ_LOG(3,("zrtplib", format, arg))
#		else
#			include "stdio.h"
#			define DBGLOGLINE(line) printf(line "\n")
#			define DBGLOGLINEFORMAT1(format, arg) printf(format "\n", arg)
#		endif // USEPJPROJECTLOGGER
#	else
#		define DBGLOGLINE(line)
#		define DBGLOGLINEFORMAT1(format, arg)
#	endif // _DEBUG

#endif // __zRtpConfig_h__

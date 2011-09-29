/*

Copyright 2010-2011 iCall, Inc.

This file is part of Open ZRTP.

Open ZRTP is free software: you can redistribute it and/or modify it under the terms of the GNU Lesser General Public License as published bythe Free Software Foundation, either version 3 of the License, or(at your option) any later version.

Open ZRTP is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU Lesser General Public License for more details.

You should have received a copy of the GNU Lesser General Public Licensealong with Open ZRTP. If not, see http://www.gnu.org/licenses/.

*/


#ifndef __zPingAck_h__
#define __zPingAck_h__

#include "zPacketBase.h"

struct ZRTPPingAckPacketHeader 
{
	uint8_t	version	[ZRTP_WORD_SIZE];
	uint8_t	localEpHash	[PING_HASH_SIZE];
	uint8_t	remoteEpHash [PING_HASH_SIZE];
	uint32_t ssrc;
};

struct ZRTPPingAckPacket
{
	ZRTPPacketHeader zrtpHeader;
	ZRTPPingAckPacketHeader pingAckHeader;
	uint8_t crc[ZRTP_WORD_SIZE];
};

class zPingAck : public zPacketBase
{
public:
	zPingAck();
	virtual ~zPingAck();
	zPingAck(uint8_t* data);

	uint32_t GetSSRC();
	void SetVersion(uint8_t *text);
	void SetSSRC(uint32_t data);
	void SetRemoteEpHash(uint8_t *hash);
	void SetLocalEpHash(uint8_t *hash);

protected:
	ZRTPPingAckPacketHeader* _PingAckHdr;

private:
	ZRTPPingAckPacket _data;
};

#endif // __zPingAck_h__

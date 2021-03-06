/*

Copyright 2010-2011 iCall, Inc.

This file is part of Open ZRTP.

Open ZRTP is free software: you can redistribute it and/or modify it under the terms of the GNU Lesser General Public License as published bythe Free Software Foundation, either version 3 of the License, or(at your option) any later version.

Open ZRTP is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU Lesser General Public License for more details.

You should have received a copy of the GNU Lesser General Public Licensealong with Open ZRTP. If not, see http://www.gnu.org/licenses/.

*/


#ifndef __zPing_h__
#define __zPing_h__

#include "zPacketBase.h"

struct ZRTPPingPacketHeader 
{
	uint8_t version[ZRTP_WORD_SIZE];
	uint8_t epHash[PING_HASH_SIZE];
};

struct ZRTPPingPacket
{
	ZRTPPacketHeader zrtpHeader;
	ZRTPPingPacketHeader pingHeader;
	uint8_t crc[ZRTP_WORD_SIZE];
};

class zPing : public zPacketBase
{
public:
	zPing();
	virtual ~zPing();
	zPing(uint8_t* data);

	void SetVersion(uint8_t *text);
	uint8_t* GetEpHash();

protected:
	ZRTPPingPacketHeader* _PingHdr;

private:
	ZRTPPingPacket _data;
};

#endif // __zPing_h__

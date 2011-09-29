/*

Copyright 2010-2011 iCall, Inc.

This file is part of Open ZRTP.

Open ZRTP is free software: you can redistribute it and/or modify it under the terms of the GNU Lesser General Public License as published bythe Free Software Foundation, either version 3 of the License, or(at your option) any later version.

Open ZRTP is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU Lesser General Public License for more details.

You should have received a copy of the GNU Lesser General Public Licensealong with Open ZRTP. If not, see http://www.gnu.org/licenses/.

*/


#include "zPing.h"
#include "zTextData.h"

zPing::zPing()
{
	DBGLOGLINE("Creating ping packet without data");

	_PacketHeader = &_data.zrtpHeader;
	_PingHdr = &_data.pingHeader;

	SetZrtpID();
	SetLength(sizeof(ZRTPPingPacket) / ZRTP_WORD_SIZE -1 );
	SetMsgType((uint8_t*)PingMsg);
	SetVersion((uint8_t*)zrtpVersion);

}

zPing::zPing(uint8_t* data)
{
	DBGLOGLINE("Creating Ping packet using data");

	_PacketHeader = (ZRTPPacketHeader *) & ((ZRTPPingPacket*)data)->zrtpHeader;
	_PingHdr = (ZRTPPingPacketHeader *) & ((ZRTPPingPacket *)data)->pingHeader;

}

zPing::~zPing()
{
	DBGLOGLINE("Deleting Ping packet.");
}

void zPing::SetVersion(uint8_t *text)
{
	memcpy(_PingHdr->version, text, ZRTP_WORD_SIZE);
}

uint8_t* zPing::GetEpHash()
{
	return _PingHdr->epHash;
}

/*

Copyright 2010-2011 iCall, Inc.

This file is part of Open ZRTP.

Open ZRTP is free software: you can redistribute it and/or modify it under the terms of the GNU Lesser General Public License as published bythe Free Software Foundation, either version 3 of the License, or(at your option) any later version.

Open ZRTP is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU Lesser General Public License for more details.

You should have received a copy of the GNU Lesser General Public Licensealong with Open ZRTP. If not, see http://www.gnu.org/licenses/.

*/


#include "zPingAck.h"
#include "zTextData.h"

zPingAck::zPingAck()
{
	DBGLOGLINE("Creating ping ack packet without data");

	_PacketHeader = &_data.zrtpHeader;
	_PingAckHdr = &_data.pingAckHeader;

	SetZrtpID();
	SetLength(sizeof(ZRTPPingAckPacket) / ZRTP_WORD_SIZE - 1);
	SetMsgType((uint8_t*)PingAckMsg);
	SetVersion((uint8_t*)zrtpVersion);
}

zPingAck::zPingAck(uint8_t *data)
{
	DBGLOGLINE("Creating PingAck Packet using data");

	_PacketHeader = (ZRTPPacketHeader *)&((ZRTPPingAckPacket*)data)->zrtpHeader;
	_PingAckHdr = (ZRTPPingAckPacketHeader *)&((ZRTPPingAckPacket *)data)->pingAckHeader;
}

zPingAck::~zPingAck()
{
	DBGLOGLINE("Deleting PingAck packet.");
}

uint32_t zPingAck::GetSSRC()
{
	return ntohl(_PingAckHdr->ssrc);
};

void zPingAck::SetVersion(uint8_t *text)
{
	memcpy(_PingAckHdr->version, text, ZRTP_WORD_SIZE);
}

void zPingAck::SetSSRC(uint32_t data)
{
	_PingAckHdr->ssrc = static_cast<uint8_t>(htonl(data));
}

void zPingAck::SetRemoteEpHash(uint8_t *hash)
{
	memcpy(_PingAckHdr->remoteEpHash, hash, sizeof(_PingAckHdr->remoteEpHash));
}

void zPingAck::SetLocalEpHash(uint8_t *hash)
{
	memcpy(_PingAckHdr->localEpHash, hash, sizeof(_PingAckHdr->localEpHash));
}
/*

Copyright 2010-2011 iCall, Inc.

This file is part of Open ZRTP.

Open ZRTP is free software: you can redistribute it and/or modify it under the terms of the GNU Lesser General Public License as published bythe Free Software Foundation, either version 3 of the License, or(at your option) any later version.

Open ZRTP is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU Lesser General Public License for more details.

You should have received a copy of the GNU Lesser General Public Licensealong with Open ZRTP. If not, see http://www.gnu.org/licenses/.

*/


#include "zPacketBase.h"

zPacketBase::~zPacketBase()
{
}

const uint8_t* zPacketBase::GetHeaderBase()
{
	return (const uint8_t*)_PacketHeader;
}

bool zPacketBase::IsZrtpPacket()
{
	return (ntohs(_PacketHeader->zrtpId) == ZRTP_PACKET_ID);
}

uint16_t zPacketBase::GetLength()
{
	return ntohs(_PacketHeader->length);
}

uint8_t* zPacketBase::GetMsgType()
{
	return _PacketHeader->messageType;
}

void zPacketBase::SetLength(uint16_t len)
{
	_PacketHeader->length = htons(len);
}

void zPacketBase::SetMsgType(uint8_t *msg) 
{
	memcpy(_PacketHeader->messageType, msg, sizeof(_PacketHeader->messageType));
}

void zPacketBase::SetZrtpID()
{
	_PacketHeader->zrtpId = htons(ZRTP_PACKET_ID);
}
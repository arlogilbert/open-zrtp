/*

Copyright 2010-2011 iCall, Inc.

This file is part of Open ZRTP.

Open ZRTP is free software: you can redistribute it and/or modify it under the terms of the GNU Lesser General Public License as published bythe Free Software Foundation, either version 3 of the License, or(at your option) any later version.

Open ZRTP is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU Lesser General Public License for more details.

You should have received a copy of the GNU Lesser General Public Licensealong with Open ZRTP. If not, see http://www.gnu.org/licenses/.

*/


#include "zConfirm.h"

zConfirm::zConfirm()
{
	DBGLOGLINE("Creating Confirm packet without using the S1 data");
	_Initialize();
	SetSignLength(0);
}

zConfirm::zConfirm(uint32_t st)
{
	DBGLOGLINE("Creating Confirm packet using the data");
	_Initialize();
	SetSignLength(st);
}

void zConfirm::_Initialize()
{
	void* allocData = &_data;

	memset(allocData, 0, sizeof(_data));

	_PacketHeader = (ZRTPPacketHeader *) & ((ZRTPConfirmPacket *)allocData)->zrtpHeader;
	confirmHdr = (ZRTPConfirmPacketHeader *) & ((ZRTPConfirmPacket *) allocData)->confirmHeader;

	SetZrtpID();
}

void zConfirm::SetSignLength(uint32_t s1)
{
	s1 &= 0x1ff;
	int32_t length = sizeof(ZRTPConfirmPacket) + (s1 * ZRTP_WORD_SIZE);

	confirmHdr->sigLength = static_cast<uint8_t>(s1);
	if(s1 & 0x100)
	{
		confirmHdr->filler[1] = 1;
	}

	SetLength(static_cast<uint16_t>(length/4));
}

void zConfirm::SetSASFlag()
{
	confirmHdr->flags |= 0x4;
}

void zConfirm::SetHmac(uint8_t* text)
{
	memcpy(confirmHdr->hmac, text, sizeof(confirmHdr->hmac));
}

void zConfirm::SetIv(uint8_t* text)
{
	memcpy(confirmHdr->iv, text, sizeof(confirmHdr->iv));
}

void zConfirm::SetExpTime(uint32_t t)
{
	confirmHdr->expTime = static_cast<uint8_t>(htonl(t));
}

void zConfirm::SetHashH0(uint8_t* t)
{
	memcpy(confirmHdr->hashH0, t, sizeof(confirmHdr->hashH0));
}

void SetSignLength(uint32_t s1);


bool zConfirm::IsSASFlag()
{
	return ((confirmHdr->flags & 0x4) ? true : false);
}

const uint8_t* zConfirm::GetHmac()
{
	return confirmHdr->hmac;
}

const uint8_t* zConfirm::GetIv()
{
	return confirmHdr->iv;
}

const uint8_t* zConfirm::GetFiller()
{
	return confirmHdr->filler;
}

uint32_t zConfirm::GetExpTime()
{
	return ntohl(confirmHdr->expTime);
}

uint8_t* zConfirm::GetHashH0()
{
	return confirmHdr->hashH0;
}

uint32_t zConfirm::GetSignLength()
{
	uint32_t s1 = confirmHdr->sigLength;
	if (confirmHdr->filler[1] == 1)
	{
		s1 |= 0x100;
	}
		return s1;
}

zConfirm::zConfirm(uint8_t* data)
{
	DBGLOGLINE("Creating Confirm packet using data");

	_AllocatedData = NULL;

	_PacketHeader = (ZRTPPacketHeader *) & ((ZRTPConfirmPacket *)data)->zrtpHeader;
	confirmHdr = (ZRTPConfirmPacketHeader *) & ((ZRTPConfirmPacket *)data)->confirmHeader;
}

zConfirm::~zConfirm()
{
	DBGLOGLINE("Deleting Confirm packet.");
}

/*

Copyright 2010-2011 iCall, Inc.

This file is part of Open ZRTP.

Open ZRTP is free software: you can redistribute it and/or modify it under the terms of the GNU Lesser General Public License as published bythe Free Software Foundation, either version 3 of the License, or(at your option) any later version.

Open ZRTP is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU Lesser General Public License for more details.

You should have received a copy of the GNU Lesser General Public Licensealong with Open ZRTP. If not, see http://www.gnu.org/licenses/.

*/


#include "zDHPart.h"
#include "zRtpConfig.h"


zDHPart::zDHPart()
{
	DBGLOGLINE("Creating DHPart packet without data and packet type");

	_Initialize();
}

zDHPart::zDHPart(PubKeySupported::Enum packet)
{
	DBGLOGLINE("Creating DHpart packet without data");

	_Initialize();
	SetPubKeyType(packet);
}

zDHPart::zDHPart(unsigned char* data)
{
	DBGLOGLINE("Creating DHPart packet from data");

	_PacketHeader = (ZRTPPacketHeader *) & ((ZRTPDHPartPacket *)data)->zrtpHeader;
	_DHPartHdr = (ZRTPDHPartPacketHeader *) & ((ZRTPDHPartPacket *)data)->dhPartHeader;

	int16_t len = GetLength();

    DBGLOGLINEFORMAT1("DHPart length: %d", len);

	if(len == 85)
	{
		_DHLength = 256;
	}
	else if(len == 117)
	{
		_DHLength = 384;
	}
	else
	{
		fprintf(stderr, "Invalid DHPart length: %d", len);
		_pv = NULL;
		return;
	}

	_pv = data + sizeof(ZRTPDHPartPacket);
}

void zDHPart::_Initialize()
{
	void* allocData = &_data;

	memset(allocData, 0, sizeof(_data));

	_PacketHeader = (ZRTPPacketHeader *) & ((ZRTPDHPartPacket *)allocData)->zrtpHeader;
	_DHPartHdr = (ZRTPDHPartPacketHeader *) & ((ZRTPDHPartPacket *)allocData)->dhPartHeader;
	_pv = ((uint8_t*)allocData) + sizeof(ZRTPDHPartPacket);

	SetZrtpID();
}

void zDHPart::SetPubKeyType(PubKeySupported::Enum packet)
{
	if (packet == PubKeySupported::Dh2048)
	{
		_DHLength = 256;
	}
	else if (packet == PubKeySupported::Dh3072)
	{
		_DHLength = 384;
	}
	else
	{
		DBGLOGLINE("error: Invalid DH");
	}

	int length = sizeof(ZRTPDHPartPacket) + _DHLength + (2 * ZRTP_WORD_SIZE);
	SetLength(static_cast<uint16_t>(length/ZRTP_WORD_SIZE));
}

zDHPart::~zDHPart()
{
	DBGLOGLINE("Deleting DHPart Packet.");
}

uint8_t* zDHPart::GetPv()
{
	return _pv;
};

uint8_t* zDHPart::GetRs1ID()
{
	return _DHPartHdr->rs1ID;
};

uint8_t* zDHPart::GetRs2ID()
{
	return _DHPartHdr->rs2ID;
};

uint8_t* zDHPart::GetH1()
{
	return _DHPartHdr->hashH1;
};

uint8_t* zDHPart::GetHMAC()
{
	return _pv+_DHLength;
};

uint8_t* zDHPart::GetPBXSecretID()
{
	return _DHPartHdr->pbxSecID;
};

uint8_t* zDHPart::GetAUXSecretID()
{
	return _DHPartHdr->auxSecID;
};

void zDHPart::SetPv(uint8_t* text)
{
	memcpy(_pv, text, _DHLength);
};

void zDHPart::SetRs1ID(uint8_t* text)
{
	memcpy(_DHPartHdr->rs1ID, text, sizeof(_DHPartHdr->rs1ID));
};

void zDHPart::SetRs2ID(uint8_t* text)
{
	memcpy(_DHPartHdr->rs2ID, text, sizeof(_DHPartHdr->rs2ID));
};

void zDHPart::SetH1(uint8_t* t)
{
	memcpy(_DHPartHdr->hashH1, t, sizeof(_DHPartHdr->hashH1));
};

void zDHPart::SetHMAC(uint8_t* t)
{
	memcpy(_pv+_DHLength, t, 2*ZRTP_WORD_SIZE);
};

void zDHPart::SetPBXSecretID(uint8_t* t)
{
	memcpy(_DHPartHdr->pbxSecID, t, sizeof(_DHPartHdr->pbxSecID));
};

void zDHPart::SetAUXSecretID(uint8_t* t)
{
	memcpy(_DHPartHdr->auxSecID, t, sizeof(_DHPartHdr->auxSecID));
};

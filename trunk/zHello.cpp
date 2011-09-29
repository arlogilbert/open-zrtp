/*

Copyright 2010-2011 iCall, Inc.

This file is part of Open ZRTP.

Open ZRTP is free software: you can redistribute it and/or modify it under the terms of the GNU Lesser General Public License as published bythe Free Software Foundation, either version 3 of the License, or(at your option) any later version.

Open ZRTP is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU Lesser General Public License for more details.

You should have received a copy of the GNU Lesser General Public Licensealong with Open ZRTP. If not, see http://www.gnu.org/licenses/.

*/


#include "zHello.h"
#include "zAlgoSupported.h"

extern const char *zCiphersupported;

zHello::zHello()
{
	DBGLOGLINE("Creating Hello Packet without Data");

	_nHash = HashSupported::EndOfEnum;
	_nCipher = SymCipherSupported::EndOfEnum;
	_nPubKey = PubKeySupported::EndOfEnum;
	_nSAS = SASTypeSupported::EndOfEnum;
	_nAuth = AuthLengthSupported::EndOfEnum;

	int32_t length = sizeof(ZRTPHelloPacket) + (2*ZRTP_WORD_SIZE);
	length += _nHash * ZRTP_WORD_SIZE;
	length += _nCipher * ZRTP_WORD_SIZE;
	length += _nPubKey * ZRTP_WORD_SIZE;
	length += _nSAS * ZRTP_WORD_SIZE;
	length += _nAuth * ZRTP_WORD_SIZE;

	_oHash = sizeof(ZRTPHelloPacketHeader);
	_oCipher = _oHash + (_nHash * ZRTP_WORD_SIZE);
	_oAuth = _oCipher + (_nCipher * ZRTP_WORD_SIZE);
	_oPubkey = _oAuth + (_nAuth * ZRTP_WORD_SIZE);
	_oSAS = _oPubkey + (_nPubKey * ZRTP_WORD_SIZE);
	_pHmac = _oSAS + (_nSAS * ZRTP_WORD_SIZE);


	void* allocData = &_data;
	memset(allocData, 0, sizeof(_data));

	_PacketHeader = (ZRTPPacketHeader*)&((ZRTPHelloPacket *)allocData)->zrtpHeader;
	_HelloHdr = (ZRTPHelloPacketHeader *)&((ZRTPHelloPacket *)allocData)->helloHeader;

	SetZrtpID();

	SetLength(static_cast<uint16_t>(length/ZRTP_WORD_SIZE));
	SetMsgType((uint8_t*)HelloMsg);

	SetVersion((uint8_t*)zrtpVersion);

	uint32_t lenField = _nHash << 16;

	for (int32_t i=0; i<_nHash; i++)
	{
		SetHashType(i, (int8_t*)HashSupported::ToString(i));
	}

	lenField |= _nCipher << 12;

	for (int32_t i=0; i < _nCipher; i++)
	{
		SetCipherType(i, (int8_t*)SymCipherSupported::ToString(i));
	}

	lenField |= _nAuth << 8;
	for (int32_t i = 0; i < _nAuth; i++)
	{
		SetAuthLen (i, (int8_t*)AuthLengthSupported::ToString(i));
	}

	lenField |= _nPubKey << 4;
	for (int32_t i=0; i < _nPubKey; i++)
	{
		SetPubKeyType(i, (int8_t*)PubKeySupported::ToString(i));
	}

	lenField |=_nSAS;
	for(int32_t i=0; i < _nSAS; i++)
	{
		SetSASType(i, (int8_t*)SASTypeSupported::ToString(i));
	}

	_HelloHdr->flagLength = htonl(lenField);
}

zHello::zHello(uint8_t *data)
{
	DBGLOGLINE("Creating Hello packet from data");

	_PacketHeader = (ZRTPPacketHeader*)&((ZRTPHelloPacket *)data)->zrtpHeader;
	_HelloHdr = (ZRTPHelloPacketHeader *)&((ZRTPHelloPacket *)data)->helloHeader;

	uint32_t temp = ntohl(_HelloHdr->flagLength);

	_nHash = (temp & (0xf << 16)) >> 16;
	_nCipher = (temp & (0xf << 12)) >> 12;
	_nAuth = (temp & (0xf << 8)) >> 8;
	_nPubKey = (temp & (0xf << 4)) >> 4;
	_nSAS = temp & 0xf;

	_oHash = sizeof(ZRTPHelloPacketHeader);
	_oCipher = _oHash + (_nHash * ZRTP_WORD_SIZE);
	_oAuth = _oCipher + (_nCipher * ZRTP_WORD_SIZE);
	_oPubkey = _oAuth + (_nAuth * ZRTP_WORD_SIZE);
	_oSAS = _oPubkey + (_nPubKey * ZRTP_WORD_SIZE);
	_pHmac = _oSAS + (_nSAS * ZRTP_WORD_SIZE);

}

zHello::~zHello()
{
}

uint8_t* zHello::GetVersion()
{
	return _HelloHdr->version;
};

uint8_t* zHello::GetClientID()
{
	return _HelloHdr->clientID;
};

uint8_t* zHello::GetH3()
{
	return _HelloHdr->hashImageH3;
};

uint8_t* zHello::GetZID()
{
	return _HelloHdr->zid;
};

void zHello::SetVersion(uint8_t *text)
{
	memcpy(_HelloHdr->version, text, ZRTP_WORD_SIZE);
}

void zHello::SetClientID(const uint8_t *t)
{
	memcpy(_HelloHdr->clientID, t, sizeof(_HelloHdr->clientID));
}

void zHello::SetH3(uint8_t *hash)
{
	memcpy(_HelloHdr->hashImageH3, hash, sizeof(_HelloHdr->hashImageH3));
}

void zHello::SetZID(uint8_t *text)
{
	memcpy(_HelloHdr->zid, text, sizeof(_HelloHdr->zid));
}

bool zHello::IsPassive()
{
	return _Passive;
};

uint8_t* zHello::GetHashType(int32_t n)
{
	return ((uint8_t*)_HelloHdr)+_oHash+(n*ZRTP_WORD_SIZE);
}

uint8_t* zHello::GetCipherType(int32_t n)
{
	return ((uint8_t*)_HelloHdr)+_oCipher+(n*ZRTP_WORD_SIZE);
}

uint8_t* zHello::GetAuthLen(int32_t n)
{
	return ((uint8_t*)_HelloHdr)+_oAuth+(n*ZRTP_WORD_SIZE);
}

uint8_t* zHello::GetPubKeyType(int32_t n)
{
	return ((uint8_t*)_HelloHdr)+_oPubkey+(n*ZRTP_WORD_SIZE);
}

uint8_t* zHello::GetSASType(int32_t n)
{
	return ((uint8_t*)_HelloHdr+_oSAS+(n*ZRTP_WORD_SIZE));
}

uint8_t* zHello::GetHMAC()
{
	return ((uint8_t*)_HelloHdr)+_pHmac;
}

void zHello::SetHashType(int32_t n, int8_t* t)
{
	memcpy(((uint8_t*)_HelloHdr)+_oHash+(n*ZRTP_WORD_SIZE), t, ZRTP_WORD_SIZE);
}

void zHello::SetCipherType(int32_t n, int8_t* t)
{
	memcpy(((uint8_t*)_HelloHdr)+_oCipher+(n*ZRTP_WORD_SIZE), t, ZRTP_WORD_SIZE);
}

void zHello::SetAuthLen(int32_t n, int8_t* t)
{
	memcpy(((uint8_t*)_HelloHdr)+_oAuth+(n*ZRTP_WORD_SIZE), t, ZRTP_WORD_SIZE);
}

void zHello::SetPubKeyType(int32_t n, int8_t* t)
{
	memcpy(((uint8_t*)_HelloHdr)+_oPubkey+(n*ZRTP_WORD_SIZE), t, ZRTP_WORD_SIZE);
}

void zHello::SetSASType(int32_t n, int8_t* t)
{
	memcpy(((uint8_t*)_HelloHdr)+_oSAS+(n*ZRTP_WORD_SIZE), t, ZRTP_WORD_SIZE);
}

void zHello::SetHMAC(uint8_t* t)
{
	memcpy(((uint8_t*)_HelloHdr)+_pHmac, t, 2*ZRTP_WORD_SIZE);
}

int32_t zHello::GetNumHashes()
{
	return _nHash;
}

int32_t zHello::GetNumCiphers()
{
	return _nCipher;
}

int32_t zHello::GetNumPubKeys()
{
	return _nPubKey;
}

int32_t zHello::GetNumSAS()
{
	return _nSAS;
}

int32_t zHello::GetNumAuth()
{
	return _nAuth;
}
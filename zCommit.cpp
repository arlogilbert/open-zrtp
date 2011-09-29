/*

Copyright 2010-2011 iCall, Inc.

This file is part of Open ZRTP.

Open ZRTP is free software: you can redistribute it and/or modify it under the terms of the GNU Lesser General Public License as published bythe Free Software Foundation, either version 3 of the License, or(at your option) any later version.

Open ZRTP is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU Lesser General Public License for more details.

You should have received a copy of the GNU Lesser General Public Licensealong with Open ZRTP. If not, see http://www.gnu.org/licenses/.

*/


#include "zCommit.h"
#include "zTextData.h"

zCommit::zCommit()
{
	DBGLOGLINE("Creating Commit packet without data");

	_PacketHeader = &_data.zrtpHeader;
	_CommitHdr = &_data.commitHeader;

	SetZrtpID();

	SetLength((sizeof(ZRTPCommitPacket) / ZRTP_WORD_SIZE) - 1);
	SetMsgType((uint8_t*)CommitMsg);
}

void zCommit::SetNonce(uint8_t* text)
{
	memcpy(_CommitHdr->hvi, text, sizeof(_CommitHdr->hvi-4*ZRTP_WORD_SIZE));
	uint16_t len = GetLength();
	len -= 4;
	SetLength(len);
}

zCommit::zCommit(uint8_t *data)
{
	DBGLOGLINE("Creating Commit packet from data");

	_PacketHeader = (ZRTPPacketHeader *)&((ZRTPCommitPacket *)data)->zrtpHeader;
	_CommitHdr = (ZRTPCommitPacketHeader *)&((ZRTPCommitPacket *)data)->commitHeader;
}

zCommit::~zCommit()
{
	DBGLOGLINE("Deleting Commit packet.");
}

uint8_t* zCommit::GetZID()
{
	return _CommitHdr->zid;
};

uint8_t* zCommit::GetHashType()
{
	return _CommitHdr->hash;
};

uint8_t* zCommit::GetCipherType()
{
	return _CommitHdr->cipher;
};

uint8_t* zCommit::GetAuthLen()
{
	return _CommitHdr->authlengths;
};

uint8_t* zCommit::GetPubKeysType()
{
	return _CommitHdr->pubkey;
};

uint8_t* zCommit::GetSasType()
{
	return _CommitHdr->sas;
};

uint8_t* zCommit::GetHvi()
{
	return _CommitHdr->hvi;
};

uint8_t* zCommit::GetNonce()
{
	return _CommitHdr->hvi;
};

uint8_t* zCommit::GetH2()
{
	return _CommitHdr->hashH2;
};

uint8_t* zCommit::GetHMAC()
{
	return _CommitHdr->hmac;
};

uint8_t* zCommit::GetHMACMulti()
{
	return _CommitHdr->hmac-4*ZRTP_WORD_SIZE;
};


void zCommit::SetZID(uint8_t* text)
{
	memcpy(_CommitHdr->zid, text, sizeof(_CommitHdr->zid));
};

void zCommit::SetHashType(uint8_t* text)
{
	memcpy(_CommitHdr->hash, text, ZRTP_WORD_SIZE);
};

void zCommit::SetCipherType(uint8_t* text)
{
	memcpy(_CommitHdr->cipher, text, ZRTP_WORD_SIZE);
};

void zCommit::SetAuthLen(uint8_t* text)
{
	memcpy(_CommitHdr->authlengths, text, ZRTP_WORD_SIZE);
};

void zCommit::SetPubKeyType(uint8_t* text)
{
	memcpy(_CommitHdr->pubkey, text, ZRTP_WORD_SIZE);
};

void zCommit::SetSasType(uint8_t* text)
{
	memcpy(_CommitHdr->sas, text, ZRTP_WORD_SIZE);
};

void zCommit::SetHvi(uint8_t* text)
{
	memcpy(_CommitHdr->hvi, text, sizeof(_CommitHdr->hvi));
};

void zCommit::SetH2(uint8_t* hash)
{
	memcpy(_CommitHdr->hashH2, hash, sizeof(_CommitHdr->hashH2));
};

void zCommit::SetHMAC(uint8_t* hash)
{
	memcpy(_CommitHdr->hmac, hash, sizeof(_CommitHdr->hmac));
};

void zCommit::SetHMACMulti(uint8_t* hash)
{
	memcpy(_CommitHdr->hmac-4*ZRTP_WORD_SIZE, hash, sizeof(_CommitHdr->hmac));
};


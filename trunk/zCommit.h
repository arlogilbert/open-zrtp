/*

Copyright 2010-2011 iCall, Inc.

This file is part of Open ZRTP.

Open ZRTP is free software: you can redistribute it and/or modify it under the terms of the GNU Lesser General Public License as published bythe Free Software Foundation, either version 3 of the License, or(at your option) any later version.

Open ZRTP is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU Lesser General Public License for more details.

You should have received a copy of the GNU Lesser General Public Licensealong with Open ZRTP. If not, see http://www.gnu.org/licenses/.

*/


#ifndef __zCommit_h__
#define __zCommit_h__

#include "zPacketBase.h"

struct ZRTPCommitPacketHeader
{
	uint8_t hashH2[HASH_IMAGE_SIZE];
	uint8_t	zid[ZID_SIZE];
	uint8_t hash[ZRTP_WORD_SIZE];
	uint8_t cipher[ZRTP_WORD_SIZE];
	uint8_t authlengths[ZRTP_WORD_SIZE];
	uint8_t	pubkey[ZRTP_WORD_SIZE];
	uint8_t	sas[ZRTP_WORD_SIZE];
	uint8_t	hvi[HVI_SIZE];
	uint8_t	hmac[HMAC_SIZE];
};

struct ZRTPCommitPacket
{
	ZRTPPacketHeader zrtpHeader;
	ZRTPCommitPacketHeader commitHeader;
	uint8_t crc[ZRTP_WORD_SIZE];
};

class zCommit : public zPacketBase
{
public:
	zCommit();				// this creates a commit packet with default available data
	zCommit(uint8_t* data); // this creates a commit packet with received data
	virtual ~zCommit();

	uint8_t* GetZID();
	uint8_t* GetHashType();
	uint8_t* GetCipherType();
	uint8_t* GetAuthLen();
	uint8_t* GetPubKeysType();
	uint8_t* GetSasType();
	uint8_t* GetHvi();
	uint8_t* GetNonce();
	uint8_t* GetH2();
	uint8_t* GetHMAC();
	uint8_t* GetHMACMulti();

	void SetZID(uint8_t* text);
	void SetHashType(uint8_t* text);
	void SetCipherType(uint8_t* text);
	void SetAuthLen(uint8_t* text);
	void SetPubKeyType(uint8_t* text);
	void SetSasType(uint8_t* text);
	void SetHvi(uint8_t* text);
	void SetNonce(uint8_t* text);
	void SetH2(uint8_t* hash);
	void SetHMAC(uint8_t* hash);
	void SetHMACMulti(uint8_t* hash);

protected:
	ZRTPCommitPacketHeader* _CommitHdr;

private:
	ZRTPCommitPacket _data;
};


#endif // __zCommit_h__











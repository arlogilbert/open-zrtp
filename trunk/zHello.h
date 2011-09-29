/*

Copyright 2010-2011 iCall, Inc.

This file is part of Open ZRTP.

Open ZRTP is free software: you can redistribute it and/or modify it under the terms of the GNU Lesser General Public License as published bythe Free Software Foundation, either version 3 of the License, or(at your option) any later version.

Open ZRTP is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU Lesser General Public License for more details.

You should have received a copy of the GNU Lesser General Public Licensealong with Open ZRTP. If not, see http://www.gnu.org/licenses/.

*/


#ifndef __zHello_h__
#define __zHello_h__

#include "zPacketBase.h"

struct ZRTPHelloPacketHeader
{
	uint8_t	 version[ZRTP_WORD_SIZE];
	uint8_t	 clientID[CLIENT_ID_SIZE];
	uint8_t	 hashImageH3[HASH_IMAGE_SIZE];
	uint8_t	 zid[ZID_SIZE];
	uint32_t flagLength;
};

struct ZRTPHelloPacket 
{
	ZRTPPacketHeader zrtpHeader;
	ZRTPHelloPacketHeader helloHeader;
};

class zHello : public zPacketBase
{
public:
	zHello();
	zHello(uint8_t *data);

	virtual ~zHello();

	bool IsPassive();

	uint8_t* GetVersion();
	uint8_t* GetClientID();
	uint8_t* GetH3();
	uint8_t* GetZID();
	uint8_t* GetHashType(int32_t);
	uint8_t* GetCipherType(int32_t);
	uint8_t* GetAuthLen(int32_t);
	uint8_t* GetPubKeyType(int32_t);
	uint8_t* GetSASType(int32_t);
	uint8_t* GetHMAC();
	int32_t GetNumHashes();
	int32_t GetNumCiphers();
	int32_t GetNumPubKeys();
	int32_t GetNumSAS();
	int32_t GetNumAuth();

	void SetVersion(uint8_t*);
	void SetClientID(const uint8_t*);
	void SetH3(uint8_t*);
	void SetZID(uint8_t*);
	void SetHashType(int32_t, int8_t*);
	void SetCipherType(int32_t, int8_t*);
	void SetAuthLen(int32_t, int8_t*);
	void SetPubKeyType(int32_t, int8_t*);
	void SetSASType(int32_t, int8_t*);
	void SetHMAC(uint8_t*);

protected:
	ZRTPHelloPacketHeader* _HelloHdr;
	bool _Passive;
	int32_t _nHash, _nCipher, _nPubKey, _nSAS, _nAuth;
	int32_t _oHash, _oCipher, _oPubkey, _oSAS, _oAuth, _pHmac;

private:
	uint8_t _data[256];
};

#endif // __zHello_h__

/*

Copyright 2010-2011 iCall, Inc.

This file is part of Open ZRTP.

Open ZRTP is free software: you can redistribute it and/or modify it under the terms of the GNU Lesser General Public License as published bythe Free Software Foundation, either version 3 of the License, or(at your option) any later version.

Open ZRTP is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU Lesser General Public License for more details.

You should have received a copy of the GNU Lesser General Public Licensealong with Open ZRTP. If not, see http://www.gnu.org/licenses/.

*/


#ifndef __zCryptoContext_h__
#define __zCryptoContext_h__

#include <string.h>
#include "int.h"
#include "zRtpConfig.h"

struct zAesSrtp;

struct zCryptoContextData;
struct zCryptoContext
{
public:
	~zCryptoContext();
	zCryptoContext();
	zCryptoContext (
		int32_t callId, uint32_t ssrc, int32_t roc, int64_t keyDerivRate,
		SrtpEncryption_t ealg, SrtpAuthentication_t aalg,
		uint8_t* masterkey, int32_t masterKeyLength,
		uint8_t* masterSalt, int32_t masterSaltLength,
		int32_t ekey1, int32_t akey1, int32_t skey1, int32_t tagLength );

	void SrtpEncrypt(uint8_t* packet, uint8_t* payload, uint32_t payloadLength, uint64_t index, uint32_t ssrc);
	void SrtpAuthenticate(uint8_t* packet, uint32_t packetLength, uint32_t rollOverCounter, uint8_t* tag);
	bool CheckReplay(uint16_t newSeqNumber);
	uint64_t GuessIndex(uint16_t newSeqNumber);
	void Update(uint16_t newSeqNumber);
	void DeriveSRTPKeys(uint64_t srtp_packet_index);

	void SetRoc(uint32_t r);
	uint32_t GetRoc() const;
	int32_t GetTagLength() const;
	int32_t GetMkiLength() const;
	uint32_t GetSsrc() const;

	zCryptoContext* NewCryptContextForSSRC (
		uint32_t ssrc,
		uint16_t roc, int64_t key_derivation_rate );

	zCryptoContext* NewCryptContextForSSRC (
		int32_t callId, uint32_t ssrc,
		uint16_t roc, int64_t key_derivation_rate );

private:
	zCryptoContextData* _Data;
};

#endif // __zCryptoContext_h__

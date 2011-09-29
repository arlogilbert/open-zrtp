/*

Copyright 2010-2011 iCall, Inc.

This file is part of Open ZRTP.

Open ZRTP is free software: you can redistribute it and/or modify it under the terms of the GNU Lesser General Public License as published bythe Free Software Foundation, either version 3 of the License, or(at your option) any later version.

Open ZRTP is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU Lesser General Public License for more details.

You should have received a copy of the GNU Lesser General Public Licensealong with Open ZRTP. If not, see http://www.gnu.org/licenses/.

*/


#ifndef __zDHPart_h__
#define __zDHPart_h__

#include "zPacketBase.h"
#include "zAlgoSupported.h"
#include "zRtpConfig.h"

struct ZRTPDHPartPacketHeader
{
	uint8_t hashH1[HASH_IMAGE_SIZE];
	uint8_t rs1ID[ID_SIZE];
	uint8_t rs2ID[ID_SIZE];
	uint8_t auxSecID[ID_SIZE];
	uint8_t pbxSecID[ID_SIZE];
};

struct ZRTPDHPartPacket
{
	ZRTPPacketHeader zrtpHeader;
	ZRTPDHPartPacketHeader dhPartHeader;
};

class zDHPart : public zPacketBase
{
public:
	zDHPart();
	virtual ~zDHPart();
	zDHPart(PubKeySupported::Enum packet);
	zDHPart(unsigned char* data);

	uint8_t* GetPv();
	uint8_t* GetRs1ID();
	uint8_t* GetRs2ID();
	uint8_t* GetH1();
	uint8_t* GetHMAC();
	uint8_t* GetPBXSecretID();
	uint8_t* GetAUXSecretID();

	void SetPv(uint8_t* text);
	void SetRs1ID(uint8_t* text);
	void SetRs2ID(uint8_t* text);
	void SetH1(uint8_t* t);
	void SetHMAC(uint8_t* t);
	void SetPBXSecretID(uint8_t* t);
	void SetAUXSecretID(uint8_t* t);
	void SetPubKeyType(PubKeySupported::Enum packet);

protected:
	uint8_t *_pv;
	ZRTPDHPartPacketHeader* _DHPartHdr;
	int32_t _DHLength;

private:
	uint8_t _data[ZDHPART_DATA_SIZE];
	void _Initialize();
};

#endif // __zDHPart_h__

/*

Copyright 2010-2011 iCall, Inc.

This file is part of Open ZRTP.

Open ZRTP is free software: you can redistribute it and/or modify it under the terms of the GNU Lesser General Public License as published bythe Free Software Foundation, either version 3 of the License, or(at your option) any later version.

Open ZRTP is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU Lesser General Public License for more details.

You should have received a copy of the GNU Lesser General Public Licensealong with Open ZRTP. If not, see http://www.gnu.org/licenses/.

*/


#ifndef __zConfirm_h__
#define __zConfirm_h__

#include "zPacketBase.h"

struct ZRTPConfirmPacketHeader
{
	uint8_t	 hmac[HMAC_SIZE];
	uint8_t	 iv[IV_SIZE];
	uint8_t	 hashH0[HASH_IMAGE_SIZE];
	uint8_t	 filler[2];
	uint8_t	 sigLength;
	uint8_t	 flags;
	uint32_t expTime;
};

struct ZRTPConfirmPacket
{
	ZRTPPacketHeader zrtpHeader;
	ZRTPConfirmPacketHeader confirmHeader;
};

class zConfirm : public zPacketBase
{
public:
	zConfirm();
	virtual ~zConfirm();
	zConfirm(uint32_t s1);
	zConfirm(uint8_t* d);

	void SetSASFlag();
	void SetHmac(uint8_t* text);
	void SetIv(uint8_t* text);
	void SetExpTime(uint32_t t);
	void SetHashH0(uint8_t* t);
	void SetSignLength(uint32_t s1);

    bool IsSASFlag();
	const uint8_t* GetHmac();
	const uint8_t* GetIv();
	const uint8_t* GetFiller();
    uint32_t GetExpTime();
	uint8_t* GetHashH0();
	uint32_t GetSignLength();

private:
	void _Initialize();
	ZRTPConfirmPacketHeader* confirmHdr;
	uint8_t _data[2100];
};

#endif // __zConfirm_h__

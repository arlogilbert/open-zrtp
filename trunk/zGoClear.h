/*

Copyright 2010-2011 iCall, Inc.

This file is part of Open ZRTP.

Open ZRTP is free software: you can redistribute it and/or modify it under the terms of the GNU Lesser General Public License as published bythe Free Software Foundation, either version 3 of the License, or(at your option) any later version.

Open ZRTP is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU Lesser General Public License for more details.

You should have received a copy of the GNU Lesser General Public Licensealong with Open ZRTP. If not, see http://www.gnu.org/licenses/.

*/


#ifndef __zGoClear_h__
#define __zGoClear_h__

#include "zPacketBase.h"

struct ZRTPGoClearPacketHeader
{
	uint8_t clearHmac[HMAC_SIZE];
};

struct ZRTPGoClearPacket
{
	ZRTPPacketHeader zrtpHeader;
	ZRTPGoClearPacketHeader goClearHeader;
	uint8_t crc[ZRTP_WORD_SIZE];
};

class zGoClear : public zPacketBase
{
protected:
	ZRTPGoClearPacketHeader* clearHeader;

public:
	zGoClear();
	zGoClear(uint8_t* data);
	virtual ~zGoClear();

	const uint8_t* GetClearHmac();
	void SetClearHmac(uint8_t *text);
	void ClrClearHmac();

private:
	ZRTPGoClearPacket data;
};

#endif // __zGoClear_h__

/*

Copyright 2010-2011 iCall, Inc.

This file is part of Open ZRTP.

Open ZRTP is free software: you can redistribute it and/or modify it under the terms of the GNU Lesser General Public License as published bythe Free Software Foundation, either version 3 of the License, or(at your option) any later version.

Open ZRTP is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU Lesser General Public License for more details.

You should have received a copy of the GNU Lesser General Public Licensealong with Open ZRTP. If not, see http://www.gnu.org/licenses/.

*/


#ifndef __zError_h__
#define __zError_h__

#include "zPacketBase.h"

struct ZRTPErrorPacketHeader
{
	uint32_t errorCode;
};

struct ZRTPErrorPacket
{
	ZRTPPacketHeader zrtpHeader;
	ZRTPErrorPacketHeader errorHeader;
	uint8_t crc[ZRTP_WORD_SIZE];
};

class zError : public zPacketBase
{
protected:
	ZRTPErrorPacketHeader* errorHeader;

public:
	zError();
	zError(uint8_t* data);
	virtual ~zError();

	uint32_t GetErrorCode();
	void SetErrorCode(uint32_t code);

private:
	ZRTPErrorPacket data;
};

#endif // __zError_h__

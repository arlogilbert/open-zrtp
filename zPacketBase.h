/*

Copyright 2010-2011 iCall, Inc.

This file is part of Open ZRTP.

Open ZRTP is free software: you can redistribute it and/or modify it under the terms of the GNU Lesser General Public License as published bythe Free Software Foundation, either version 3 of the License, or(at your option) any later version.

Open ZRTP is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU Lesser General Public License for more details.

You should have received a copy of the GNU Lesser General Public Licensealong with Open ZRTP. If not, see http://www.gnu.org/licenses/.

*/


#ifndef __zPacketBase_h__
#define __zPacketBase_h__

#include <stdio.h>
#include <string.h>
#include <stdlib.h>

#include "int.h"
#include "network.h"
#include "zRtpConfig.h"
#include "zCRC32.h"
#include "zTextData.h"

struct ZRTPPacketHeader
{
	uint16_t	zrtpId;
	uint16_t	length;
	uint8_t		messageType[TYPE_SIZE];
};

class zPacketBase
{
protected:
	void*				_AllocatedData;
	ZRTPPacketHeader*	_PacketHeader;

public:
	virtual ~zPacketBase();

	const uint8_t* GetHeaderBase();
	uint16_t GetLength();
	uint8_t* GetMsgType();
	
	void SetLength(uint16_t);
	void SetMsgType(uint8_t*);
	void SetZrtpID();

	bool IsZrtpPacket();
};

#endif // __zPacketBase_h__

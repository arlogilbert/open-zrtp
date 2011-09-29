/*

Copyright 2010-2011 iCall, Inc.

This file is part of Open ZRTP.

Open ZRTP is free software: you can redistribute it and/or modify it under the terms of the GNU Lesser General Public License as published bythe Free Software Foundation, either version 3 of the License, or(at your option) any later version.

Open ZRTP is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU Lesser General Public License for more details.

You should have received a copy of the GNU Lesser General Public Licensealong with Open ZRTP. If not, see http://www.gnu.org/licenses/.

*/


#include "zConf2Ack.h"

zConf2Ack::zConf2Ack()
{
	DBGLOGLINE("Creating Conf2Ack packet without data");

	_PacketHeader = &data.zrtpHeader;

	SetZrtpID();
	SetLength((sizeof (ZRTPConf2AckPacket) / ZRTP_WORD_SIZE) - 1);
	SetMsgType((uint8_t*)Conf2AckMsg);
}

zConf2Ack::zConf2Ack(char *data)
{
	DBGLOGLINE("Creating Conf2Ack packet from data");

	_PacketHeader = (ZRTPPacketHeader *)&((ZRTPConf2AckPacket*)data)->zrtpHeader;
}

zConf2Ack::~zConf2Ack()
{
	DBGLOGLINE("Deleting Conf2Ack packet.");
}

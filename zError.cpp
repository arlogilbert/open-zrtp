/*

Copyright 2010-2011 iCall, Inc.

This file is part of Open ZRTP.

Open ZRTP is free software: you can redistribute it and/or modify it under the terms of the GNU Lesser General Public License as published bythe Free Software Foundation, either version 3 of the License, or(at your option) any later version.

Open ZRTP is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU Lesser General Public License for more details.

You should have received a copy of the GNU Lesser General Public Licensealong with Open ZRTP. If not, see http://www.gnu.org/licenses/.

*/


#include "zError.h"

zError::zError()
{
	DBGLOGLINE("Creating Error packet without data");

	_PacketHeader = &data.zrtpHeader;	// the standard header
	errorHeader = &data.errorHeader;

	SetZrtpID();
	SetLength((sizeof(ZRTPErrorPacket) / ZRTP_WORD_SIZE) - 1);
	SetMsgType((uint8_t*)ErrorMsg);
}

zError::zError(uint8_t *data)
{
	DBGLOGLINE("Creating Error packet from data");

	_AllocatedData = NULL;
	_PacketHeader = (ZRTPPacketHeader *)&((ZRTPErrorPacket *)data)->zrtpHeader;	// the standard header
	errorHeader = (ZRTPErrorPacketHeader *)&((ZRTPErrorPacket *)data)->errorHeader;
}

zError::~zError()
{
	DBGLOGLINE("Deleting Error packet.");
}

uint32_t zError::GetErrorCode()
{
	return ntohl(errorHeader->errorCode);
};

void zError::SetErrorCode(uint32_t code)
{
	errorHeader->errorCode = htonl(code);
};

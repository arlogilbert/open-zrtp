/*

Copyright 2010-2011 iCall, Inc.

This file is part of Open ZRTP.

Open ZRTP is free software: you can redistribute it and/or modify it under the terms of the GNU Lesser General Public License as published bythe Free Software Foundation, either version 3 of the License, or(at your option) any later version.

Open ZRTP is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU Lesser General Public License for more details.

You should have received a copy of the GNU Lesser General Public Licensealong with Open ZRTP. If not, see http://www.gnu.org/licenses/.

*/


#ifndef __zCRC32_h__
#define __zCRC32_h__

#include "int.h"

struct zCRC32
{
	static bool Check(uint8_t *buffer, uint16_t length, uint32_t crc32);
	static uint32_t Generate(uint8_t *buffer, uint16_t length);
	static uint32_t End(uint32_t crc32);
};

#endif // __zCRC32_h__


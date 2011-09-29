/*

Copyright 2010-2011 iCall, Inc.

This file is part of Open ZRTP.

Open ZRTP is free software: you can redistribute it and/or modify it under the terms of the GNU Lesser General Public License as published bythe Free Software Foundation, either version 3 of the License, or(at your option) any later version.

Open ZRTP is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU Lesser General Public License for more details.

You should have received a copy of the GNU Lesser General Public Licensealong with Open ZRTP. If not, see http://www.gnu.org/licenses/.

*/

#ifndef __Base32_h__
#define __Base32_h__

#include <iostream>
#include <cstdlib>

#include <assert.h>
#include <stddef.h>
#include <string.h>

using namespace std;

class Base32
{
public:
	Base32(const string encoded);
	Base32(const string encoded, int numberofbits);
	Base32(const unsigned char* data, int numberofbits);
	~Base32();

	const string GetEncoded() { return _Encoded; };

	const unsigned char* GetDecoded(int &len);

    static size_t b2a_Lengtn(const size_t lenInBits);

private:
	void _a2b_l(const string cs, size_t size, const size_t lenInBits);
	void _b2a_l(const unsigned char* cs, int len, const size_t numberofbits);

	unsigned char *_BinResult;
	int _ResultLen;
	string _Encoded;
	unsigned char _SmallBuf[128];
};

#endif // __Base32_h__

/*

Copyright 2010-2011 iCall, Inc.

This file is part of Open ZRTP.

Open ZRTP is free software: you can redistribute it and/or modify it under the terms of the GNU Lesser General Public License as published bythe Free Software Foundation, either version 3 of the License, or(at your option) any later version.

Open ZRTP is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU Lesser General Public License for more details.

You should have received a copy of the GNU Lesser General Public Licensealong with Open ZRTP. If not, see http://www.gnu.org/licenses/.

*/


#include "int.h"
#include "Base32.h"
#include <math.h>
#include <stdio.h>

namespace
{
	int divcl(int x, int y)
	{
		int z;
		if(x>0)
		{
			if(y>0) z=x+y-1;
			else z=x;
		}
		else
		{
			if(y>0)
				z=x;
			else
				z=x+y-1;
		}
		return z/y;
	}

	static const char* const chars= "ybndrfg8ejkmcpqxot1uwisza345h769";

	static const unsigned char revchars[] =
	{
		255, 255, 255, 255, 255, 255, 255, 255,
		255, 255, 255, 255, 255, 255, 255, 255,
		255, 255, 255, 255, 255, 255, 255, 255,
		255, 255, 255, 255, 255, 255, 255, 255,
		255, 255, 255, 255, 255, 255, 255, 255,
		255, 255, 255, 255, 255, 255, 255, 255,
		255,  18, 255,	25,	 26,  27,  30,	29,
		7,	31, 255, 255, 255, 255, 255, 255,
		255, 255, 255, 255, 255, 255, 255, 255,
		255, 255, 255, 255, 255, 255, 255, 255,
		255, 255, 255, 255, 255, 255, 255, 255,
		255, 255, 255, 255, 255, 255, 255, 255,
		255,  24,	1,	12,	  3,   8,	5,	 6,
		28,	  21,	9,	10, 255,  11,	2,	16,
		13,	  14,	4,	22,	 17,  19, 255,	20,
		15,	   0,  23, 255, 255, 255, 255, 255,
		255, 255, 255, 255, 255, 255, 255, 255,
		255, 255, 255, 255, 255, 255, 255, 255,
		255, 255, 255, 255, 255, 255, 255, 255,
		255, 255, 255, 255, 255, 255, 255, 255,
		255, 255, 255, 255, 255, 255, 255, 255,
		255, 255, 255, 255, 255, 255, 255, 255,
		255, 255, 255, 255, 255, 255, 255, 255,
		255, 255, 255, 255, 255, 255, 255, 255,
		255, 255, 255, 255, 255, 255, 255, 255,
		255, 255, 255, 255, 255, 255, 255, 255,
		255, 255, 255, 255, 255, 255, 255, 255,
		255, 255, 255, 255, 255, 255, 255, 255,
		255, 255, 255, 255, 255, 255, 255, 255,
		255, 255, 255, 255, 255, 255, 255, 255,
		255, 255, 255, 255, 255, 255, 255, 255,
		255, 255, 255, 255, 255, 255, 255, 255
	};
}

Base32::Base32(const string encoded)
	: _BinResult(NULL)
	, _ResultLen(0)
{
	_a2b_l(encoded, encoded.size(), (encoded.size()*5/8)*8);
}

Base32::Base32(const string encoded, int numberofbits)
	: _BinResult(NULL)
	, _ResultLen(0)
{
	_a2b_l(encoded, divcl(numberofbits, 5), numberofbits);
}

Base32::Base32(const unsigned char* data, int numberofbits)
	: _BinResult(NULL)
	, _ResultLen(0)
{
	_b2a_l(data, (numberofbits+7)/8, numberofbits);
}

Base32::~Base32()
{
	if(_BinResult != NULL && _BinResult != _SmallBuf)
	{
		delete [] _BinResult;
	}
	_BinResult = NULL;
}

const unsigned char* Base32::GetDecoded(int &len)
{
	len = _ResultLen;
	return _BinResult;
}

void Base32::_b2a_l(const unsigned char* os, int len, const size_t lenInBits)
{
	string result(divcl(len*8, 5), ' ');

	int resp = result.size();

	const unsigned char* osp = os + len;

	unsigned long a = 0;
	switch ((osp - os) % 5)
	{
		case 0:
			do{
				a = *--osp;
				result[--resp] = chars[a % 32];
				a /= 32;
				case 4:
					a |= ((unsigned long)(*--osp)) << 3;
					result[--resp] = chars[a % 32];
					a /= 32;
					result[--resp] = chars[a % 32];
					a /= 32;
				case 3:
					a |= ((unsigned long)(*--osp)) << 1;
					result[--resp] = chars[a % 32];
					a /= 32;
				case 2:
					a |= ((unsigned long)(*--osp)) << 4;
					result[--resp] = chars[a % 32];
					a /= 32;
					result[--resp] = chars[a % 32];
					a /= 32;
				case 1:
					a |= ((unsigned long)(*--osp)) << 2;
					result[--resp] = chars[a % 32];
					a /= 32;
					result[--resp] = chars[a];
			}while (osp > os);
	}

	_Encoded = result.substr(0, divcl(lenInBits, 5));
	return;
}

void Base32::_a2b_l(const string cs, size_t size, const size_t lenInBits)
{
	unsigned long a = 0;

	int len = divcl(size*5, 8);

	if(len < 128)
	{
		_BinResult = _SmallBuf;
	}
	else{
		_BinResult = new unsigned char[len];
	}

	unsigned char* resp = _BinResult + len;

	int csp = size;


	switch (csp % 8)
	{
		case 0:
		do {
			a = revchars[cs[--csp]];
			case 7:
				a |= revchars[cs[--csp]] << 5;
				*--resp = a % 256;
				a /= 256;
			case 6:
				a |= revchars[cs[--csp]] << 2;
			case 5:
				a |= revchars[cs[--csp]] << 7;
				*--resp = a % 256;
				a /= 256;
			case 4:
				a |= revchars[cs[--csp]] << 4;
				*--resp = a % 256;
				a /= 256;
			case 3:
				a |= revchars[cs[--csp]] << 1;
			case 2:
				a |= revchars[cs[--csp]] << 6;
				*--resp = a % 256;
				a /= 256;
			case 1:
				a |= revchars[cs[--csp]] << 3;
				*--resp = a % 256;
		} while(csp);
	}

	_ResultLen = divcl(lenInBits, 8);
	return;
};

size_t Base32::b2a_Lengtn(const size_t lenInBits)
{
	return divcl(lenInBits, 5);
}

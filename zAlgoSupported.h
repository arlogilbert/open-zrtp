/*

Copyright 2010-2011 iCall, Inc.

This file is part of Open ZRTP.

Open ZRTP is free software: you can redistribute it and/or modify it under the terms of the GNU Lesser General Public License as published bythe Free Software Foundation, either version 3 of the License, or(at your option) any later version.

Open ZRTP is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU Lesser General Public License for more details.

You should have received a copy of the GNU Lesser General Public Licensealong with Open ZRTP. If not, see http://www.gnu.org/licenses/.

*/


#ifndef __zAlgoSupported_h__
#define __zAlgoSupported_h__

struct HashSupported
{
	typedef enum 
	{
		Sha256,
		EndOfEnum
	} Enum;

	static const char* ToString(Enum e);
	static const char* ToString(int e);
};

struct SymCipherSupported
{
	typedef enum 
	{
		Aes256,
		Aes128,
		EndOfEnum
	} Enum;

	static const char* ToString(Enum e);
	static const char* ToString(int e);
};

struct PubKeySupported
{
	typedef enum 
	{
		Dh2048,
		Dh3072,
		MultiStream,
		EndOfEnum
	} Enum;

	static const char* ToString(Enum e);
	static const char* ToString(int e);
};

struct SASTypeSupported
{
	typedef enum 
	{
		Libase32,
		EndOfEnum
	} Enum;

	static const char* ToString(Enum e);
	static const char* ToString(int e);
};

struct AuthLengthSupported
{
	typedef enum 
	{
		AuthLen32,
		AuthLen80,
		EndOfEnum
	} Enum;

	static const char* ToString(Enum e);
	static const char* ToString(int e);
};

#endif // __zAlgoSupported_h__
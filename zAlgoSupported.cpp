/*

Copyright 2010-2011 iCall, Inc.

This file is part of Open ZRTP.

Open ZRTP is free software: you can redistribute it and/or modify it under the terms of the GNU Lesser General Public License as published bythe Free Software Foundation, either version 3 of the License, or(at your option) any later version.

Open ZRTP is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU Lesser General Public License for more details.

You should have received a copy of the GNU Lesser General Public Licensealong with Open ZRTP. If not, see http://www.gnu.org/licenses/.

*/


#include "zAlgoSupported.h"

const char* HashSupported::ToString(HashSupported::Enum e)
{
	return HashSupported::ToString(static_cast<int>(e));
}

const char* HashSupported::ToString(int e)
{
	switch(e)
	{
	case HashSupported::Sha256:
	default:
		return "S256";
	}
}

const char* SymCipherSupported::ToString(SymCipherSupported::Enum e)
{
	return SymCipherSupported::ToString(static_cast<int>(e));
}

const char* SymCipherSupported::ToString(int e)
{
	switch(e)
	{
	case SymCipherSupported::Aes128:
	default:
		return "AES1";
	case SymCipherSupported::Aes256:
		return "AES3";
	}
}

const char* PubKeySupported::ToString(PubKeySupported::Enum e)
{
	return PubKeySupported::ToString(static_cast<int>(e));
}

const char* PubKeySupported::ToString(int e)
{
	switch(e)
	{
	case PubKeySupported::MultiStream:
		return "Mult";

	case PubKeySupported::Dh2048:
		return "DH2k";

	case PubKeySupported::Dh3072:
	default:
		return "DH3k";
	}
}

const char* SASTypeSupported::ToString(SASTypeSupported::Enum e)
{
	return SASTypeSupported::ToString(static_cast<int>(e));
}

const char* SASTypeSupported::ToString(int e)
{
	switch(e)
	{
	case SASTypeSupported::Libase32:
	default:
		return "B32 ";
	}
}

const char* AuthLengthSupported::ToString(AuthLengthSupported::Enum e)
{
	return AuthLengthSupported::ToString(static_cast<int>(e));
}

const char* AuthLengthSupported::ToString(int e)
{
	switch(e)
	{
	case AuthLengthSupported::AuthLen32:
	default:
		return "HS32";
	case AuthLengthSupported::AuthLen80:
		return "HS80";
	}
}
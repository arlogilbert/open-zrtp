/*

Copyright 2010-2011 iCall, Inc.

This file is part of Open ZRTP.

Open ZRTP is free software: you can redistribute it and/or modify it under the terms of the GNU Lesser General Public License as published bythe Free Software Foundation, either version 3 of the License, or(at your option) any later version.

Open ZRTP is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU Lesser General Public License for more details.

You should have received a copy of the GNU Lesser General Public Licensealong with Open ZRTP. If not, see http://www.gnu.org/licenses/.

*/


#ifndef __zDH_h__
#define __zDH_h__

#include "int.h"
#include "zopenssl.h"
#include "zAlgoSupported.h"

void GenerateRandomZrtpBytes(uint8_t *buf, int32_t length);

class zDH
{
public:
	zDH(PubKeySupported::Enum type);
	~zDH();

	int32_t GeneratePubKey();										//< generates a public key based on DH parameter and also a private key
	int32_t GetPubKeySize() const;									//< size of the computed public key
	int32_t GetDhSize() const;										//<  size of the DH parameter in bytes
	int32_t GetPubKeyBytes(uint8_t *buf) const;
	int32_t ComputeSecKey(uint8_t *pubKeyBytes, uint8_t *secret);	//< compute the secret key and send it back to the caller
	int32_t CheckPubKey(uint8_t* pubKeyBytes) const;				//< check and validate the received public key

	PubKeySupported::Enum getDHtype()
	{
		return pkType;
	}

private:
	void* ctx;
	PubKeySupported::Enum pkType;
};

#endif // __zDH_h__

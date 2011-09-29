/*

Copyright 2010-2011 iCall, Inc.

This file is part of Open ZRTP.

Open ZRTP is free software: you can redistribute it and/or modify it under the terms of the GNU Lesser General Public License as published bythe Free Software Foundation, either version 3 of the License, or(at your option) any later version.

Open ZRTP is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU Lesser General Public License for more details.

You should have received a copy of the GNU Lesser General Public Licensealong with Open ZRTP. If not, see http://www.gnu.org/licenses/.

*/


#ifndef __zEndpointInfo_h__
#define __zEndpointInfo_h__

#include <stdio.h>

#include "zRecord.h"
#include "zRtpConfig.h"

class zEndpointInfo
{
public:
	static zEndpointInfo* Instance();
	
	int Open(char *name);
	bool IsOpen();
	void Close();

	unsigned int GetRecord(zRecord *zidRec);
	unsigned int SaveRecord(zRecord *zidRec);

	const unsigned char* GetZID();

private:
	zEndpointInfo()
		: _EndpointInfoFileStream(NULL)
	{ };
	~zEndpointInfo();

	void _CreateEndpointInfo(char* name);
	void _CheckMigration(char* name);

private:
	FILE* _EndpointInfoFileStream;
	uint8_t _AccociatedZID[ZRECORD_IDENTIFIER_LENGTH];
};

#endif // __zEndpointInfo_h__

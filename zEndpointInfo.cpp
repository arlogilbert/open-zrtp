/*

Copyright 2010-2011 iCall, Inc.

This file is part of Open ZRTP.

Open ZRTP is free software: you can redistribute it and/or modify it under the terms of the GNU Lesser General Public License as published bythe Free Software Foundation, either version 3 of the License, or(at your option) any later version.

Open ZRTP is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU Lesser General Public License for more details.

You should have received a copy of the GNU Lesser General Public Licensealong with Open ZRTP. If not, see http://www.gnu.org/licenses/.

*/


#include <string>
#include <cstdlib>
#include <ctime>

#include "zRtpConfig.h"
#include "zEndpointInfo.h"

static zEndpointInfo* instance;
static int errors = 0;

void zEndpointInfo::_CreateEndpointInfo(char* name) 
{
	_EndpointInfoFileStream = fopen(name, "wb+");

	if (_EndpointInfoFileStream != NULL) 
	{
		unsigned int* ip;
		ip = (unsigned int*) _AccociatedZID;
		srand((unsigned int)time(NULL));
		*ip++ = rand();
		*ip++ = rand();
		*ip = rand();

		zRecord rec(_AccociatedZID);
		rec.SetOwnZIDRecord();
		fseek(_EndpointInfoFileStream, 0L, SEEK_SET);
		if (fwrite(rec._GetRecordData(), rec._GetRecordLength(), 1, _EndpointInfoFileStream) < 1)
			++errors;
		fflush(_EndpointInfoFileStream);
	}
}

void zEndpointInfo::_CheckMigration(char* name) 
{
	FILE* fdOld;
	unsigned char inb[2];
	zRecord1 recOld;

	fseek(_EndpointInfoFileStream, 0L, SEEK_SET);
	if (fread(inb, 2, 1, _EndpointInfoFileStream) < 1) 
	{
		++errors;
		inb[0] = 0;
	}

	if (inb[0] > 0) 
	{
		return;
	}
	fclose(_EndpointInfoFileStream);
	_EndpointInfoFileStream = NULL;

	std::string fn = std::string(name) + std::string(".save");
	if (rename(name, fn.c_str()) < 0) 
	{
		unlink(name);
		_CreateEndpointInfo(name);
		return;
	}
	fdOld = fopen(fn.c_str(), "rb");	// reopen old format in read only mode

	// Get first record from old file - is the own ZID
	fseek(fdOld, 0L, SEEK_SET);
	if (fread(&recOld, sizeof(zRecord1), 1, fdOld) != 1) 
	{
		fclose(fdOld);
		return;
	}
	if (recOld.ownZID != 1) 
	{
		fclose(fdOld);
		return;
	}
	_EndpointInfoFileStream = fopen(name, "wb+");
	if (_EndpointInfoFileStream == NULL) 
	{
		return;
	}

	zRecord rec(recOld.identifier);
	rec.SetOwnZIDRecord();
	if (fwrite(rec._GetRecordData(), rec._GetRecordLength(), 1, _EndpointInfoFileStream) < 1)
		++errors;

	int numRead;
	do 
	{
		numRead = fread(&recOld, sizeof(zRecord1), 1, fdOld);
		if (numRead == 0) 
		{
			break;
		}
		if (recOld.ownZID == 1 || recOld.validRec == 0) 
		{
			continue;
		}
		zRecord rec2(recOld.identifier);
		rec2._SetValid();
		if (recOld.rs1Valid & zRecordFlags::SASVerfied) 
		{
			rec2.SetSASVerified();
		}
		rec2.SetNewRs1Value(recOld.rs2Data);
		rec2.SetNewRs1Value(recOld.rs1Data);
		if (fwrite(rec2._GetRecordData(), rec2._GetRecordLength(), 1, _EndpointInfoFileStream) < 1)
			++errors;

	} while (numRead == 1);
	fflush(_EndpointInfoFileStream);
}

zEndpointInfo::~zEndpointInfo() 
{
	Close();
}

zEndpointInfo* zEndpointInfo::Instance() 
{
	if (instance == NULL) 
	{
		instance = new zEndpointInfo();
	}
	return instance;
}

int zEndpointInfo::Open(char* name) // Open Endpoint info file and return a Endpoint info class
{
	if (_EndpointInfoFileStream != NULL) 
	{
		return 0;
	}
	if ((_EndpointInfoFileStream = fopen(name, "rb+")) == NULL) 
	{
		_CreateEndpointInfo(name);
	}
	else
	{
		_CheckMigration(name);
		if (_EndpointInfoFileStream != NULL) 
		{
			zRecord rec;
			fseek(_EndpointInfoFileStream, 0L, SEEK_SET);
			if (fread(rec._GetRecordData(), rec._GetRecordLength(), 1, _EndpointInfoFileStream) != 1) 
			{
				fclose(_EndpointInfoFileStream);
				_EndpointInfoFileStream = NULL;
				return -1;
			}
			if (!rec.IsOwnZIDRecord()) 
			{
				fclose(_EndpointInfoFileStream);
				_EndpointInfoFileStream = NULL;
				return -1;
			}
			memcpy(_AccociatedZID, rec.GetIdentfr(), ZRECORD_IDENTIFIER_LENGTH);
		}
	}
	return ((_EndpointInfoFileStream == NULL) ? -1 : 1);
}

bool zEndpointInfo::IsOpen() // Check endpoint info has any open file
{
	return (_EndpointInfoFileStream != NULL);
};

void zEndpointInfo::Close() // Close the endpoint info file
{
	if (_EndpointInfoFileStream != NULL) 
	{
		fclose(_EndpointInfoFileStream);
		_EndpointInfoFileStream = NULL;
	}
}

unsigned int zEndpointInfo::GetRecord(zRecord* zidRecord) // Get a ZID record from an open endpoint info file
{
	unsigned long pos;
	zRecord rec;
	int numRead;

	fseek(_EndpointInfoFileStream, rec._GetRecordLength(), SEEK_SET);

	do 
	{
		pos = ftell(_EndpointInfoFileStream);
		numRead = fread(rec._GetRecordData(), rec._GetRecordLength(), 1, _EndpointInfoFileStream);
		if (numRead == 0) 
		{
			break;
		}

		if (rec.IsOwnZIDRecord() || !rec._IsValid()) 
		{
			continue;
		}

	} while (numRead == 1 &&
		memcmp(zidRecord->GetIdentfr(), rec.GetIdentfr(), ZRECORD_IDENTIFIER_LENGTH) != 0);

	if (numRead == 0) 
	{
		zRecord rec1(zidRecord->GetIdentfr());
		rec1._SetValid();
		if (fwrite(rec1._GetRecordData(), rec1._GetRecordLength(), 1, _EndpointInfoFileStream) < 1)
			++errors;
		memcpy(zidRecord->_GetRecordData(), rec1._GetRecordData(), rec1._GetRecordLength());
	}
	else 
	{
		memcpy(zidRecord->_GetRecordData(), rec._GetRecordData(), rec._GetRecordLength());
	}

	zidRecord->_SetPosition(pos);
	return 1;
}

unsigned int zEndpointInfo::SaveRecord(zRecord *zidRecord) // Save ZID record into an open Endpoint file
{
	fseek(_EndpointInfoFileStream, zidRecord->_GetPostion(), SEEK_SET);
	if (fwrite(zidRecord->_GetRecordData(), zidRecord->_GetRecordLength(), 1, _EndpointInfoFileStream) < 1)
		++errors;
	fflush(_EndpointInfoFileStream);
	return 1;
}

const unsigned char* zEndpointInfo::GetZID() // Get the ZID associated with this Endpoint info file
{
	return _AccociatedZID;
};

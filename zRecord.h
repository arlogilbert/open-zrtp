/*

Copyright 2010-2011 iCall, Inc.

This file is part of Open ZRTP.

Open ZRTP is free software: you can redistribute it and/or modify it under the terms of the GNU Lesser General Public License as published bythe Free Software Foundation, either version 3 of the License, or(at your option) any later version.

Open ZRTP is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU Lesser General Public License for more details.

You should have received a copy of the GNU Lesser General Public Licensealong with Open ZRTP. If not, see http://www.gnu.org/licenses/.

*/


#ifndef __zRecord_h__
#define __zRecord_h__

#include <string.h>
#include "int.h"
#include "zRtpConfig.h"

struct zRecord1
{
	char validRec;
	char ownZID;
	char rs1Valid;
	char rs2Valid;
	uint8_t identifier[ZRECORD_IDENTIFIER_LENGTH];
	uint8_t rs1Data[ZRECORD_RS_LENGTH];
	uint8_t rs2Data[ZRECORD_RS_LENGTH];
};

struct zRecord2
{
	char ver;
	char flags;
	char filler1;
	char filler2;
	uint8_t identifier[ZRECORD_IDENTIFIER_LENGTH];
	uint8_t rs1Interval[ZRECORD_TIMEINTERVAL_LENGTH];
	uint8_t rs1Data[ZRECORD_RS_LENGTH];
	uint8_t rs2Interval[ZRECORD_TIMEINTERVAL_LENGTH];
	uint8_t rs2Data[ZRECORD_RS_LENGTH];
	uint8_t MITMKey[ZRECORD_RS_LENGTH];
};

struct zRecordFlags
{
	typedef enum
	{
		valid		   =  0x00000001,
		SASVerfied	   =  0x00000002,
		RS1Valid	   =  0x00000004,
		RS2Valid	   =  0x00000008,
		MITMKeyAvail   =  0x00000010,
		OwnZIDRecord   =  0x00000020,
	} Enum;
};

class zRecord
{
	friend class zEndpointInfo;

public:
	zRecord(const uint8_t *DataID);

	void SetRs1Valid();
	void ResetRs1Valid();
	bool IsRs1Valid();
	void SetRs2Valid();
	void ResetRs2Valid();
	bool IsRs2Valid();
	void SetMITMKeyAvail();
	void ResetMITMKeyAvail();
	bool IsMITMKeyAvail();
	void SetOwnZIDRecord();
	void ResetOwnZIDRecord();
	bool IsOwnZIDRecord();
	void SetSASVerified();
	void ResetSASVerified();
	bool IsSASVerified();
	const uint8_t* GetIdentfr();
    bool IsRs1NotExpired();
	const uint8_t* GetRs1();
    bool IsRs2NotExpired();
	const uint8_t* GetRs2();
	void SetNewRs1Value(const uint8_t* data, int32_t expire = -1);
	void SetMITMData(const uint8_t* data);
	const uint8_t* GetMITMData();

private:
	zRecord();

	void _SetPosition(long pos);
	long _GetPostion();
	zRecord2* _GetRecordData();
	int _GetRecordLength();
	bool _IsValid();
	void _SetValid();

private:
	zRecord2 _Record;
	unsigned long _Position;
};

#endif // __zRecord_h__

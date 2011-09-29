/*

Copyright 2010-2011 iCall, Inc.

This file is part of Open ZRTP.

Open ZRTP is free software: you can redistribute it and/or modify it under the terms of the GNU Lesser General Public License as published bythe Free Software Foundation, either version 3 of the License, or(at your option) any later version.

Open ZRTP is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU Lesser General Public License for more details.

You should have received a copy of the GNU Lesser General Public Licensealong with Open ZRTP. If not, see http://www.gnu.org/licenses/.

*/


#include <time.h>
#include "zRecord.h"

zRecord::zRecord()
{	
	_Record.ver = 2;
}

zRecord::zRecord(const uint8_t *idData)
{
	memset(&_Record, 0, sizeof(zRecord2));
	memcpy(_Record.identifier, idData, ZRECORD_IDENTIFIER_LENGTH);
	_Record.ver = 2;
}

void zRecord::_SetPosition(long pos) 
{
	_Position = pos;
}

long zRecord::_GetPostion()		   
{
	return _Position; 
}

zRecord2* zRecord::_GetRecordData() 
{
	return &_Record; 
}

int zRecord::_GetRecordLength()			
{
	return sizeof(zRecord2); 
}

bool zRecord::_IsValid()	   
{
	return ((_Record.flags & zRecordFlags::valid) == zRecordFlags::valid); 
}

void zRecord::_SetValid()   
{
	_Record.flags |= zRecordFlags::valid; 
}

void zRecord::SetRs1Valid()	  
{
	_Record.flags |= zRecordFlags::RS1Valid; 
}

void zRecord::ResetRs1Valid() 
{
	_Record.flags &= ~zRecordFlags::RS1Valid; 
}

bool zRecord::IsRs1Valid()	  
{
	return ((_Record.flags & zRecordFlags::RS1Valid) == zRecordFlags::RS1Valid); 
}

void zRecord::SetRs2Valid()	  
{
	_Record.flags |= zRecordFlags::RS2Valid; 
}

void zRecord::ResetRs2Valid() 
{
	_Record.flags &= ~zRecordFlags::RS2Valid; 
}

bool zRecord::IsRs2Valid()	  
{
	return ((_Record.flags & zRecordFlags::RS2Valid) == zRecordFlags::RS2Valid); 
}

void zRecord::SetMITMKeyAvail()	   
{
	_Record.flags |= zRecordFlags::MITMKeyAvail; 
}

void zRecord::ResetMITMKeyAvail()  
{
	_Record.flags &= ~zRecordFlags::MITMKeyAvail; 
}

bool zRecord::IsMITMKeyAvail()	   
{
	return ((_Record.flags & zRecordFlags::MITMKeyAvail) == zRecordFlags::MITMKeyAvail); 
}

void zRecord::SetOwnZIDRecord()	 
{
	_Record.flags = zRecordFlags::OwnZIDRecord; 
}

void zRecord::ResetOwnZIDRecord()
{
	_Record.flags = 0; 
}

bool zRecord::IsOwnZIDRecord()	 
{
	return (_Record.flags == zRecordFlags::OwnZIDRecord); 
}

void zRecord::SetSASVerified()	 
{
	_Record.flags |= zRecordFlags::SASVerfied; 
}

void zRecord::ResetSASVerified() 
{
	_Record.flags &= ~zRecordFlags::SASVerfied; 
}

bool zRecord::IsSASVerified()	 
{
	return ((_Record.flags & zRecordFlags::SASVerfied) == zRecordFlags::SASVerfied); 
}

const uint8_t* zRecord::GetIdentfr() 
{
	return _Record.identifier; 
}

bool zRecord::IsRs1NotExpired()
{
	time_t current = time(NULL);
	time_t validThru;

	if (sizeof(time_t) == 4)
	{
		long long temp;
		memcpy((uint8_t*)&temp, _Record.rs1Interval, ZRECORD_TIMEINTERVAL_LENGTH);
		validThru = temp;
	}
	else
	{
		memcpy((uint8_t*)&validThru, _Record.rs1Interval, ZRECORD_TIMEINTERVAL_LENGTH);
	}

	if (validThru == -1)
		return true;
	if (validThru == 0)
		return false;

	return (current <= validThru) ? true : false;
}

const uint8_t* zRecord::GetRs1() 
{
	return _Record.rs1Data; 
}

bool zRecord::IsRs2NotExpired()
{
	time_t current = time(NULL);
	time_t validThru;

	if (sizeof(time_t) == 4)
	{
		long long temp;
		memcpy((uint8_t*)&temp, _Record.rs2Interval, ZRECORD_TIMEINTERVAL_LENGTH);
		validThru = temp;
	}
	else
	{
		memcpy((uint8_t*)&validThru, _Record.rs2Interval, ZRECORD_TIMEINTERVAL_LENGTH);
	}

	if (validThru == -1)
		return true;
	if (validThru == 0)
		return false;

	return (current <= validThru) ? true : false;
}

const uint8_t* zRecord::GetRs2() 
{
	return _Record.rs2Data; 
}

void zRecord::SetNewRs1Value(const uint8_t* data, int32_t expire)
{
	// shift RS1 data into RS2 position
	memcpy(_Record.rs2Data, _Record.rs1Data, ZRECORD_RS_LENGTH);
	memcpy(_Record.rs2Interval, _Record.rs1Interval, ZRECORD_TIMEINTERVAL_LENGTH);

	// now propagate flags as well
	if (IsRs1Valid())
	{
		SetRs2Valid();
	}

	// set new RS1 data
	memcpy(_Record.rs1Data, data, ZRECORD_RS_LENGTH);

	time_t validThru;
	if (expire == -1)
	{
		validThru = -1;
	}
	else if (expire <= 0)
	{
		validThru = 0;
	}
	else
	{
		validThru = time(NULL) + expire;
	}

	if (sizeof(time_t) == 4)
	{
		long long temp = validThru;
		memcpy(_Record.rs1Interval, (uint8_t*)&temp, ZRECORD_TIMEINTERVAL_LENGTH);
	}
	else
	{
		memcpy(_Record.rs1Interval, (uint8_t*)&validThru, ZRECORD_TIMEINTERVAL_LENGTH);
	}
	SetRs1Valid();
}

const uint8_t* zRecord::GetMITMData()
{
	return _Record.MITMKey;
}

void zRecord::SetMITMData(const uint8_t* data)
{
	memcpy(_Record.MITMKey, data, ZRECORD_RS_LENGTH);
	SetMITMKeyAvail();
}

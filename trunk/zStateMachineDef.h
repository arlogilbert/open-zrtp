/*

Copyright 2010-2011 iCall, Inc.

This file is part of Open ZRTP.

Open ZRTP is free software: you can redistribute it and/or modify it under the terms of the GNU Lesser General Public License as published bythe Free Software Foundation, either version 3 of the License, or(at your option) any later version.

Open ZRTP is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU Lesser General Public License for more details.

You should have received a copy of the GNU Lesser General Public Licensealong with Open ZRTP. If not, see http://www.gnu.org/licenses/.

*/


#ifndef __zStateMachineDef_h__
#define __zStateMachineDef_h__

#include <stdlib.h>
#include <string.h>
#include <assert.h>
#include <vector>

#include "int.h"
#include "zCodes.h"

class zStateMachineDef;
struct zStateMachineDefData;
struct zRtpEngine;
class zPacketBase;
class zCommit;

struct state
{
	void (zStateMachineDef::* StateHandler)(void);
	zCodes::ZRTPStates State;

	state(zCodes::ZRTPStates state, void (zStateMachineDef::* handler)(void));
};
typedef state State_t;
typedef std::vector<State_t> StatesArray_t;

class zStates
{
public:
	zStates (
		StatesArray_t zstates,
		const int32_t numStates,
		const int32_t initialState );

	int32_t ProcessEvent(zStateMachineDef & zsmd);
	bool CurrentState(const int32_t s);
	void NextState(int32_t s);

private:
	zStates(const zStates&);
	zStates& operator= (const zStates&);

	const int32_t _NumStates;
	StatesArray_t _States;
	int32_t _state;

	zStates();
};

struct zEvent
{
	zCodes::ZRTPEventType	type;
	uint8_t*				pkt;
};

struct zTimer
{
	int32_t	time,
			StartTime,
			Increment,
			CappingTime,
			Counter,
			MaxResends;
};

typedef zEvent zEvent_t;
typedef zTimer zTimer_t;

class zStateMachineDef
{
public:
	zStateMachineDef(int32_t call_id, zRtpEngine *p);
	~zStateMachineDef();

	bool CurrentState(const int32_t state);
	void NextState(int32_t state);
	void ProcessEvent(zEvent_t *evt);

	int32_t StartTimer(zTimer_t *t);
	int32_t NextTimer(zTimer_t *t);
	int32_t CancelTimer();
	void SendErrorPkt(uint32_t errCode);
	void SendFail();
	void TimerFail(int32_t subCode);
	void SetMultiStream(bool multi);
	bool IsMultiStream();

private:
	void onInitial();
	void onDetect();
	void onAckDetected();
	void onAckSent();
	void onWaitCommit();
	void onCommitSent();
	void onWaitDHPart2();
	void onWaitConfirm1();
	void onWaitConfirm2();
	void onWaitConfAck();
	void onWaitClearAck();
	void onSecureState();
	void onWaitErrorAck();

	StatesArray_t& getStatesArray();

private:
	zStateMachineDefData* _Impl;
};

#endif // __zStateMachineDef_h__

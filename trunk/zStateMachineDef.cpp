/*

Copyright 2010-2011 iCall, Inc.

This file is part of Open ZRTP.

Open ZRTP is free software: you can redistribute it and/or modify it under the terms of the GNU Lesser General Public License as published bythe Free Software Foundation, either version 3 of the License, or(at your option) any later version.

Open ZRTP is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU Lesser General Public License for more details.

You should have received a copy of the GNU Lesser General Public Licensealong with Open ZRTP. If not, see http://www.gnu.org/licenses/.

*/


#include <iostream>
#include <cstdlib>
#include <ctype.h>

#include "network.h"

#include "zRtpEngine.h"
#include "zStateMachineDef.h"

state::state (
	zCodes::ZRTPStates state,
	void (zStateMachineDef::* handler)(void) )
 : StateHandler(handler)
 , State(state)
{
}

zStates::zStates (
	StatesArray_t zstates,
	const int32_t numStates,
	const int32_t initialState )
 : _NumStates(numStates)
 , _States(zstates)
 , _state(initialState)
{
}

int32_t zStates::ProcessEvent(zStateMachineDef & zsmd)
{
	(zsmd.*_States[_state].StateHandler)();
	return 0;
}

bool zStates::CurrentState(const int32_t s)
{
	return ((s == _state));
}

void zStates::NextState(int32_t s)
{
	_state = s;
}

struct zStateMachineDefData
{
	StatesArray_t _StatesArray;

	zRtpEngine* _Parent;
	zStates* _zStates;
	zEvent_t* _Event;

	zPacketBase* _PktSent;
	zCommit* _PktCommit;

	zTimer_t _T1;
	zTimer_t _T2;

	bool _MultiStream;

	int32_t _CallID;

	zStateMachineDefData(int32_t call_id, zRtpEngine* p)
		: _Parent(p)
		, _zStates(NULL)
		, _PktCommit(NULL)
		, _MultiStream(false)
		, _CallID(call_id)
	{
		_T1.StartTime = 50;
		_T1.MaxResends = 20;
		_T1.CappingTime = 200;
		_T2.StartTime = 150;
		_T2.MaxResends = 10;
		_T2.CappingTime = 600;
	}
};

zStateMachineDef::zStateMachineDef(int32_t call_id, zRtpEngine *p)
	: _Impl(new zStateMachineDefData(call_id, p))
{
	_Impl->_zStates = new zStates(getStatesArray(), zCodes::CountOf_ZRTPStates, zCodes::StateStart);
}

StatesArray_t& zStateMachineDef::getStatesArray()
{
	if (_Impl->_StatesArray.empty())
	{
		_Impl->_StatesArray.reserve(zCodes::CountOf_ZRTPStates);
		_Impl->_StatesArray.push_back(State_t(zCodes::StateStart,			&zStateMachineDef::onInitial));
		_Impl->_StatesArray.push_back(State_t(zCodes::StateDetect,			&zStateMachineDef::onDetect));
		_Impl->_StatesArray.push_back(State_t(zCodes::StateAckDetected,		&zStateMachineDef::onAckDetected));
		_Impl->_StatesArray.push_back(State_t(zCodes::StateAckSent,			&zStateMachineDef::onAckSent));
		_Impl->_StatesArray.push_back(State_t(zCodes::StateWaitCommit,		&zStateMachineDef::onWaitCommit));
		_Impl->_StatesArray.push_back(State_t(zCodes::StateSentCommit,		&zStateMachineDef::onCommitSent));
		_Impl->_StatesArray.push_back(State_t(zCodes::StateWaitDH2,			&zStateMachineDef::onWaitDHPart2));
		_Impl->_StatesArray.push_back(State_t(zCodes::StateWaitConfirm1,	&zStateMachineDef::onWaitConfirm1));
		_Impl->_StatesArray.push_back(State_t(zCodes::StateWaitConfirm2,	&zStateMachineDef::onWaitConfirm2));
		_Impl->_StatesArray.push_back(State_t(zCodes::StateWaitConfirmAck,	&zStateMachineDef::onWaitConfAck));
		_Impl->_StatesArray.push_back(State_t(zCodes::StateWaitClearAck,	&zStateMachineDef::onWaitClearAck));
		_Impl->_StatesArray.push_back(State_t(zCodes::StateSecure,			&zStateMachineDef::onSecureState));
		_Impl->_StatesArray.push_back(State_t(zCodes::StateWaitErrorAck,	&zStateMachineDef::onWaitErrorAck));
	}
	return _Impl->_StatesArray;
}

zStateMachineDef::~zStateMachineDef(void)
{
	if (!CurrentState(zCodes::StateStart))
	{
		zEvent_t ev;

		CancelTimer();
		ev.type = zCodes::ZrtpEventTypeClose;
		_Impl->_Event = &ev;
		_Impl->_zStates->ProcessEvent(*this);
	}
	delete _Impl->_zStates;
	delete _Impl;
}

bool zStateMachineDef::CurrentState(const int32_t state)
{
	return _Impl->_zStates->CurrentState(state);
}

void zStateMachineDef::NextState(int32_t state)
{
	_Impl->_zStates->NextState(state);
}

void zStateMachineDef::ProcessEvent(zEvent_t *ev)
{
	_Impl->_Event = ev;
	char *msg, first, middle, last;
	uint8_t *pkt;

	_Impl->_Parent->_EnterSynch();

	if (_Impl->_Event->type == zCodes::ZrtpEventTypePacket)
	{
		pkt = _Impl->_Event->pkt;
		msg = (char *)pkt + 4;
		first = (char)tolower(*msg);
		middle = (char)tolower(*(msg+4));
		last = (char)tolower(*(msg+7));

		if (first == 'e' && middle =='r' && last == ' ')
		{

			CancelTimer();
			zError epkt(pkt);
			zErrorAck* eapkt = _Impl->_Parent->_MakeErrorAckPacket(&epkt);
			_Impl->_Parent->_SendZrtpPacket(static_cast<zPacketBase *>(eapkt));
			_Impl->_Event->type = zCodes::ZrtpEventTypeErrorPacket;
		}
		else if (first == 'p' && middle == ' ' && last == ' ')
		{
			zPing ppkt(pkt);
			zPingAck* ppktAck = _Impl->_Parent->_MakePingAckPacket(&ppkt);
			_Impl->_Parent->_SendZrtpPacket(static_cast<zPacketBase *>(ppktAck));
			_Impl->_Parent->_LeaveSynch();
			return;
		}
	}

	else if (_Impl->_Event->type == zCodes::ZrtpEventTypeClose)
	{
		CancelTimer();
	}
	_Impl->_zStates->ProcessEvent(*this);
	_Impl->_Parent->_LeaveSynch();
}

void zStateMachineDef::onInitial(void)
{
	DBGLOGLINEFORMAT1("Call:%.2d StateStart. Checking for match in Initial. ", _Impl->_CallID);

	if (_Impl->_Event->type == zCodes::ZrtpEventTypeStart)
	{
		zHello* hello = _Impl->_Parent->_MakeHelloPacket();

		_Impl->_PktSent = static_cast<zPacketBase *>(hello);

		if (!_Impl->_Parent->_SendZrtpPacket(_Impl->_PktSent))
		{
			SendFail();
			return;
		}
		if (StartTimer(&_Impl->_T1) <= 0)
		{
			TimerFail(zCodes::FatalNoTimer);
			return;
		}
		NextState(zCodes::StateDetect);
	}
}

void zStateMachineDef::onDetect(void)
{
	DBGLOGLINEFORMAT1("Call:%.2d StateDetect. Checking for match in Detect. ", _Impl->_CallID);

	char *msg, first, last;
	uint8_t *pkt;
	uint32_t errorCode = 0;


	if (_Impl->_Event->type == zCodes::ZrtpEventTypePacket)
	{
		pkt = _Impl->_Event->pkt;
		msg = (char *)pkt + 4;

		first = (char)tolower(*msg);
		last = (char)tolower(*(msg+7));

		if (first == 'h' && last =='k')
		{
			CancelTimer();
			_Impl->_PktSent = NULL;
			NextState(zCodes::StateAckDetected);
			return;
		}

		if (first == 'h' && last ==' ')
		{
			CancelTimer();
			zHelloAck* helloAck = _Impl->_Parent->_MakeHelloAckPacket();

			if (!_Impl->_Parent->_SendZrtpPacket(static_cast<zPacketBase *>(helloAck)))
			{
				_Impl->_Parent->_NegotiationFail(zCodes::MsgLevelFatal, zCodes::FatalCannotSend);
				return;
			}
			
			zHello hpkt(pkt);
			_Impl->_PktCommit = _Impl->_Parent->_MakeCommitPacket(&hpkt, &errorCode);

			NextState(zCodes::StateAckSent);
			if (_Impl->_PktCommit == NULL)
			{
				SendErrorPkt(errorCode);	
				return;
			}
			if (StartTimer(&_Impl->_T1) <= 0) {		   
				TimerFail(zCodes::FatalNoTimer);	
			}
			_Impl->_T1.MaxResends = 60;					
		}
		return;		 
	}
	
	else if (_Impl->_Event->type == zCodes::ZrtpEventTypeTimer)
	{
		if (!_Impl->_Parent->_SendZrtpPacket(_Impl->_PktSent))
		{
			SendFail();		  
			return;
		}
		if (NextTimer(&_Impl->_T1) <= 0)
		{
			_Impl->_PktCommit = NULL;
			_Impl->_Parent->_NoSupportOtherEndpoint();
			NextState(zCodes::StateDetect);
		}
	}
	
	else if (_Impl->_Event->type == zCodes::ZrtpEventTypeStart)
	{
		CancelTimer();
		if (!_Impl->_Parent->_SendZrtpPacket(_Impl->_PktSent))
		{
			SendFail();					
			return;
		}
		if (StartTimer(&_Impl->_T1) <= 0)
		{
			TimerFail(zCodes::FatalNoTimer);   
		}
	}
	else { 
		if (_Impl->_Event->type != zCodes::ZrtpEventTypeClose)
		{
			_Impl->_Parent->_NegotiationFail(zCodes::MsgLevelFatal, zCodes::FatalProtocolError);
		}
		_Impl->_PktSent = NULL;
		NextState(zCodes::StateStart);
	}
}

void zStateMachineDef::onAckSent(void)
{
	DBGLOGLINEFORMAT1("Call:%.2d StateAckSent. Checking for match in AckSent. ", _Impl->_CallID);

	char *msg, first, last;
	uint8_t *pkt;
	uint32_t errorCode = 0;

	if (_Impl->_Event->type == zCodes::ZrtpEventTypePacket)
	{
		pkt = _Impl->_Event->pkt;
		msg = (char *)pkt + 4;

		first = (char)tolower(*msg);
		last = (char)tolower(*(msg+7));


		if (first == 'h' && last =='k')
		{
			CancelTimer();

			_Impl->_PktSent = static_cast<zPacketBase *>(_Impl->_PktCommit);
			_Impl->_PktCommit = NULL;					 
			NextState(zCodes::StateSentCommit);
			if (!_Impl->_Parent->_SendZrtpPacket(_Impl->_PktSent))
			{
				SendFail();				
				return;
			}
			if (StartTimer(&_Impl->_T2) <= 0)
			{
				TimerFail(zCodes::FatalNoTimer);  
			}
			return;
		}

		if (first == 'h' && last ==' ')
		{
			zHelloAck* helloAck = _Impl->_Parent->_MakeHelloAckPacket();

			if (!_Impl->_Parent->_SendZrtpPacket(static_cast<zPacketBase *>(helloAck)))
			{
				NextState(zCodes::StateDetect);
				_Impl->_Parent->_NegotiationFail(zCodes::MsgLevelFatal, zCodes::FatalCannotSend);
			}
			return;
		}

		if (first == 'c')
		{
			CancelTimer();
			zCommit cpkt(pkt);

			if (!_Impl->_MultiStream)
			{
				zDHPart* dhPart1 = _Impl->_Parent->_MakeDHPart1Packet(&cpkt, &errorCode);

				if (dhPart1 == NULL)
				{
					if (errorCode != zCodes::IgnorePacket)
					{
						SendErrorPkt(errorCode);
					}
					return;
				}
				_Impl->_PktCommit = NULL;
				_Impl->_PktSent = static_cast<zPacketBase *>(dhPart1);
				NextState(zCodes::StateWaitDH2);
			}
			else
			{
				zConfirm* confirm = _Impl->_Parent->_MakeConfirm1PacketForMultistreamMode(&cpkt, &errorCode);

				if (confirm == NULL)
				{
					if (errorCode != zCodes::IgnorePacket)
					{
						SendErrorPkt(errorCode);
					}
					return;
				}
				_Impl->_PktSent = static_cast<zPacketBase *>(confirm);
				NextState(zCodes::StateWaitConfirm2);
			}
			if (!_Impl->_Parent->_SendZrtpPacket(_Impl->_PktSent))
			{
				SendFail();		 
			}
		}
	}

	else if (_Impl->_Event->type == zCodes::ZrtpEventTypeTimer)
	{
		if (!_Impl->_Parent->_SendZrtpPacket(_Impl->_PktSent))
		{
			return SendFail();		
		}
		if (NextTimer(&_Impl->_T1) <= 0)
		{
			_Impl->_Parent->_NoSupportOtherEndpoint();
			_Impl->_PktCommit = NULL;
			
			NextState(zCodes::StateDetect);
		}
	}
	else
	{	
		if (_Impl->_Event->type != zCodes::ZrtpEventTypeClose)
		{
			_Impl->_Parent->_NegotiationFail(zCodes::MsgLevelFatal, zCodes::FatalProtocolError);
		}
		_Impl->_PktCommit = NULL;
		_Impl->_PktSent = NULL;
		NextState(zCodes::StateStart);
	}
}

void zStateMachineDef::onAckDetected(void)
{
	DBGLOGLINEFORMAT1("Call:%.2d StateAckDetected. Checking for match in AckDetected. ", _Impl->_CallID);

	char *msg, first, last;
	uint8_t *pkt;
	uint32_t errorCode = 0;

	if (_Impl->_Event->type == zCodes::ZrtpEventTypePacket)
	{
		pkt = _Impl->_Event->pkt;
		msg = (char *)pkt + 4;

		first = (char)tolower(*msg);
		last = (char)tolower(*(msg+7));

		if (first == 'h' && last ==' ')
		{
			zHello hpkt(pkt);
			zCommit* commit = _Impl->_Parent->_MakeCommitPacket(&hpkt, &errorCode);

			if (commit == NULL)
			{
				SendErrorPkt(errorCode);
				return;
			}
			zHelloAck *helloAck = _Impl->_Parent->_MakeHelloAckPacket();
			NextState(zCodes::StateWaitCommit);

			
			_Impl->_PktSent = static_cast<zPacketBase *>(helloAck);
			if (!_Impl->_Parent->_SendZrtpPacket(static_cast<zPacketBase *>(helloAck)))
			{
				SendFail();
			}
		}
	}
	else
	{  
		if (_Impl->_Event->type != zCodes::ZrtpEventTypeClose)
		{
			_Impl->_Parent->_NegotiationFail(zCodes::MsgLevelFatal, zCodes::FatalProtocolError);
		}
		NextState(zCodes::StateStart);
	}
}

void zStateMachineDef::onWaitCommit(void)
{
	DBGLOGLINEFORMAT1("Call:%.2d StateWaitCommit. Checking for match in WaitCommit. ", _Impl->_CallID);

	char *msg, first, last;
	uint8_t *pkt;
	uint32_t errorCode = 0;

	if (_Impl->_Event->type == zCodes::ZrtpEventTypePacket)
	{
		pkt = _Impl->_Event->pkt;
		msg = (char *)pkt + 4;

		first = (char)tolower(*msg);
		last = (char)tolower(*(msg+7));

		if (first == 'h')
		{
			if (!_Impl->_Parent->_SendZrtpPacket(_Impl->_PktSent))
			{
				SendFail();		  
			}
			return;
		}

		if (first == 'c')
		{
			zCommit cpkt(pkt);

			if (!_Impl->_MultiStream)
			{
				zDHPart* dhPart1 = _Impl->_Parent->_MakeDHPart1Packet(&cpkt, &errorCode);

				
				if (dhPart1 == NULL)
				{
					if (errorCode != zCodes::IgnorePacket)
					{
						SendErrorPkt(errorCode);
					}
					return;
				}
				_Impl->_PktSent = static_cast<zPacketBase *>(dhPart1);
				NextState(zCodes::StateWaitDH2);
			}
			else
			{
				zConfirm* confirm = _Impl->_Parent->_MakeConfirm1PacketForMultistreamMode(&cpkt, &errorCode);

				
				if (confirm == NULL)
				{
					if (errorCode != zCodes::IgnorePacket)
					{
						SendErrorPkt(errorCode);
					}
					return;
				}
				_Impl->_PktSent = static_cast<zPacketBase *>(confirm);
				NextState(zCodes::StateWaitConfirm2);
			}
			if (!_Impl->_Parent->_SendZrtpPacket(_Impl->_PktSent))
			{
				SendFail();		  
			}
		}
	}
	else {	
		if (_Impl->_Event->type != zCodes::ZrtpEventTypeClose)
		{
			_Impl->_Parent->_NegotiationFail(zCodes::MsgLevelFatal, zCodes::FatalProtocolError);
		}
		_Impl->_PktSent = NULL;
		NextState(zCodes::StateStart);
	}
}

void zStateMachineDef::onCommitSent(void)
{
	DBGLOGLINEFORMAT1("Call:%.2d StateSentCommit. Checking for match in CommitSend. ", _Impl->_CallID);

	char *msg, first, last;
	uint8_t *pkt;
	uint32_t errorCode = 0;

	if (_Impl->_Event->type == zCodes::ZrtpEventTypePacket)
	{
		pkt = _Impl->_Event->pkt;
		msg = (char *)pkt + 4;

		first = (char)tolower(*msg);
		last = (char)tolower(*(msg+7));


		if (first == 'h' && (last =='k' || last == ' '))
		{
			return;
		}


		if (first == 'c' && last == ' ')
		{
			zCommit zpCo(pkt);

			if (!_Impl->_Parent->_VerifyH2HashImage(&zpCo))
			{
				return;
			}
			CancelTimer();		   

			if (_Impl->_Parent->_CompareCommit(&zpCo) < 0)
			{
				if (!_Impl->_MultiStream)
				{
					zDHPart* dhPart1 = _Impl->_Parent->_MakeDHPart1Packet(&zpCo, &errorCode);

					
					if (dhPart1 == NULL)
					{
						if (errorCode != zCodes::IgnorePacket)
						{
							SendErrorPkt(errorCode);
						}
						return;
					}
					NextState(zCodes::StateWaitDH2);
					_Impl->_PktSent = static_cast<zPacketBase *>(dhPart1);
				}
				else
				{
					zConfirm* confirm = _Impl->_Parent->_MakeConfirm1PacketForMultistreamMode(&zpCo, &errorCode);

					
					if (confirm == NULL)
					{
						if (errorCode != zCodes::IgnorePacket)
						{
							SendErrorPkt(errorCode);
						}
						return;
					}
					NextState(zCodes::StateWaitConfirm2);
					_Impl->_PktSent = static_cast<zPacketBase *>(confirm);
				}
				if (!_Impl->_Parent->_SendZrtpPacket(_Impl->_PktSent))
				{
					SendFail();		  
				}
			}
			else
			{
				if (StartTimer(&_Impl->_T2) <= 0) { 
					TimerFail(zCodes::FatalNoTimer);	
				}
			}
			return;
		}

		if (first == 'd')
		{
			CancelTimer();
			_Impl->_PktSent = NULL;
			zDHPart dpkt(pkt);
			zDHPart* dhPart2 = _Impl->_Parent->_MakeDHPart2Packet(&dpkt, &errorCode);

			if (dhPart2 == NULL)
			{
				if (errorCode != zCodes::IgnorePacket)
				{
					SendErrorPkt(errorCode);
				}
				else
				{
					if (StartTimer(&_Impl->_T2) <= 0)
					{
						TimerFail(zCodes::FatalNoTimer);	   
					}
				}

				return;
			}
			_Impl->_PktSent = static_cast<zPacketBase *>(dhPart2);
			NextState(zCodes::StateWaitConfirm1);

			if (!_Impl->_Parent->_SendZrtpPacket(_Impl->_PktSent))
			{
				SendFail();		  
				return;
			}
			if (StartTimer(&_Impl->_T2) <= 0)
			{
				TimerFail(zCodes::FatalNoTimer);	   
			}
			return;
		}

		if (_Impl->_MultiStream && (first == 'c' && last == '1'))
		{
			CancelTimer();
			zConfirm cpkt(pkt);

			zConfirm* confirm = _Impl->_Parent->_MakeConfirm2PacketForMultistreamMode(&cpkt, &errorCode);

			
			if (confirm == NULL)
			{
				SendErrorPkt(errorCode);
				return;
			}
			NextState(zCodes::StateWaitConfirmAck);
			_Impl->_PktSent = static_cast<zPacketBase *>(confirm);

			if (!_Impl->_Parent->_SendZrtpPacket(_Impl->_PktSent))
			{
				SendFail();			
				return;
			}
			if (StartTimer(&_Impl->_T2) <= 0)
			{
				TimerFail(zCodes::FatalNoTimer);  
			}
			
			if (!_Impl->_Parent->_SecretsReady(ForReceiver))
			{
				_Impl->_Parent->_SendInformationMessageToHost(zCodes::MsgLevelFatal, zCodes::CriticalSoftwareError);
				SendErrorPkt(zCodes::CriticalSoftwareError);
				return;
			}
		}
	}
	else if (_Impl->_Event->type == zCodes::ZrtpEventTypeTimer)
	{
		if (!_Impl->_Parent->_SendZrtpPacket(_Impl->_PktSent))
		{
			SendFail();		  
			return;
		}
		if (NextTimer(&_Impl->_T2) <= 0)
		{
			TimerFail(zCodes::FatalRetrySaturation);	   
		}
	}
	else
	{  
		if (_Impl->_Event->type != zCodes::ZrtpEventTypeClose)
		{
			_Impl->_Parent->_NegotiationFail(zCodes::MsgLevelFatal, zCodes::FatalProtocolError);
		}
		_Impl->_PktSent = NULL;
		NextState(zCodes::StateStart);
	}
}

void zStateMachineDef::onWaitDHPart2(void)
{
	DBGLOGLINEFORMAT1("Call:%.2d StateWaitDH2. Checking for match in DHPart2. ", _Impl->_CallID);

	char *msg, first, last;
	uint8_t *pkt;
	uint32_t errorCode = 0;

	if (_Impl->_Event->type == zCodes::ZrtpEventTypePacket)
	{
		pkt = _Impl->_Event->pkt;
		msg = (char *)pkt + 4;

		first = (char) tolower(*msg);
		last = (char) tolower(*(msg+7));


		if (first == 'c')
		{
			if (!_Impl->_Parent->_SendZrtpPacket(_Impl->_PktSent))
			{
				return SendFail();		 
			}
			return;
		}

		if (first == 'd')
		{
			zDHPart dpkt(pkt);
			zConfirm* confirm = _Impl->_Parent->_MakeConfirm1Packet(&dpkt, &errorCode);

			if (confirm == NULL)
			{
				if (errorCode != zCodes::IgnorePacket)
				{
					SendErrorPkt(errorCode);
				}
				return;
			}
			NextState(zCodes::StateWaitConfirm2);
			_Impl->_PktSent = static_cast<zPacketBase *>(confirm);
			if (!_Impl->_Parent->_SendZrtpPacket(_Impl->_PktSent))
			{
				SendFail();		  
			}
		}
	}
	else
	{  
		if (_Impl->_Event->type != zCodes::ZrtpEventTypeClose)
		{
			_Impl->_Parent->_NegotiationFail(zCodes::MsgLevelFatal, zCodes::FatalProtocolError);
		}
		_Impl->_PktSent = NULL;
		NextState(zCodes::StateStart);
	}
}

void zStateMachineDef::onWaitConfirm1(void)
{
	DBGLOGLINEFORMAT1("Call:%.2d StateWaitConfirm1. Checking for match in WaitConfirm1. ", _Impl->_CallID);

	char *msg, first, last;
	uint8_t *pkt;
	uint32_t errorCode = 0;

	if (_Impl->_Event->type == zCodes::ZrtpEventTypePacket)
	{
		pkt = _Impl->_Event->pkt;
		msg = (char *)pkt + 4;

		first = (char) tolower(*msg);
		last = (char) tolower(*(msg+7));


		if (first == 'c' && last == '1')
		{
			CancelTimer();
			zConfirm cpkt(pkt);

			zConfirm* confirm = _Impl->_Parent->_MakeConfirm2Packet(&cpkt, &errorCode);

			
			if (confirm == NULL)
			{
				SendErrorPkt(errorCode);
				return;
			}
			NextState(zCodes::StateWaitConfirmAck);
			_Impl->_PktSent = static_cast<zPacketBase *>(confirm);

			if (!_Impl->_Parent->_SendZrtpPacket(_Impl->_PktSent))
			{
				SendFail();			
				return;
			}
			if (StartTimer(&_Impl->_T2) <= 0)
			{
				TimerFail(zCodes::FatalNoTimer);  
			}
			
			if (!_Impl->_Parent->_SecretsReady(ForReceiver))
			{
				_Impl->_Parent->_SendInformationMessageToHost(zCodes::MsgLevelFatal, zCodes::CriticalSoftwareError);
				SendErrorPkt(zCodes::CriticalSoftwareError);
				return;
			}
		}
	}
	else if (_Impl->_Event->type == zCodes::ZrtpEventTypeTimer)
	{
		if (!_Impl->_Parent->_SendZrtpPacket(_Impl->_PktSent))
		{
			SendFail();				
			return;
		}
		if (NextTimer(&_Impl->_T2) <= 0)
		{
			TimerFail(zCodes::FatalRetrySaturation);	 
		}
	}
	else
	{	
		if (_Impl->_Event->type != zCodes::ZrtpEventTypeClose)
		{
			_Impl->_Parent->_NegotiationFail(zCodes::MsgLevelFatal, zCodes::FatalProtocolError);
		}
		_Impl->_PktSent = NULL;
		NextState(zCodes::StateStart);
	}
}

void zStateMachineDef::onWaitConfirm2(void)
{
	DBGLOGLINEFORMAT1("Call:%.2d StateWaitConfirm2. Checking for match in WaitConfirm2. ", _Impl->_CallID);

	char *msg, first, last;
	uint8_t *pkt;
	uint32_t errorCode = 0;

	if (_Impl->_Event->type == zCodes::ZrtpEventTypePacket)
	{
		pkt = _Impl->_Event->pkt;
		msg = (char *)pkt + 4;

		first = (char) tolower(*msg);
		last = (char) tolower(*(msg+7));


		if (first == 'd' || (_Impl->_MultiStream && (first == 'c' && last == ' ')))
		{
			if (!_Impl->_Parent->_SendZrtpPacket(_Impl->_PktSent))
			{
				SendFail();				
			}
			return;
		}

		if (first == 'c' && last == '2')
		{
			zConfirm cpkt(pkt);
			zConf2Ack* confack = _Impl->_Parent->_MakeConf2AckPacket(&cpkt, &errorCode);

			
			if (confack == NULL)
			{
				SendErrorPkt(errorCode);
				return;
			}
			_Impl->_PktSent = static_cast<zPacketBase *>(confack);

			if (!_Impl->_Parent->_SendZrtpPacket(_Impl->_PktSent))
			{
				SendFail();				
				return;
			}
			if (!_Impl->_Parent->_SecretsReady(ForSender) ||
				!_Impl->_Parent->_SecretsReady(ForReceiver))
			{
				_Impl->_Parent->_SendInformationMessageToHost(zCodes::MsgLevelFatal, zCodes::CriticalSoftwareError);
				SendErrorPkt(zCodes::CriticalSoftwareError);
				return;
			}
			NextState(zCodes::StateSecure);
			_Impl->_Parent->_SendInformationMessageToHost(zCodes::MsgLevelInfo, zCodes::InfoSecureStateOn);
		}
	}
	else {	
		if (_Impl->_Event->type != zCodes::ZrtpEventTypeClose)
		{
			_Impl->_Parent->_NegotiationFail(zCodes::MsgLevelFatal, zCodes::FatalProtocolError);
		}
		_Impl->_PktSent = NULL;
		NextState(zCodes::StateStart);
	}
}

void zStateMachineDef::onWaitConfAck(void)
{
	DBGLOGLINEFORMAT1("Call:%.2d StateWaitConfirmAck. Checking for match in WaitConfAck. ", _Impl->_CallID);

	char *msg, first, last;
	uint8_t *pkt;

	if (_Impl->_Event->type == zCodes::ZrtpEventTypePacket)
	{
		pkt = _Impl->_Event->pkt;
		msg = (char *)pkt + 4;

		first = (char) tolower(*msg);
		last = (char) tolower(*(msg+7));


		if (first == 'c')
		{
			CancelTimer();
			_Impl->_PktSent = NULL;
			
			
			if (!_Impl->_Parent->_SecretsReady(ForSender))
			{
				_Impl->_Parent->_SendInformationMessageToHost(zCodes::MsgLevelFatal, zCodes::CriticalSoftwareError);
				SendErrorPkt(zCodes::CriticalSoftwareError);
				return;
			}
			NextState(zCodes::StateSecure);
			
			_Impl->_Parent->_SendInformationMessageToHost(zCodes::MsgLevelInfo, zCodes::InfoSecureStateOn);
		}
	}
	else if (_Impl->_Event->type == zCodes::ZrtpEventTypeTimer)
	{
		if (!_Impl->_Parent->_SendZrtpPacket(_Impl->_PktSent))
		{
			SendFail();				
			_Impl->_Parent->_SetSecretsOff(ForReceiver);
			return;
		}
		if (NextTimer(&_Impl->_T2) <= 0)
		{
			TimerFail(zCodes::FatalRetrySaturation); 
			_Impl->_Parent->_SetSecretsOff(ForReceiver);
		}
	}
	else
	{  
		if (_Impl->_Event->type != zCodes::ZrtpEventTypeClose)
		{
			_Impl->_Parent->_NegotiationFail(zCodes::MsgLevelFatal, zCodes::FatalProtocolError);
		}
		_Impl->_PktSent = NULL;
		NextState(zCodes::StateStart);
		_Impl->_Parent->_SetSecretsOff(ForReceiver);
	}
}

void zStateMachineDef::onWaitClearAck(void)
{
	DBGLOGLINEFORMAT1("Call:%.2d StateWaitClearAck. Checking for match in ClearAck. ", _Impl->_CallID);

	char *msg, first, last;
	uint8_t *pkt;

	if (_Impl->_Event->type == zCodes::ZrtpEventTypePacket)
	{
		pkt = _Impl->_Event->pkt;
		msg = (char *)pkt + 4;

		first = (char) tolower(*msg);
		last = (char) tolower(*(msg+7));


		if (first == 'c' && last =='k')
		{
			CancelTimer();
			_Impl->_PktSent = NULL;
			NextState(zCodes::StateStart);
		}
	}
	
	else if (_Impl->_Event->type == zCodes::ZrtpEventTypeTimer)
	{
		if (!_Impl->_Parent->_SendZrtpPacket(_Impl->_PktSent))
		{
			SendFail();					
			return;
		}
		if (NextTimer(&_Impl->_T2) <= 0)
		{
			TimerFail(zCodes::FatalRetrySaturation);	 
		}
	}
	else {	
		if (_Impl->_Event->type != zCodes::ZrtpEventTypeClose)
		{
			_Impl->_Parent->_NegotiationFail(zCodes::MsgLevelFatal, zCodes::FatalProtocolError);
		}
		_Impl->_PktSent = NULL;
		NextState(zCodes::StateStart);
	}
}

void zStateMachineDef::onWaitErrorAck(void)
{
	DBGLOGLINEFORMAT1("Call:%.2d StateWaitErrorAck. Checking for match in ErrorAck. ", _Impl->_CallID);

	char *msg, first, last;
	uint8_t *pkt;

	if (_Impl->_Event->type == zCodes::ZrtpEventTypePacket)
	{
		pkt = _Impl->_Event->pkt;
		msg = (char *)pkt + 4;

		first = (char) tolower(*msg);
		last = (char) tolower(*(msg+7));


		if (first == 'e' && last =='k')
		{
			CancelTimer();
			_Impl->_PktSent = NULL;
			NextState(zCodes::StateStart);
		}
	}
	
	else if (_Impl->_Event->type == zCodes::ZrtpEventTypeTimer)
	{
		if (!_Impl->_Parent->_SendZrtpPacket(_Impl->_PktSent))
		{
			SendFail();					
			return;
		}
		if (NextTimer(&_Impl->_T2) <= 0)
		{
			TimerFail(zCodes::FatalRetrySaturation);	 
		}
	}
	else
	{  
		if (_Impl->_Event->type != zCodes::ZrtpEventTypeClose)
		{
			_Impl->_Parent->_NegotiationFail(zCodes::MsgLevelFatal, zCodes::FatalProtocolError);
		}
		_Impl->_PktSent = NULL;
		NextState(zCodes::StateStart);
	}
}

void zStateMachineDef::onSecureState(void)
{
	DBGLOGLINEFORMAT1("Call:%.2d StateSecure. Checking for match in SecureState. ", _Impl->_CallID);

	char *msg, first, last;
	uint8_t *pkt;

	if (_Impl->_Event->type == zCodes::ZrtpEventTypePacket)
	{
		pkt = _Impl->_Event->pkt;
		msg = (char *)pkt + 4;

		first = (char) tolower(*msg);
		last = (char) tolower(*(msg+7));


		if (first == 'c' && last == '2')
		{
			if (_Impl->_PktSent != NULL && !_Impl->_Parent->_SendZrtpPacket(_Impl->_PktSent))
			{
				_Impl->_PktSent = NULL;
				NextState(zCodes::StateStart);
				_Impl->_Parent->_SetSecretsOff(ForSender);
				_Impl->_Parent->_SetSecretsOff(ForReceiver);
				_Impl->_Parent->_NegotiationFail(zCodes::MsgLevelFatal, zCodes::FatalCannotSend);
			}
			return;
		}

		if (first == 'g' && last == 'r')
		{
			zGoClear gpkt(pkt);
			zGoClearAck* clearAck = _Impl->_Parent->_MakeClearAckPacket(&gpkt);

			if (!_Impl->_Parent->_SendZrtpPacket(static_cast<zPacketBase *>(clearAck)))
			{
				return;
			}
			
		}
	}
	else
	{  
		_Impl->_PktSent = NULL;
		_Impl->_Parent->_SetSecretsOff(ForSender);
		_Impl->_Parent->_SetSecretsOff(ForReceiver);
		NextState(zCodes::StateStart);
		if (_Impl->_Event->type != zCodes::ZrtpEventTypeClose)
		{
			_Impl->_Parent->_NegotiationFail(zCodes::MsgLevelFatal, zCodes::FatalProtocolError);
		}
		_Impl->_Parent->_SendInformationMessageToHost(zCodes::MsgLevelInfo, zCodes::InfoSecureStateOff);
	}
}

int32_t zStateMachineDef::StartTimer(zTimer_t *t)
{
	t->time = t->StartTime;
	t->Counter = 0;
	return _Impl->_Parent->_TimerActive(t->time);
}

int32_t zStateMachineDef::CancelTimer()
{
	return _Impl->_Parent->_TimerCancel();
};

int32_t zStateMachineDef::NextTimer(zTimer_t *t) {
	t->time += t->time;
	t->time = (t->time > t->CappingTime)? t->CappingTime : t->time;
	t->Counter++;
	if (t->Counter > t->MaxResends)
	{
		return -1;
	}
	return _Impl->_Parent->_TimerActive(t->time);
}

void zStateMachineDef::SendErrorPkt(uint32_t errorCode)
{
	CancelTimer();

	zError* err = _Impl->_Parent->_MakeErrorPacket(errorCode);
	_Impl->_Parent->_NegotiationFail(zCodes::MsgLevelZrtpError, errorCode);

	_Impl->_PktSent =  static_cast<zPacketBase *>(err);
	NextState(zCodes::StateWaitErrorAck);
	if (!_Impl->_Parent->_SendZrtpPacket(static_cast<zPacketBase *>(err)) || (StartTimer(&_Impl->_T2) <= 0))
	{
		SendFail();
	}
}

void zStateMachineDef::SendFail()
{
	_Impl->_PktSent = NULL;
	NextState(zCodes::StateStart);
	_Impl->_Parent->_NegotiationFail(zCodes::MsgLevelFatal, zCodes::FatalCannotSend);
}

void zStateMachineDef::TimerFail(int32_t subCode)
{
	_Impl->_PktSent = NULL;
	NextState(zCodes::StateStart);
	_Impl->_Parent->_NegotiationFail(zCodes::MsgLevelFatal, subCode);
}

void zStateMachineDef::SetMultiStream(bool multi)
{
	_Impl->_MultiStream = multi;
}

bool zStateMachineDef::IsMultiStream()
{
	return _Impl->_MultiStream;
}

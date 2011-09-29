/*

Copyright 2010-2011 iCall, Inc.

This file is part of Open ZRTP.

Open ZRTP is free software: you can redistribute it and/or modify it under the terms of the GNU Lesser General Public License as published bythe Free Software Foundation, either version 3 of the License, or(at your option) any later version.

Open ZRTP is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU Lesser General Public License for more details.

You should have received a copy of the GNU Lesser General Public Licensealong with Open ZRTP. If not, see http://www.gnu.org/licenses/.

*/


#include <sstream>

#include "int.h"
#include "network.h"

#include "zRtpEngine.h"

#include "zStateMachineDef.h"
#include "zRecord.h"
#include "zEndpointInfo.h"
#include "Base32.h"
#include "zDH.h"

namespace
{
	void __ComputeKey (
		uint8_t* key,
		uint32_t keyLength,
		uint8_t* label,
		int32_t labelLength,
		uint8_t* context,
		int32_t contextLength,
		int32_t L,
		uint8_t* output )
	{
		unsigned char* data[6];
		uint32_t length[6];
		uint32_t pos = 0;
		uint32_t maclen = 0;

		uint32_t counter = 1;
		counter = htonl(counter);
		data[pos] = (unsigned char*)&counter;
		length[pos++] = sizeof(uint32_t);

		data[pos] = label;
		length[pos++] = labelLength;

		data[pos] = context;
		length[pos++] = contextLength;

		uint32_t len = htonl(L);
		data[pos] = (unsigned char*)&len;
		length[pos++] = sizeof(uint32_t);

		data[pos] = NULL;

		Hmac256::Compute (
			key,
			keyLength,
			data,
			length,
			output,
			&maclen );
	}
}

struct zRtpEngineData
{
	zStateMachineDef*	_EngineState;
	zCallback*			_Callback;

	HashSupported::Enum			_CommitedHash;
	SymCipherSupported::Enum	_CommitedCipher;
	PubKeySupported::Enum		_CommitedPublicKey;
	SASTypeSupported::Enum		_SASType;
	AuthLengthSupported::Enum	_AuthLength;

	zDH*		_ActiveDHContext;
	uint8_t*	_ComputedDHSecret;
	uint8_t		_MyComputedPublicKeyBytes[400];
	int32_t		_MyComputedPublicKeyLength;
	Role		_MyRole;

	std::string _SASValue;
	uint8_t _SASHashForSignaling[Sha256::DigestLength];

	bool _RS1Valid;
	bool _RS2Valid;

	bool _MultiStream;
	bool _MultiStreamAvailable;

	bool _PBXEnroll;

	uint8_t* _AuxiliarySecretStorage;
	int32_t _AuxiliarySecretStorageLength;

	void* _MessageSHAContext;

	uint8_t* _SignatureData;
	int32_t _SignatureDataLength;

	uint32_t _PeerSSRC;

	uint8_t _HashImage0[Sha256::DigestLength];
	uint8_t _HashImage1[Sha256::DigestLength];
	uint8_t _HashImage2[Sha256::DigestLength];
	uint8_t _HashImage3[Sha256::DigestLength];
	uint8_t _HashHello[Sha256::DigestLength];

	uint8_t _PeerHashImage0[Sha256::DigestLength];
	uint8_t _PeerHashImage1[Sha256::DigestLength];
	uint8_t _PeerHashImage2[Sha256::DigestLength];
	uint8_t _PeerHashImage3[Sha256::DigestLength];

	uint8_t _HashMessage[Sha256::DigestLength];

	uint8_t _S0[Sha256::DigestLength];

	uint8_t _NewRS1[ZRECORD_RS_LENGTH];

	uint8_t _ZrtpSessionKey[Sha256::DigestLength];

	uint8_t _MyOwnZidData[ZRECORD_IDENTIFIER_LENGTH];
	uint8_t _MyOwnHVI[Sha256::DigestLength];

	uint8_t _OtherEndpointZidData[ZRECORD_IDENTIFIER_LENGTH];
	uint8_t _OtherEndpointHVI[Sha256::DigestLength];

	uint8_t _Initiator1ID[Sha256::DigestLength];
	uint8_t _Initiator2ID[Sha256::DigestLength];
	uint8_t _InitiatorAuxSecretID[Sha256::DigestLength];
	uint8_t _InitiatorPbxSecretID[Sha256::DigestLength];
	uint8_t _InitiatorHmacKey[Sha256::DigestLength];
	uint8_t _InitiatorSrtpKey[Sha256::DigestLength];
	uint8_t _InitiatorSrtpSalt[Sha256::DigestLength];
	uint8_t _InitiatorConfirmZrtpKey[Sha256::DigestLength];

	uint8_t _Responder1ID[Sha256::DigestLength];
	uint8_t _Responder2ID[Sha256::DigestLength];
	uint8_t _ResponderAuxSecretID[Sha256::DigestLength];
	uint8_t _ResponderPbxSecretID[Sha256::DigestLength];
	uint8_t _ResponderHmacKey[Sha256::DigestLength];
	uint8_t _ResponderSrtpKey[Sha256::DigestLength];
	uint8_t _ResponderSrtpSalt[Sha256::DigestLength];
	uint8_t _ResponderConfirmZrtpKey[Sha256::DigestLength];

	zHello			_PacketHello;
	zHelloAck		_PacketHelloAck;
	zCommit			_PacketCommit;
	zConfirm		_PacketConfirm1;
	zConfirm		_PacketConfirm2;
	zConf2Ack		_PacketConf2Ack;
	zDHPart			_PacketDHPart1;
	zDHPart			_PacketDHPart2;
	zGoClear		_PacketGoClear;
	zGoClearAck		_PacketGoClearAck;
	zError			_PacketError;
	zErrorAck		_PacketErrorAck;
	zPing			_PacketPing;
	zPingAck		_PacketPingAck;

	uint8_t _RandomInitialVector[RANDOM_INITIAL_VECTOR_LEN];
	uint8_t _TemporaryMessageBuffer[1024];
	int32_t _LengthMsgData;

	int32_t _CallID;

	zRtpEngineData(int32_t call_id, const uint8_t* myZID, zCallback* cb, std::string id)
		: _Callback(cb)
		, _ActiveDHContext(NULL)
		, _ComputedDHSecret(NULL)
		, _RS1Valid(false)
		, _RS2Valid(false)
		, _MultiStream(false)
		, _MultiStreamAvailable(false)
		, _PBXEnroll(false)
		, _AuxiliarySecretStorage(NULL)
		, _AuxiliarySecretStorageLength(0)
		, _MessageSHAContext(NULL)
		, _CallID(call_id)
	{
		_ZeroMemory();

		GenerateRandomZrtpBytes(_HashImage0, HASH_IMAGE_SIZE);

		Sha256::Compute(_HashImage0, HASH_IMAGE_SIZE, _HashImage1);
		Sha256::Compute(_HashImage1, HASH_IMAGE_SIZE, _HashImage2);
		Sha256::Compute(_HashImage2, HASH_IMAGE_SIZE, _HashImage3);

		_PacketHello.SetH3(_HashImage3);

		memcpy(_MyOwnZidData, myZID, ZID_SIZE);

		_PacketHello.SetZID(_MyOwnZidData);
	}

	~zRtpEngineData()
	{
		if (_ComputedDHSecret != NULL)
		{
			delete _ComputedDHSecret;
			_ComputedDHSecret = NULL;
		}

		if (_EngineState != NULL)
		{
			delete _EngineState;
			_EngineState = NULL;
		}

		if (_ActiveDHContext != NULL)
		{
			delete _ActiveDHContext;
			_ActiveDHContext = NULL;
		}

		if (_MessageSHAContext != NULL)
		{
			Sha256::CloseSha256Context(_MessageSHAContext, NULL);
			_MessageSHAContext = NULL;
		}

		if (_AuxiliarySecretStorage != NULL)
		{
			delete _AuxiliarySecretStorage;
			_AuxiliarySecretStorage = NULL;
			_AuxiliarySecretStorageLength = 0;
		}

		_ZeroMemory();
	}

	void _ZeroMemory()
	{
		memset(_InitiatorHmacKey, 0, Sha256::DigestLength);
		memset(_ResponderHmacKey, 0, Sha256::DigestLength);
		memset(_InitiatorConfirmZrtpKey, 0, Sha256::DigestLength);
		memset(_ResponderConfirmZrtpKey, 0, Sha256::DigestLength);
		memset(_InitiatorSrtpKey, 0, Sha256::DigestLength);
		memset(_InitiatorSrtpSalt, 0,  Sha256::DigestLength);
		memset(_ResponderSrtpKey, 0, Sha256::DigestLength);
		memset(_ResponderSrtpSalt, 0, Sha256::DigestLength);
		memset(_ZrtpSessionKey, 0, Sha256::DigestLength);
		memset(_RandomInitialVector, 0, RANDOM_INITIAL_VECTOR_LEN);
		memset(_TemporaryMessageBuffer, 0, 1024);
	}
};

zRtpEngine::zRtpEngine (
	int32_t call_id,
	const uint8_t* myZID,
	zCallback* cb,
	std::string id )
 : _EngineData(new zRtpEngineData(call_id, myZID, cb, id))
{
	_SetClientIDForZrtpHelloMessage(id);

	_EngineData->_EngineState = new zStateMachineDef(call_id, this);

	DBGLOGLINEFORMAT1("ZRTP Engine was created for call id %d ...", _EngineData->_CallID);
}

zRtpEngine::~zRtpEngine()
{
	DBGLOGLINEFORMAT1("Destroy ZRTP Engine of call id %d ...", _EngineData->_CallID);

	StopEngine();
	delete _EngineData;
}

void zRtpEngine::StartEngine()
{
	zEvent_t ev;

	ev.type = zCodes::ZrtpEventTypeStart;
	_EngineData->_EngineState->ProcessEvent(&ev);
}

void zRtpEngine::StopEngine()
{
	zEvent_t ev;

	if (_EngineData->_EngineState != NULL)
	{
		ev.type = zCodes::ZrtpEventTypeClose;
		_EngineData->_EngineState->ProcessEvent(&ev);
	}
}

void zRtpEngine::ProcessMessage(uint8_t *message, uint32_t pSSRC)
{
	zEvent_t ev;

	_EngineData->_PeerSSRC = pSSRC;
	ev.type = zCodes::ZrtpEventTypePacket;
	ev.pkt = message;

	if (_EngineData->_EngineState != NULL)
	{
		_EngineData->_EngineState->ProcessEvent(&ev);
	}
}

void zRtpEngine::ProcessTimeout()
{
	zEvent_t ev;

	ev.type = zCodes::ZrtpEventTypeTimer;
	if (_EngineData->_EngineState != NULL)
	{
		_EngineData->_EngineState->ProcessEvent(&ev);
	}
}

void zRtpEngine::SetAuxillarySecret(uint8_t* data, int32_t length)
{
	if (length > 0)
	{
		_EngineData->_AuxiliarySecretStorage = new uint8_t[length];
		_EngineData->_AuxiliarySecretStorageLength = length;
		memcpy(_EngineData->_AuxiliarySecretStorage, data, length);
	}
}

void zRtpEngine::SetPBXSecret(uint8_t* data, int32_t length)
{
	(data);
	(length);
}

bool zRtpEngine::HandleGoClear(uint8_t* extHdr)
{
	(extHdr);
	return 0;
}

bool zRtpEngine::CheckCurrentState(int32_t state)
{
	if (_EngineData->_EngineState != NULL)
	{
		return _EngineData->_EngineState->CurrentState(state);
	}
	else
	{
		return false;
	}
}

void zRtpEngine::SetSASVerified()
{
	zRecord zidRec(_EngineData->_OtherEndpointZidData);
	zEndpointInfo *zid = zEndpointInfo::Instance();

	zid->GetRecord(&zidRec);
	zidRec.SetSASVerified();
	zid->SaveRecord(&zidRec);
}

void zRtpEngine::ResetSASVerifiedFlag()
{
	zRecord zidRec(_EngineData->_OtherEndpointZidData);
	zEndpointInfo *zid = zEndpointInfo::Instance();

	zid->GetRecord(&zidRec);
	zidRec.ResetSASVerified();
	zid->SaveRecord(&zidRec);
}

std::string zRtpEngine::GetHelloHashData()
{
	// see sections
	// 8. Signaling Interactions
	// 8.1. Binding the Media Stream to the Signaling Layer via the Hello Hash

	std::ostringstream stm;

	uint8_t* hp = _EngineData->_HashHello;

	stm << zrtpVersion;
	stm << " ";
	stm.fill('0');
	stm << hex;
	for (int i = 0; i < Sha256::DigestLength; i++)
	{
		stm.width(2);
		stm << static_cast<uint32_t>(*hp++);
	}
	return stm.str();
}

std::string zRtpEngine::GetMultiStreamParams()
{
	std::string str("");
	char tmp[Sha256::DigestLength + 1 + 1 + 1];
	if (CheckCurrentState(zCodes::StateSecure) && !_EngineData->_MultiStream)
	{
		tmp[0] = (char)_EngineData->_CommitedHash;
		tmp[1] = (char)_EngineData->_AuthLength;
		tmp[2] = (char)_EngineData->_CommitedCipher;
		memcpy(tmp+3, _EngineData->_ZrtpSessionKey, Sha256::DigestLength);
		str.assign(tmp, Sha256::DigestLength + 1 + 1 + 1); 	}
	return str;
}

void zRtpEngine::SetMultiStreamParams(std::string parameters)
{
	char tmp[Sha256::DigestLength + 1 + 1 + 1];
	_EngineData->_CommitedHash = static_cast<HashSupported::Enum>(parameters.at(0) & 0xff);

	parameters.copy(tmp, Sha256::DigestLength + 1 + 1 + 1, 0);

	_EngineData->_AuthLength = static_cast<AuthLengthSupported::Enum>(tmp[1] & 0xff);
	_EngineData->_CommitedCipher = static_cast<SymCipherSupported::Enum>(tmp[2] & 0xff);
	memcpy(_EngineData->_ZrtpSessionKey, tmp+3, Sha256::DigestLength);

	_EngineData->_MultiStream = true;
	_EngineData->_EngineState->SetMultiStream(true);
}

bool zRtpEngine::CheckIsMultiStream()
{
	return _EngineData->_MultiStream;
}

bool zRtpEngine::CheckIsMultiStreamAvailable()
{
	return _EngineData->_MultiStreamAvailable;
}

bool zRtpEngine::SetSignatureData(uint8_t* data, int32_t length)
{
	(data);
	(length);
	return false;
}

int32_t zRtpEngine::GetSignatureData(uint8_t* data)
{
	(data);
	return 0;
}

int32_t zRtpEngine::GetSignatureLength()
{
	return 0;
}

void zRtpEngine:: SetPBXEnroll(bool yesNo)
{
	_EngineData->_PBXEnroll = yesNo;
}

void zRtpEngine::AcceptEnrollRequest(bool accepted)
{
	(accepted);
	return;
}

void zRtpEngine::Conf2AckSecure()
{
	zEvent_t ev;

	ev.type = zCodes::ZrtpEventTypePacket;
	ev.pkt = (uint8_t*)&_EngineData->_PacketConf2Ack;

	if (_EngineData->_EngineState != NULL)
	{
		_EngineData->_EngineState->ProcessEvent(&ev);
	}
}

int32_t zRtpEngine::GetOtherEndpointZidData(uint8_t* data)
{
	memcpy(data, _EngineData->_OtherEndpointZidData, ZRECORD_IDENTIFIER_LENGTH);
	return ZRECORD_IDENTIFIER_LENGTH;
}

void zRtpEngine::_EnterSynch()
{
	_EngineData->_Callback->EnterSynch();
}

void zRtpEngine::_LeaveSynch()
{
	_EngineData->_Callback->LeaveSynch();
}

int32_t zRtpEngine::_TimerActive(int32_t tm)
{
	return (_EngineData->_Callback->TimerActive(tm));
}

int32_t zRtpEngine::_TimerCancel()
{
	return (_EngineData->_Callback->TimerCancel());
}

int32_t zRtpEngine::_SendZrtpPacket(zPacketBase *packet)
{
	return ((packet == NULL) ? 0 :
		_EngineData->_Callback->SendPacketThroughRTP(packet->GetHeaderBase(), (packet->GetLength() * 4) + 4));
}

void zRtpEngine::_SendInformationMessageToHost(zCodes::ZRTPMessageLevel severity, int32_t subCode)
{
	_EngineData->_Callback->SendInformationToTheHost(severity, subCode);
}

void zRtpEngine::_NegotiationFail(zCodes::ZRTPMessageLevel severity, int32_t subCode)
{
	_EngineData->_Callback->HandleNegotiationFail(severity, subCode);
}

void zRtpEngine::_NoSupportOtherEndpoint()
{
	_EngineData->_Callback->HandleNoSupportOther();
}

void zRtpEngine::_StoreZrtpMessageInTempBuffer(zPacketBase* pkt)
{
	int32_t length = pkt->GetLength() * ZRTP_WORD_SIZE;
	memset(_EngineData->_TemporaryMessageBuffer, 0, sizeof(_EngineData->_TemporaryMessageBuffer));
	memcpy(_EngineData->_TemporaryMessageBuffer, (uint8_t*)pkt->GetHeaderBase(), length);
	_EngineData->_LengthMsgData = length;
}

int32_t zRtpEngine::_CompareCommit(zCommit *commit)
{
	int32_t len = 0;
	len = !_EngineData->_MultiStream ? HVI_SIZE : (4 * ZRTP_WORD_SIZE);
	return (memcmp(_EngineData->_MyOwnHVI, commit->GetHvi(), len));
}

bool zRtpEngine::_VerifyH2HashImage(zCommit *commit)
{
	uint8_t tmpH3[Sha256::DigestLength];

	Sha256::Compute(commit->GetH2(), HASH_IMAGE_SIZE, tmpH3);
	if (memcmp(tmpH3, _EngineData->_PeerHashImage3, HASH_IMAGE_SIZE) != 0)
	{
		return false;
	}
	return true;
}

bool zRtpEngine::_SecretsReady(EnableSecurity part)
{
	SRTPSecrets_t sec;

	sec.keyInit = _EngineData->_InitiatorSrtpKey;
	sec.initKeyLen = (_EngineData->_CommitedCipher == SymCipherSupported::Aes128) ? 16 : 32 * 8;
	sec.saltInit = _EngineData->_InitiatorSrtpSalt;
	sec.initSaltLen = 112;

	sec.keyResp = _EngineData->_ResponderSrtpKey;
	sec.respKeyLen = (_EngineData->_CommitedCipher == SymCipherSupported::Aes128) ? 16 : 32 * 8;
	sec.saltResp = _EngineData->_ResponderSrtpSalt;
	sec.respSaltLen = 112;

	sec.srtpAuthTagLen = (_EngineData->_AuthLength == AuthLengthSupported::AuthLen32) ? 32 : 80;

	sec.sas = _EngineData->_SASValue;
	sec.role = _EngineData->_MyRole;

	return _EngineData->_Callback->SecretsReady(&sec, part);
}

void zRtpEngine::_SetSecretsOff(EnableSecurity part)
{
	_EngineData->_Callback->SecretsOff(part);
}

bool zRtpEngine::_CheckZrtpMessageHmac(uint8_t* key)
{
	uint8_t hmac[Sha256::DigestLength];
	uint32_t macLen;
	int32_t len = _EngineData->_LengthMsgData-(HMAC_SIZE);
	Hmac256::Compute(key, HASH_IMAGE_SIZE, _EngineData->_TemporaryMessageBuffer, len, hmac, &macLen);
	return (memcmp(hmac, _EngineData->_TemporaryMessageBuffer+len, (HMAC_SIZE)) == 0 ? true : false);
}

void zRtpEngine::_SetClientIDForZrtpHelloMessage(std::string id)
{
	const char* tmp = "			   ";

	if (id.size() < ZID_SIZE)
	{
		_EngineData->_PacketHello.SetClientID((unsigned char*)tmp);
	}
	_EngineData->_PacketHello.SetClientID((unsigned char*)id.c_str());
	int32_t len = _EngineData->_PacketHello.GetLength() * ZRTP_WORD_SIZE;

	uint8_t hmac[Sha256::DigestLength];
	uint32_t macLen;
	Hmac256::Compute(_EngineData->_HashImage2, HASH_IMAGE_SIZE, (uint8_t*)_EngineData->_PacketHello.GetHeaderBase(),
		len-(2*ZRTP_WORD_SIZE), hmac, &macLen);
	_EngineData->_PacketHello.SetHMAC(hmac);

	Sha256::Compute((uint8_t*)_EngineData->_PacketHello.GetHeaderBase(), len, _EngineData->_HashHello);
}

bool zRtpEngine::_CheckIsMultiStreamModeOffered(zHello *hello)
{
	int	 i;
	int num = hello->GetNumPubKeys();

	if (num == 0)
	{
		return true;
	}
	for (i = 0; i < num; i++)
	{
		if (strcmp((const char*)hello->GetPubKeyType(i), PubKeySupported::ToString(PubKeySupported::Dh3072)) == 0)
		{
			return true;
		}
	}
	return false;
}

void zRtpEngine::_ComputeHviValue(zDHPart* zDH, zHello *hello)
{
	unsigned char* data[3];
	unsigned int length[3];

	data[0] = (uint8_t*)zDH->GetHeaderBase();
	length[0] = zDH->GetLength() * ZRTP_WORD_SIZE;

	data[1] = (uint8_t*)hello->GetHeaderBase();
	length[1] = hello->GetLength() * ZRTP_WORD_SIZE;

	data[2] = NULL;			   	Sha256::Compute(data, length, _EngineData->_MyOwnHVI);
	return;
}

void zRtpEngine:: _ComputeSharedSecret(zRecord &zidRec)
{
	uint8_t randBuf[ZRECORD_RS_LENGTH];
	uint32_t macLen;

	if (!zidRec.IsRs1Valid())
	{
		GenerateRandomZrtpBytes(randBuf, ZRECORD_RS_LENGTH);
		Hmac256::Compute(randBuf, ZRECORD_RS_LENGTH, (unsigned char*)initiator, strlen(initiator), _EngineData->_Initiator1ID, &macLen);
		Hmac256::Compute(randBuf, ZRECORD_RS_LENGTH, (unsigned char*)responder, strlen(responder), _EngineData->_Responder1ID, &macLen);
	}
	else
	{
		_EngineData->_RS1Valid = true;
		Hmac256::Compute((unsigned char*)zidRec.GetRs1(), ZRECORD_RS_LENGTH, (unsigned char*)initiator, strlen(initiator), _EngineData->_Initiator1ID, &macLen);
		Hmac256::Compute((unsigned char*)zidRec.GetRs1(), ZRECORD_RS_LENGTH, (unsigned char*)responder, strlen(responder), _EngineData->_Responder1ID, &macLen);
	}

	if (!zidRec.IsRs2Valid())
	{
		GenerateRandomZrtpBytes(randBuf, ZRECORD_RS_LENGTH);
		Hmac256::Compute(randBuf, ZRECORD_RS_LENGTH, (unsigned char*)initiator, strlen(initiator), _EngineData->_Initiator2ID, &macLen);
		Hmac256::Compute(randBuf, ZRECORD_RS_LENGTH, (unsigned char*)responder, strlen(responder), _EngineData->_Responder2ID, &macLen);
	}
	else
	{
		_EngineData->_RS2Valid = true;
		Hmac256::Compute((unsigned char*)zidRec.GetRs2(), ZRECORD_RS_LENGTH, (unsigned char*)initiator, strlen(initiator), _EngineData->_Initiator2ID, &macLen);
		Hmac256::Compute((unsigned char*)zidRec.GetRs2(), ZRECORD_RS_LENGTH, (unsigned char*)responder, strlen(responder), _EngineData->_Responder2ID, &macLen);
	}


	GenerateRandomZrtpBytes(randBuf, ZRECORD_RS_LENGTH);
	Hmac256::Compute(randBuf, ZRECORD_RS_LENGTH, (unsigned char*)initiator, strlen(initiator), _EngineData->_InitiatorAuxSecretID, &macLen);
	Hmac256::Compute(randBuf, ZRECORD_RS_LENGTH, (unsigned char*)responder, strlen(responder), _EngineData->_ResponderAuxSecretID, &macLen);

	GenerateRandomZrtpBytes(randBuf, ZRECORD_RS_LENGTH);
	Hmac256::Compute(randBuf, ZRECORD_RS_LENGTH, (unsigned char*)initiator, strlen(initiator), _EngineData->_InitiatorPbxSecretID, &macLen);
	Hmac256::Compute(randBuf, ZRECORD_RS_LENGTH, (unsigned char*)responder, strlen(responder), _EngineData->_ResponderPbxSecretID, &macLen);
}

void zRtpEngine::_ComputeSRTPKeys()
{
	uint8_t KDFcontext[sizeof(_EngineData->_OtherEndpointZidData)+sizeof(_EngineData->_MyOwnZidData)+sizeof(_EngineData->_HashMessage)];
	int32_t kdfSize = sizeof(_EngineData->_OtherEndpointZidData)+sizeof(_EngineData->_MyOwnZidData)+Sha256::DigestLength;

	int32_t keyLen = (_EngineData->_CommitedCipher == SymCipherSupported::Aes128) ? 16 : 32 * 8;

	if (_EngineData->_MyRole == Responder)
	{
		memcpy(KDFcontext, _EngineData->_OtherEndpointZidData, sizeof(_EngineData->_OtherEndpointZidData));
		memcpy(KDFcontext+sizeof(_EngineData->_OtherEndpointZidData), _EngineData->_MyOwnZidData, sizeof(_EngineData->_MyOwnZidData));
	}
	else
	{
		memcpy(KDFcontext, _EngineData->_MyOwnZidData, sizeof(_EngineData->_MyOwnZidData));
		memcpy(KDFcontext+sizeof(_EngineData->_MyOwnZidData), _EngineData->_OtherEndpointZidData, sizeof(_EngineData->_OtherEndpointZidData));
	}
	memcpy(KDFcontext+sizeof(_EngineData->_MyOwnZidData)+sizeof(_EngineData->_OtherEndpointZidData), _EngineData->_HashMessage, Sha256::DigestLength);

	__ComputeKey(_EngineData->_S0, Sha256::DigestLength, (unsigned char*)iniMasterKey, strlen(iniMasterKey)+1, KDFcontext, kdfSize, keyLen, _EngineData->_InitiatorSrtpKey);
	__ComputeKey(_EngineData->_S0, Sha256::DigestLength, (unsigned char*)iniMasterSalt, strlen(iniMasterSalt)+1, KDFcontext, kdfSize, 112, _EngineData->_InitiatorSrtpSalt);

	__ComputeKey(_EngineData->_S0, Sha256::DigestLength, (unsigned char*)resMasterKey, strlen(resMasterKey)+1, KDFcontext, kdfSize, keyLen, _EngineData->_ResponderSrtpKey);
	__ComputeKey(_EngineData->_S0, Sha256::DigestLength, (unsigned char*)resMasterSalt, strlen(resMasterSalt)+1, KDFcontext, kdfSize, 112, _EngineData->_ResponderSrtpSalt);

	__ComputeKey(_EngineData->_S0, Sha256::DigestLength, (unsigned char*)iniHmacKey, strlen(iniHmacKey)+1, KDFcontext, kdfSize, Sha256::DigestLength*8, _EngineData->_InitiatorHmacKey);

	__ComputeKey(_EngineData->_S0, Sha256::DigestLength, (unsigned char*)resHmacKey, strlen(resHmacKey)+1, KDFcontext, kdfSize, Sha256::DigestLength*8, _EngineData->_ResponderHmacKey);

	__ComputeKey(_EngineData->_S0, Sha256::DigestLength, (unsigned char*)iniZrtpKey, strlen(iniZrtpKey)+1, KDFcontext, kdfSize, keyLen, _EngineData->_InitiatorConfirmZrtpKey);
	__ComputeKey(_EngineData->_S0, Sha256::DigestLength, (unsigned char*)resZrtpKey, strlen(resZrtpKey)+1, KDFcontext, kdfSize, keyLen, _EngineData->_ResponderConfirmZrtpKey);

	if (!_EngineData->_MultiStream)
	{
		__ComputeKey(_EngineData->_S0, Sha256::DigestLength, (unsigned char*)retainedSec, strlen(retainedSec)+1, KDFcontext, kdfSize, Sha256::DigestLength*8, _EngineData->_NewRS1);

		__ComputeKey(_EngineData->_S0, Sha256::DigestLength, (unsigned char*)zrtpSessKey, strlen(zrtpSessKey)+1, KDFcontext, kdfSize, Sha256::DigestLength*8, _EngineData->_ZrtpSessionKey);

		uint8_t sasBytes[4];
		__ComputeKey(_EngineData->_S0, Sha256::DigestLength, (unsigned char*)sasString, strlen(sasString)+1, KDFcontext, kdfSize, Sha256::DigestLength*8, _EngineData->_SASHashForSignaling);

		sasBytes[0] = _EngineData->_SASHashForSignaling[0];
		sasBytes[1] = _EngineData->_SASHashForSignaling[1];
		sasBytes[2] = _EngineData->_SASHashForSignaling[2] & 0xf0;
		sasBytes[3] = 0;
		_EngineData->_SASValue = Base32(sasBytes, 20).GetEncoded();
	}
	memset(KDFcontext, 0, sizeof(KDFcontext));
}

void zRtpEngine::_GenerateInitiatorKeys(zDHPart *dhPart, zRecord& zidRec)
{
	const uint8_t* setD[3];
	int32_t rsFound = 0;

	setD[0] = setD[1] = setD[2] = NULL;

	int matchingSecrets = 0;
	if (memcmp(_EngineData->_Responder1ID, dhPart->GetRs1ID(), HMAC_SIZE) == 0)
	{
		setD[matchingSecrets++] = zidRec.GetRs1();
		rsFound = 0x1;
	}
	else if (memcmp(_EngineData->_Responder1ID, dhPart->GetRs2ID(), HMAC_SIZE) == 0)
	{
		setD[matchingSecrets++] = zidRec.GetRs1();
		rsFound = 0x2;
	}
	else if (memcmp(_EngineData->_Responder2ID, dhPart->GetRs1ID(), HMAC_SIZE) == 0)
	{
		setD[matchingSecrets++] = zidRec.GetRs2();
		rsFound = 0x4;
	}
	else if (memcmp(_EngineData->_Responder2ID, dhPart->GetRs2ID(), HMAC_SIZE) == 0)
	{
		setD[matchingSecrets++] = zidRec.GetRs2();
		rsFound = 0x8;
	}

	if (rsFound == 0)
	{
		if (_EngineData->_RS1Valid || _EngineData->_RS2Valid)
		{
			_SendInformationMessageToHost(zCodes::MsgLevelWarning, zCodes::WarningNoExpectedRSMatch);
			zidRec.ResetSASVerified();
		}
		else
		{
			_SendInformationMessageToHost(zCodes::MsgLevelWarning, zCodes::WarningNoRSMatch);
		}
	}
	else
	{
		_SendInformationMessageToHost(zCodes::MsgLevelInfo, zCodes::InfoRSMatchFound);
	}

	unsigned char* data[13];
	unsigned int   length[13];
	uint32_t pos = 0;
	uint32_t counter, sLen[3];

	counter = 1;
	counter = htonl(counter);
	data[pos] = (unsigned char*)&counter;
	length[pos++] = sizeof(uint32_t);

	data[pos] = _EngineData->_ComputedDHSecret;
	length[pos++] = _EngineData->_ActiveDHContext->GetDhSize();

	data[pos] = (unsigned char*)KDFString;
	length[pos++] = strlen(KDFString);

	data[pos] = _EngineData->_MyOwnZidData;
	length[pos++] = ZID_SIZE;

	data[pos] = _EngineData->_OtherEndpointZidData;
	length[pos++] = ZID_SIZE;

	data[pos] = _EngineData->_HashMessage;
	length[pos++] = Sha256::DigestLength;

	int secretHashLen = ZRECORD_RS_LENGTH;
	secretHashLen = htonl(secretHashLen);
	for (int32_t i = 0; i < 3; i++)
	{
		if (setD[i] != NULL) {			 			sLen[i] = secretHashLen;
		data[pos] = (unsigned char*)&sLen[i];
		length[pos++] = sizeof(uint32_t);
		data[pos] = (unsigned char*)setD[i];
		length[pos++] = ZRECORD_RS_LENGTH;
		}
		else {							 			sLen[i] = 0;
		data[pos] = (unsigned char*)&sLen[i];
		length[pos++] = sizeof(uint32_t);
		}
	}

	data[pos] = NULL;
	Sha256::Compute(data, length, _EngineData->_S0);

	memset(_EngineData->_ComputedDHSecret, 0, _EngineData->_ActiveDHContext->GetDhSize());
	delete _EngineData->_ComputedDHSecret;
	_EngineData->_ComputedDHSecret = NULL;

	_ComputeSRTPKeys();
	memset(_EngineData->_S0, 0, Sha256::DigestLength);
}

void zRtpEngine::_GenerateResponderKeys(zDHPart *dhPart, zRecord& zidRec)
{
	const uint8_t* setD[3];
	int32_t rsFound = 0;

	setD[0] = setD[1] = setD[2] = NULL;


	int matchingSecrets = 0;
	if (memcmp(_EngineData->_Initiator1ID, dhPart->GetRs1ID(), HMAC_SIZE) == 0)
	{
		setD[matchingSecrets++] = zidRec.GetRs1();
		rsFound = 0x1;
	}
	else if (memcmp(_EngineData->_Initiator1ID, dhPart->GetRs2ID(), HMAC_SIZE) == 0)
	{
		setD[matchingSecrets++] = zidRec.GetRs1();
		rsFound = 0x2;
	}
	else if (memcmp(_EngineData->_Initiator2ID, dhPart->GetRs2ID(), HMAC_SIZE) == 0)
	{
		setD[matchingSecrets++] = zidRec.GetRs2();
		rsFound |= 0x4;
	}
	else if (memcmp(_EngineData->_Initiator2ID, dhPart->GetRs1ID(), HMAC_SIZE) == 0)
	{
		setD[matchingSecrets++] = zidRec.GetRs2();
		rsFound |= 0x8;
	}

	if (rsFound == 0)
	{
		if (_EngineData->_RS1Valid || _EngineData->_RS2Valid)
		{
			_SendInformationMessageToHost(zCodes::MsgLevelWarning, zCodes::WarningNoExpectedRSMatch);
			zidRec.ResetSASVerified();
		}
		else
		{
			_SendInformationMessageToHost(zCodes::MsgLevelWarning, zCodes::WarningNoRSMatch);
		}
	}
	else
	{
		_SendInformationMessageToHost(zCodes::MsgLevelInfo, zCodes::InfoRSMatchFound);
	}

	unsigned char* data[13];
	unsigned int   length[13];
	uint32_t pos = 0;
	uint32_t counter, sLen[3];

	counter = 1;
	counter = htonl(counter);
	data[pos] = (unsigned char*)&counter;
	length[pos++] = sizeof(uint32_t);

	data[pos] = _EngineData->_ComputedDHSecret;
	length[pos++] = _EngineData->_ActiveDHContext->GetDhSize();

	data[pos] = (unsigned char*)KDFString;
	length[pos++] = strlen(KDFString);

	data[pos] = _EngineData->_OtherEndpointZidData;
	length[pos++] = ZID_SIZE;

	data[pos] = _EngineData->_MyOwnZidData;
	length[pos++] = ZID_SIZE;

	data[pos] = _EngineData->_HashMessage;
	length[pos++] = Sha256::DigestLength;


	int secretHashLen = ZRECORD_RS_LENGTH;
	secretHashLen = htonl(secretHashLen);
	for (int32_t i = 0; i < 3; i++)
	{
		if (setD[i] != NULL)
		{
			sLen[i] = secretHashLen;
			data[pos] = (unsigned char*)&sLen[i];
			length[pos++] = sizeof(uint32_t);
			data[pos] = (unsigned char*)setD[i];
			length[pos++] = ZRECORD_RS_LENGTH;
		}
		else
		{
			sLen[i] = 0;
			data[pos] = (unsigned char*)&sLen[i];
			length[pos++] = sizeof(uint32_t);
		}
	}

	data[pos] = NULL;
	Sha256::Compute(data, length, _EngineData->_S0);

	memset(_EngineData->_ComputedDHSecret, 0, _EngineData->_ActiveDHContext->GetDhSize());
	delete _EngineData->_ComputedDHSecret;
	_EngineData->_ComputedDHSecret = NULL;

	_ComputeSRTPKeys();
	memset(_EngineData->_S0, 0, Sha256::DigestLength);
}

void zRtpEngine::_GenerateMultiStreamKeys()
{
	uint8_t KDFcontext[sizeof(_EngineData->_OtherEndpointZidData)+sizeof(_EngineData->_MyOwnZidData)+sizeof(_EngineData->_HashMessage)];
	int32_t kdfSize = sizeof(_EngineData->_OtherEndpointZidData)+sizeof(_EngineData->_MyOwnZidData)+Sha256::DigestLength;

	if (_EngineData->_MyRole == Responder)
	{
		memcpy(KDFcontext, _EngineData->_OtherEndpointZidData, sizeof(_EngineData->_OtherEndpointZidData));
		memcpy(KDFcontext+sizeof(_EngineData->_OtherEndpointZidData), _EngineData->_MyOwnZidData, sizeof(_EngineData->_MyOwnZidData));
	}
	else
	{
		memcpy(KDFcontext, _EngineData->_MyOwnZidData, sizeof(_EngineData->_MyOwnZidData));
		memcpy(KDFcontext+sizeof(_EngineData->_MyOwnZidData), _EngineData->_OtherEndpointZidData, sizeof(_EngineData->_OtherEndpointZidData));
	}
	memcpy(KDFcontext+sizeof(_EngineData->_MyOwnZidData)+sizeof(_EngineData->_OtherEndpointZidData), _EngineData->_HashMessage, Sha256::DigestLength);

	__ComputeKey(_EngineData->_ZrtpSessionKey, Sha256::DigestLength, (unsigned char*)zrtpMsk, strlen(zrtpMsk)+1,
		KDFcontext, kdfSize, Sha256::DigestLength*8, _EngineData->_S0);

	memset(KDFcontext, 0, sizeof(KDFcontext));

	_ComputeSRTPKeys();
}

zHello* zRtpEngine::_MakeHelloPacket()
{
	return &_EngineData->_PacketHello;
}

zHelloAck* zRtpEngine::_MakeHelloAckPacket()
{
	return &_EngineData->_PacketHelloAck;
}

zCommit* zRtpEngine::_MakeCommitPacket(zHello *hello, uint32_t* errMsg)
{
	_SendInformationMessageToHost(zCodes::MsgLevelInfo, zCodes::InfoHelloReceive);

	if (memcmp(hello->GetVersion(), zrtpVersion, ZRTP_WORD_SIZE-1) != 0)
	{
		*errMsg = zCodes::UnsupportedZrtpVersion;
		return NULL;
	}
	memcpy(_EngineData->_OtherEndpointZidData, hello->GetZID(), ZID_SIZE);
	if (memcmp(_EngineData->_OtherEndpointZidData, _EngineData->_MyOwnZidData, ZID_SIZE) == 0)
	{
		*errMsg = zCodes::EqualZidsInHello;
		return NULL;
	}
	memcpy(_EngineData->_PeerHashImage3, hello->GetH3(), HASH_IMAGE_SIZE);

	_EngineData->_SASType = _SearchSASAlgo(hello);

	if (!_EngineData->_MultiStream)
	{
		_EngineData->_AuthLength = _SearchAuthentificationLength(hello);
		_EngineData->_CommitedPublicKey = _SearchPublicKeyAlgo(hello);
		_EngineData->_CommitedCipher = _SearchCipherAlgo(hello, _EngineData->_CommitedPublicKey);
		_EngineData->_CommitedHash = _SearchHashAlgo(hello);
		_EngineData->_MultiStreamAvailable = _CheckIsMultiStreamModeOffered(hello);
	}
	else
	{
		if (_CheckIsMultiStreamModeOffered(hello))
		{
			return _MakeCommitPacketForMultistreamMode(hello);
		}
		else
		{
			*errMsg = zCodes::UnsupportedPublicKeyExchange;
			return NULL;
		}
	}

	_EngineData->_ActiveDHContext = new zDH(_EngineData->_CommitedPublicKey);
	_EngineData->_ActiveDHContext->GeneratePubKey();

	_EngineData->_ActiveDHContext->GetPubKeyBytes(_EngineData->_MyComputedPublicKeyBytes);
	_SendInformationMessageToHost(zCodes::MsgLevelInfo, zCodes::InfoCommitDHGenerate);

	GenerateRandomZrtpBytes(_EngineData->_RandomInitialVector, sizeof(_EngineData->_RandomInitialVector));


	zRecord zidRec(_EngineData->_OtherEndpointZidData);
	zEndpointInfo *zidFile = zEndpointInfo::Instance();
	zidFile->GetRecord(&zidRec);

	_ComputeSharedSecret(zidRec);


	_EngineData->_PacketDHPart2.SetPubKeyType(_EngineData->_CommitedPublicKey);
	_EngineData->_PacketDHPart2.SetMsgType((uint8_t*)DHPart2Msg);
	_EngineData->_PacketDHPart2.SetRs1ID(_EngineData->_Initiator1ID);
	_EngineData->_PacketDHPart2.SetRs2ID(_EngineData->_Initiator2ID);
	_EngineData->_PacketDHPart2.SetAUXSecretID(_EngineData->_InitiatorAuxSecretID);
	_EngineData->_PacketDHPart2.SetPBXSecretID(_EngineData->_InitiatorPbxSecretID);
	_EngineData->_PacketDHPart2.SetPv(_EngineData->_MyComputedPublicKeyBytes);
	_EngineData->_PacketDHPart2.SetH1(_EngineData->_HashImage1);

	int32_t len = _EngineData->_PacketDHPart2.GetLength() * ZRTP_WORD_SIZE;

	uint8_t hmac[Sha256::DigestLength];
	uint32_t macLen;
	Hmac256::Compute(_EngineData->_HashImage0, HASH_IMAGE_SIZE, (uint8_t*)_EngineData->_PacketDHPart2.GetHeaderBase(),
		len-(HMAC_SIZE), hmac, &macLen);
	_EngineData->_PacketDHPart2.SetHMAC(hmac);

	_ComputeHviValue(&_EngineData->_PacketDHPart2, hello);

	_EngineData->_PacketCommit.SetZID(_EngineData->_MyOwnZidData);
	_EngineData->_PacketCommit.SetHashType((uint8_t*)HashSupported::ToString(_EngineData->_CommitedHash));
	_EngineData->_PacketCommit.SetCipherType((uint8_t*)SymCipherSupported::ToString(_EngineData->_CommitedCipher));
	_EngineData->_PacketCommit.SetAuthLen((uint8_t*)AuthLengthSupported::ToString(_EngineData->_AuthLength));
	_EngineData->_PacketCommit.SetPubKeyType((uint8_t*)PubKeySupported::ToString(_EngineData->_CommitedPublicKey));
	_EngineData->_PacketCommit.SetSasType((uint8_t*)SASTypeSupported::ToString(_EngineData->_SASType));
	_EngineData->_PacketCommit.SetHvi(_EngineData->_MyOwnHVI);
	_EngineData->_PacketCommit.SetH2(_EngineData->_HashImage2);

	len = _EngineData->_PacketCommit.GetLength() * ZRTP_WORD_SIZE;

	Hmac256::Compute(_EngineData->_HashImage1, HASH_IMAGE_SIZE, (uint8_t*)_EngineData->_PacketCommit.GetHeaderBase(),
		len-(HMAC_SIZE), hmac, &macLen);
	_EngineData->_PacketCommit.SetHMAC(hmac);

	_EngineData->_MessageSHAContext = Sha256::CreateSha256Context();
	Sha256::UpdateShaContext(_EngineData->_MessageSHAContext, (unsigned char*)hello->GetHeaderBase(), hello->GetLength() * ZRTP_WORD_SIZE);
	Sha256::UpdateShaContext(_EngineData->_MessageSHAContext, (unsigned char*)_EngineData->_PacketCommit.GetHeaderBase(), len);

	_StoreZrtpMessageInTempBuffer(hello);
	return &_EngineData->_PacketCommit;
}

zCommit* zRtpEngine::_MakeCommitPacketForMultistreamMode(zHello *hello)
{
	GenerateRandomZrtpBytes(_EngineData->_MyOwnHVI, ZRTP_WORD_SIZE*4);
	_EngineData->_PacketCommit.SetZID(_EngineData->_MyOwnZidData);
	_EngineData->_PacketCommit.SetHashType((uint8_t*)HashSupported::ToString(_EngineData->_CommitedHash));
	_EngineData->_PacketCommit.SetCipherType((uint8_t*)SymCipherSupported::ToString(_EngineData->_CommitedCipher));
	_EngineData->_PacketCommit.SetAuthLen((uint8_t*)AuthLengthSupported::ToString(_EngineData->_AuthLength));
	_EngineData->_PacketCommit.SetPubKeyType((uint8_t*)"Mult");	 	_EngineData->_PacketCommit.SetSasType((uint8_t*)SASTypeSupported::ToString(_EngineData->_SASType));
	_EngineData->_PacketCommit.SetNonce(_EngineData->_MyOwnHVI);
	_EngineData->_PacketCommit.SetH2(_EngineData->_HashImage2);

	int32_t len = _EngineData->_PacketCommit.GetLength() * ZRTP_WORD_SIZE;

	uint8_t hmac[Sha256::DigestLength];
	uint32_t macLen;
	Hmac256::Compute(_EngineData->_HashImage1, HASH_IMAGE_SIZE, (uint8_t*)_EngineData->_PacketCommit.GetHeaderBase(),
		len-(HMAC_SIZE), hmac, &macLen);
	_EngineData->_PacketCommit.SetHMACMulti(hmac);

	_EngineData->_MessageSHAContext = Sha256::CreateSha256Context();

	Sha256::UpdateShaContext(_EngineData->_MessageSHAContext, (unsigned char*)hello->GetHeaderBase(), hello->GetLength() * ZRTP_WORD_SIZE);
	Sha256::UpdateShaContext(_EngineData->_MessageSHAContext, (unsigned char*)_EngineData->_PacketCommit.GetHeaderBase(), len);

	_StoreZrtpMessageInTempBuffer(hello);
	return &_EngineData->_PacketCommit;
}

zDHPart* zRtpEngine::_MakeDHPart1Packet(zCommit *commit, uint32_t* errMsg)
{
	int i;

	_SendInformationMessageToHost(zCodes::MsgLevelInfo, zCodes::InfoRespCommitReceive);

	uint8_t tmpH3[Sha256::DigestLength];
	memcpy(_EngineData->_PeerHashImage2, commit->GetH2(), HASH_IMAGE_SIZE);
	Sha256::Compute(_EngineData->_PeerHashImage2, HASH_IMAGE_SIZE, tmpH3);

	if (memcmp(tmpH3, _EngineData->_PeerHashImage3, HASH_IMAGE_SIZE) != 0)
	{
		*errMsg = zCodes::IgnorePacket;
		return NULL;
	}

	if (!_CheckZrtpMessageHmac(_EngineData->_PeerHashImage2))
	{
		_SendInformationMessageToHost(zCodes::MsgLevelFatal, zCodes::FatalHelloHMAC);
		*errMsg = zCodes::CriticalSoftwareError;
		return NULL;
	}

	uint32_t cipherType = *(uint32_t*)commit->GetCipherType();
	for (i=0; i < SymCipherSupported::EndOfEnum; i++)
	{
		if(cipherType == *(uint32_t*)SymCipherSupported::ToString(i))
		{
			break;
		}
	}
	if(i >= SymCipherSupported::EndOfEnum)
	{
		*errMsg = zCodes::UnsupportedCipherType;
		return NULL;
	}
	_EngineData->_CommitedCipher = (SymCipherSupported::Enum)i;

	uint32_t authLen = *(uint32_t*)commit->GetAuthLen();
	for(i = 0; i < AuthLengthSupported::EndOfEnum; i++)
	{
		if(authLen == *(uint32_t*)AuthLengthSupported::ToString(i))
		{
			break;
		}
	}

	if(i >= AuthLengthSupported::EndOfEnum)
	{
		*errMsg = zCodes::UnsupportedSRTPAuthTag;
		return NULL;
	}
	authLen = (AuthLengthSupported::Enum)i;

	uint32_t hashType = *(uint32_t*)commit->GetHashType();
	for(i = 0; i < HashSupported::EndOfEnum; i++)
	{
		if(hashType == *(uint32_t*)HashSupported::ToString(i))
		{
			break;
		}
	}
	if(i >= HashSupported::EndOfEnum)
	{
		*errMsg = zCodes::UnsupportedHashType;
		return NULL;
	}
	if (_EngineData->_CommitedHash != (HashSupported::Enum)i)
	{
		_EngineData->_CommitedHash = (HashSupported::Enum)i;

		zRecord zidRec(_EngineData->_OtherEndpointZidData);
		zEndpointInfo *zidFile = zEndpointInfo::Instance();
		zidFile->GetRecord(&zidRec);

		_ComputeSharedSecret(zidRec);
	}

	uint32_t pubKeyType = *(uint32_t*)commit->GetPubKeysType();
	for(i = 0; i < PubKeySupported::EndOfEnum; i++)
	{
		if(pubKeyType == *(uint32_t*)PubKeySupported::ToString(i))
		{
			break;
		}
	}
	if(i >= PubKeySupported::EndOfEnum)
	{
		*errMsg = zCodes::UnsupportedPublicKeyExchange;
		return NULL;
	}
	_EngineData->_CommitedPublicKey = (PubKeySupported::Enum)i;

	uint32_t sasTypeVariable =*(uint32_t*)commit->GetSasType();
	for(i = 0;i < SASTypeSupported::EndOfEnum; i++)
	{
		if(sasTypeVariable == *(uint32_t*)SASTypeSupported::ToString(i))
		{
			break;
		}
		else
		{
			printf("\n SAS Type mismatch input = %s matching to = %s",commit->GetSasType(), SASTypeSupported::ToString(i));
		}
	}
	if ( i >= SASTypeSupported::EndOfEnum )
	{
		*errMsg = zCodes::UnsupportedSASRenderScheme;
		return NULL;
	}
	_EngineData->_SASType = (SASTypeSupported::Enum)i;

	if (*(int32_t*)(PubKeySupported::ToString(_EngineData->_ActiveDHContext->getDHtype())) != *(int32_t*)(PubKeySupported::ToString(_EngineData->_CommitedPublicKey)))
	{
		delete _EngineData->_ActiveDHContext;
		_EngineData->_ActiveDHContext = new zDH(_EngineData->_CommitedPublicKey);
		_EngineData->_ActiveDHContext->GeneratePubKey();
	}
	_SendInformationMessageToHost(zCodes::MsgLevelInfo, zCodes::InfoDH1DHGenerate);

	_EngineData->_ActiveDHContext->GetPubKeyBytes(_EngineData->_MyComputedPublicKeyBytes);

	_EngineData->_PacketDHPart1.SetPubKeyType(_EngineData->_CommitedPublicKey);
	_EngineData->_PacketDHPart1.SetMsgType((uint8_t*)DHPart1Msg);
	_EngineData->_PacketDHPart1.SetRs1ID(_EngineData->_Responder1ID);
	_EngineData->_PacketDHPart1.SetRs2ID(_EngineData->_Responder2ID);
	_EngineData->_PacketDHPart1.SetAUXSecretID(_EngineData->_ResponderAuxSecretID);
	_EngineData->_PacketDHPart1.SetPBXSecretID(_EngineData->_ResponderPbxSecretID);
	_EngineData->_PacketDHPart1.SetPv(_EngineData->_MyComputedPublicKeyBytes);
	_EngineData->_PacketDHPart1.SetH1(_EngineData->_HashImage1);

	int32_t len = _EngineData->_PacketDHPart1.GetLength() * ZRTP_WORD_SIZE;

	uint8_t hmac[Sha256::DigestLength];
	uint32_t macLen;
	Hmac256::Compute(_EngineData->_HashImage0, HASH_IMAGE_SIZE, (uint8_t*)_EngineData->_PacketDHPart1.GetHeaderBase(),
		len-(HMAC_SIZE), hmac, &macLen);
	_EngineData->_PacketDHPart1.SetHMAC(hmac);

	_EngineData->_MyRole = Responder;
	memcpy(_EngineData->_OtherEndpointHVI, commit->GetHvi(), HVI_SIZE);

	if (_EngineData->_MessageSHAContext != NULL)
	{
		Sha256::CloseSha256Context(_EngineData->_MessageSHAContext, NULL);
	}
	_EngineData->_MessageSHAContext = Sha256::CreateSha256Context();

	Sha256::UpdateShaContext(_EngineData->_MessageSHAContext, (unsigned char*)_EngineData->_PacketHello.GetHeaderBase(),
		_EngineData->_PacketHello.GetLength() * ZRTP_WORD_SIZE);
	Sha256::UpdateShaContext(_EngineData->_MessageSHAContext, (unsigned char*)commit->GetHeaderBase(),
		commit->GetLength() * ZRTP_WORD_SIZE);
	Sha256::UpdateShaContext(_EngineData->_MessageSHAContext, (unsigned char*)_EngineData->_PacketDHPart1.GetHeaderBase(),
		_EngineData->_PacketDHPart1.GetLength() * ZRTP_WORD_SIZE);

	_StoreZrtpMessageInTempBuffer(commit);

	return &_EngineData->_PacketDHPart1;
}

zDHPart* zRtpEngine::_MakeDHPart2Packet(zDHPart *dhPart1, uint32_t* errMsg)
{
	uint8_t* pvr;

	_SendInformationMessageToHost(zCodes::MsgLevelInfo, zCodes::InfoInitDH1Receive);

	uint8_t tmpHash[Sha256::DigestLength];
	Sha256::Compute(dhPart1->GetH1(), HASH_IMAGE_SIZE, tmpHash);
	memcpy(_EngineData->_PeerHashImage2, tmpHash, HASH_IMAGE_SIZE);
	Sha256::Compute(_EngineData->_PeerHashImage2, HASH_IMAGE_SIZE, tmpHash);
	if (memcmp(tmpHash, _EngineData->_PeerHashImage3, HASH_IMAGE_SIZE) != 0)
	{
		*errMsg = zCodes::IgnorePacket;
		return NULL;
	}

	if (!_CheckZrtpMessageHmac(_EngineData->_PeerHashImage2))
	{
		_SendInformationMessageToHost(zCodes::MsgLevelFatal, zCodes::FatalHelloHMAC);
		*errMsg = zCodes::CriticalSoftwareError;
		return NULL;
	}

	_EngineData->_ComputedDHSecret = new uint8_t[_EngineData->_ActiveDHContext->GetDhSize()];
	if (_EngineData->_ComputedDHSecret == NULL)
	{
		*errMsg = zCodes::CriticalSoftwareError;
		return NULL;
	}

	pvr = dhPart1->GetPv();
	if (!_EngineData->_ActiveDHContext->CheckPubKey(pvr))
	{
		*errMsg = zCodes::BadPviOrPvR;
		return NULL;
	}
	_EngineData->_ActiveDHContext->ComputeSecKey(pvr, _EngineData->_ComputedDHSecret);

	_EngineData->_MyRole = Initiator;

	Sha256::UpdateShaContext(_EngineData->_MessageSHAContext, (unsigned char*)dhPart1->GetHeaderBase(), dhPart1->GetLength() * ZRTP_WORD_SIZE);
	Sha256::UpdateShaContext(_EngineData->_MessageSHAContext, (unsigned char*)_EngineData->_PacketDHPart2.GetHeaderBase(), _EngineData->_PacketDHPart2.GetLength() * ZRTP_WORD_SIZE);

	Sha256::CloseSha256Context(_EngineData->_MessageSHAContext, _EngineData->_HashMessage);
	_EngineData->_MessageSHAContext = NULL;

	zRecord zidRec(_EngineData->_OtherEndpointZidData);
	zEndpointInfo *zid = zEndpointInfo::Instance();
	zid->GetRecord(&zidRec);

	_GenerateInitiatorKeys(dhPart1, zidRec);
	zid->SaveRecord(&zidRec);

	delete _EngineData->_ActiveDHContext;
	_EngineData->_ActiveDHContext = NULL;

	_StoreZrtpMessageInTempBuffer(dhPart1);
	return &_EngineData->_PacketDHPart2;
}

zConfirm* zRtpEngine::_MakeConfirm1Packet(zDHPart* dhPart2, uint32_t* errMsg)
{
	uint8_t* pvi;

	_SendInformationMessageToHost(zCodes::MsgLevelInfo, zCodes::InfoRespDH2Receive);

	uint8_t tmpHash[Sha256::DigestLength];
	Sha256::Compute(dhPart2->GetH1(), HASH_IMAGE_SIZE, tmpHash);
	if (memcmp(tmpHash, _EngineData->_PeerHashImage2, HASH_IMAGE_SIZE) != 0)
	{
		*errMsg = zCodes::IgnorePacket;
		return NULL;
	}

	if (!_CheckZrtpMessageHmac(dhPart2->GetH1()))
	{
		_SendInformationMessageToHost(zCodes::MsgLevelFatal, zCodes::FatalCommitHMAC);
		*errMsg = zCodes::CriticalSoftwareError;
		return NULL;
	}
	_ComputeHviValue(dhPart2, &_EngineData->_PacketHello);
	if (memcmp(_EngineData->_MyOwnHVI, _EngineData->_OtherEndpointHVI, HVI_SIZE) != 0)
	{
		*errMsg = zCodes::MismatchHviAndHash;
		return NULL;
	}
	_EngineData->_ComputedDHSecret = new uint8_t[_EngineData->_ActiveDHContext->GetDhSize()];
	if (_EngineData->_ComputedDHSecret == NULL)
	{
		*errMsg = zCodes::CriticalSoftwareError;
		return NULL;
	}
	pvi = dhPart2->GetPv();
	if (!_EngineData->_ActiveDHContext->CheckPubKey(pvi))
	{
		*errMsg = zCodes::BadPviOrPvR;
		return NULL;
	}
	_EngineData->_ActiveDHContext->ComputeSecKey(pvi, _EngineData->_ComputedDHSecret);
	Sha256::UpdateShaContext(_EngineData->_MessageSHAContext, (unsigned char*)dhPart2->GetHeaderBase(),
		dhPart2->GetLength() * ZRTP_WORD_SIZE);

	Sha256::CloseSha256Context(_EngineData->_MessageSHAContext, _EngineData->_HashMessage);
	_EngineData->_MessageSHAContext = NULL;

	zRecord zidRec(_EngineData->_OtherEndpointZidData);
	zEndpointInfo *zid = zEndpointInfo::Instance();
	zid->GetRecord(&zidRec);

	_GenerateResponderKeys(dhPart2, zidRec);
	zid->SaveRecord(&zidRec);

	delete _EngineData->_ActiveDHContext;
	_EngineData->_ActiveDHContext = NULL;

	_EngineData->_PacketConfirm1.SetMsgType((uint8_t*)Confirm1Msg);
	_EngineData->_PacketConfirm1.SetSignLength(0);

	if (zidRec.IsSASVerified())
	{
		_EngineData->_PacketConfirm1.SetSASFlag();
	}
	_EngineData->_PacketConfirm1.SetExpTime(0xFFFFFFFF);
	_EngineData->_PacketConfirm1.SetIv(_EngineData->_RandomInitialVector);
	_EngineData->_PacketConfirm1.SetHashH0(_EngineData->_HashImage0);

	uint8_t confMac[Sha256::DigestLength];
	uint32_t macLen;

	int hmlen = (_EngineData->_PacketConfirm1.GetLength() - 9) * ZRTP_WORD_SIZE;
	ZAes::Encrypt(_EngineData->_ResponderConfirmZrtpKey, (_EngineData->_CommitedCipher == SymCipherSupported::Aes128) ? 16 : 32, _EngineData->_RandomInitialVector, _EngineData->_PacketConfirm1.GetHashH0(), hmlen);
	Hmac256::Compute(_EngineData->_ResponderHmacKey, Sha256::DigestLength, (unsigned char*)_EngineData->_PacketConfirm1.GetHashH0(), hmlen, confMac, &macLen);
	_EngineData->_PacketConfirm1.SetHmac(confMac);

	_StoreZrtpMessageInTempBuffer(dhPart2);
	return &_EngineData->_PacketConfirm1;
}

zConfirm* zRtpEngine::_MakeConfirm1PacketForMultistreamMode(zCommit* commit, uint32_t* errMsg)
{
	int i;

	_SendInformationMessageToHost(zCodes::MsgLevelInfo, zCodes::InfoRespCommitReceive);

	uint8_t tmpH3[Sha256::DigestLength];
	memcpy(_EngineData->_PeerHashImage2, commit->GetH2(), HASH_IMAGE_SIZE);
	Sha256::Compute(_EngineData->_PeerHashImage2, HASH_IMAGE_SIZE, tmpH3);

	if (memcmp(tmpH3, _EngineData->_PeerHashImage3, HASH_IMAGE_SIZE) != 0)
	{
		*errMsg = zCodes::IgnorePacket;
		return NULL;
	}

	if (!_CheckZrtpMessageHmac(_EngineData->_PeerHashImage2))
	{
		_SendInformationMessageToHost(zCodes::MsgLevelFatal, zCodes::FatalHelloHMAC);
		*errMsg = zCodes::CriticalSoftwareError;
		return NULL;
	}

	uint32_t pubKeysType = *(uint32_t*)commit->GetPubKeysType();
	if (pubKeysType != *(uint32_t*)PubKeySupported::ToString(PubKeySupported::MultiStream))
	{
		*errMsg = zCodes::UnsupportedPublicKeyExchange;
		return NULL;
	}

	uint32_t cipherType = *(uint32_t*)commit->GetCipherType();
	for (i=0; i < SymCipherSupported::EndOfEnum; i++)
	{
		if(cipherType == *(uint32_t*)SymCipherSupported::ToString(i))
		{
			break;
		}
	}
	if(i >= SymCipherSupported::EndOfEnum)
	{
		*errMsg = zCodes::UnsupportedCipherType;
		return NULL;
	}
	_EngineData->_CommitedCipher = (SymCipherSupported::Enum)i;

	uint32_t authLen = *(uint32_t*)commit->GetAuthLen();
	for(i = 0; i < AuthLengthSupported::EndOfEnum; i++)
	{
		if(authLen == *(uint32_t*)AuthLengthSupported::ToString(i))
		{
			break;
		}
	}
	if(i >= AuthLengthSupported::EndOfEnum)
	{
		*errMsg = zCodes::UnsupportedSRTPAuthTag;
		return NULL;
	}
	authLen = (AuthLengthSupported::Enum)i;

	uint32_t hashType = *(uint32_t*)commit->GetHashType();
	for(i = 0; i < HashSupported::EndOfEnum; i++)
	{
		if(hashType == *(uint32_t*)HashSupported::ToString(i))
		{
			break;
		}
	}
	if(i >= HashSupported::EndOfEnum)
	{
		*errMsg = zCodes::UnsupportedHashType;
		return NULL;
	}
	if (_EngineData->_CommitedHash != (HashSupported::Enum)i)
	{
		_EngineData->_CommitedHash = (HashSupported::Enum)i;
	}
	_EngineData->_MyRole = Responder;

	if (_EngineData->_MessageSHAContext != NULL)
	{
		Sha256::CloseSha256Context(_EngineData->_MessageSHAContext, NULL);
	}
	_EngineData->_MessageSHAContext = Sha256::CreateSha256Context();

	Sha256::UpdateShaContext(_EngineData->_MessageSHAContext, (unsigned char*)_EngineData->_PacketHello.GetHeaderBase(),
		_EngineData->_PacketHello.GetLength() * ZRTP_WORD_SIZE);
	Sha256::UpdateShaContext(_EngineData->_MessageSHAContext, (unsigned char*)commit->GetHeaderBase(),
		commit->GetLength() * ZRTP_WORD_SIZE);

	Sha256::CloseSha256Context(_EngineData->_MessageSHAContext, _EngineData->_HashMessage);
	_EngineData->_MessageSHAContext = NULL;

	_GenerateMultiStreamKeys();

	_EngineData->_PacketConfirm1.SetMsgType((uint8_t*)Confirm1Msg);
	_EngineData->_PacketConfirm1.SetSignLength(0);
	_EngineData->_PacketConfirm1.SetExpTime(0xFFFFFFFF);
	_EngineData->_PacketConfirm1.SetIv(_EngineData->_RandomInitialVector);
	_EngineData->_PacketConfirm1.SetHashH0(_EngineData->_HashImage0);

	uint8_t confMac[Sha256::DigestLength];
	uint32_t macLen;

	int32_t hmlen = (_EngineData->_PacketConfirm1.GetLength() - 9) * ZRTP_WORD_SIZE;
	ZAes::Encrypt(_EngineData->_ResponderConfirmZrtpKey, (_EngineData->_CommitedCipher == SymCipherSupported::Aes128) ? 16 : 32, _EngineData->_RandomInitialVector,
		_EngineData->_PacketConfirm1.GetHashH0(), hmlen);
	Hmac256::Compute(_EngineData->_ResponderHmacKey, Sha256::DigestLength,
		(unsigned char*)_EngineData->_PacketConfirm1.GetHashH0(),
		hmlen, confMac, &macLen);

	_EngineData->_PacketConfirm1.SetHmac(confMac);

	_StoreZrtpMessageInTempBuffer(commit);
	return &_EngineData->_PacketConfirm1;
}

zConfirm* zRtpEngine::_MakeConfirm2Packet(zConfirm* confirm1, uint32_t* errMsg)
{
	_SendInformationMessageToHost(zCodes::MsgLevelInfo, zCodes::InfoInitConf1Receive);

	uint8_t confMac[Sha256::DigestLength];
	uint32_t macLen;

	int16_t hmlen = (confirm1->GetLength() - 9) * ZRTP_WORD_SIZE;

	Hmac256::Compute(_EngineData->_ResponderHmacKey, Sha256::DigestLength,
		(unsigned char*)confirm1->GetHashH0(),
		hmlen, confMac, &macLen);

	if (memcmp(confMac, confirm1->GetHmac(), HMAC_SIZE) != 0)
	{
		*errMsg = zCodes::BadConfirmPktMAC;
		return NULL;
	}
	ZAes::Decrypt (
		_EngineData->_ResponderConfirmZrtpKey,
		(_EngineData->_CommitedCipher == SymCipherSupported::Aes128) ? 16 : 32,
		confirm1->GetIv(),
		confirm1->GetHashH0(),
		hmlen );

	std::string cs(SymCipherSupported::ToString(_EngineData->_CommitedCipher));
	cs.append("/").append(PubKeySupported::ToString(_EngineData->_CommitedPublicKey));

	if (!_CheckZrtpMessageHmac(confirm1->GetHashH0()))
	{
		_SendInformationMessageToHost(zCodes::MsgLevelFatal, zCodes::FatalDH1HMAC);
		*errMsg = zCodes::CriticalSoftwareError;
		return NULL;
	}

	bool sasFlag = confirm1->IsSASFlag();

	zRecord zidRec(_EngineData->_OtherEndpointZidData);

	zEndpointInfo *zid = zEndpointInfo::Instance();
	zid->GetRecord(&zidRec);

	if (!sasFlag)
	{
		zidRec.ResetSASVerified();
	}
	sasFlag = zidRec.IsSASVerified() ? true : false;

	bool sasVerified = zidRec.IsSASVerified();
	_EngineData->_Callback->SecretsOn(cs, _EngineData->_SASValue, sasVerified);

	zidRec.SetNewRs1Value((const uint8_t*)_EngineData->_NewRS1);
	zid->SaveRecord(&zidRec);

	_EngineData->_PacketConfirm2.SetMsgType((uint8_t*)Confirm2Msg);
	_EngineData->_PacketConfirm2.SetSignLength(0);
	_EngineData->_PacketConfirm2.SetHashH0(_EngineData->_HashImage0);

	if (sasFlag)
	{
		_EngineData->_PacketConfirm2.SetSASFlag();
	}
	_EngineData->_PacketConfirm2.SetExpTime(0xFFFFFFFF);
	_EngineData->_PacketConfirm2.SetIv(_EngineData->_RandomInitialVector);

	hmlen = (_EngineData->_PacketConfirm2.GetLength() - 9) * ZRTP_WORD_SIZE;
	ZAes::Encrypt(_EngineData->_InitiatorConfirmZrtpKey, (_EngineData->_CommitedCipher == SymCipherSupported::Aes128) ? 16 : 32, _EngineData->_RandomInitialVector,
		_EngineData->_PacketConfirm2.GetHashH0(), hmlen);
	Hmac256::Compute(_EngineData->_InitiatorHmacKey, Sha256::DigestLength,
		(unsigned char*)_EngineData->_PacketConfirm2.GetHashH0(),
		hmlen, confMac, &macLen);

	_EngineData->_PacketConfirm2.SetHmac(confMac);

	return &_EngineData->_PacketConfirm2;
}

zConfirm* zRtpEngine::_MakeConfirm2PacketForMultistreamMode(zConfirm* confirm1, uint32_t* errMsg)
{
	_SendInformationMessageToHost(zCodes::MsgLevelInfo, zCodes::InfoInitConf1Receive);

	uint8_t confMac[Sha256::DigestLength];
	uint32_t macLen;

	Sha256::CloseSha256Context(_EngineData->_MessageSHAContext, _EngineData->_HashMessage);
	_EngineData->_MessageSHAContext = NULL;
	_EngineData->_MyRole = Initiator;

	_GenerateMultiStreamKeys();

	int32_t hmlen = (confirm1->GetLength() - 9) * ZRTP_WORD_SIZE;

	Hmac256::Compute(_EngineData->_ResponderHmacKey, Sha256::DigestLength,
		(unsigned char*)confirm1->GetHashH0(),
		hmlen, confMac, &macLen);

	if (memcmp(confMac, confirm1->GetHmac(), HMAC_SIZE) != 0)
	{
		*errMsg = zCodes::BadConfirmPktMAC;
		return NULL;
	}
	ZAes::Decrypt(_EngineData->_ResponderConfirmZrtpKey, (_EngineData->_CommitedCipher == SymCipherSupported::Aes128) ? 16 : 32,
		confirm1->GetIv(),
		confirm1->GetHashH0(), hmlen);
	std::string cs(SymCipherSupported::ToString(_EngineData->_CommitedCipher));

	uint8_t tmpHash[Sha256::DigestLength];
	Sha256::Compute(confirm1->GetHashH0(), HASH_IMAGE_SIZE, tmpHash);
	Sha256::Compute(tmpHash, HASH_IMAGE_SIZE, tmpHash);
	memcpy(_EngineData->_PeerHashImage2, tmpHash, HASH_IMAGE_SIZE);
	if (!_CheckZrtpMessageHmac(_EngineData->_PeerHashImage2))
	{
		_SendInformationMessageToHost(zCodes::MsgLevelFatal, zCodes::FatalHelloHMAC);
		*errMsg = zCodes::CriticalSoftwareError;
		return NULL;
	}

	std::string cs1("");
	_EngineData->_Callback->SecretsOn(cs, cs1, true);

	_EngineData->_PacketConfirm2.SetMsgType((uint8_t*)Confirm2Msg);
	_EngineData->_PacketConfirm2.SetSignLength(0);
	_EngineData->_PacketConfirm2.SetHashH0(_EngineData->_HashImage0);
	_EngineData->_PacketConfirm2.SetExpTime(0xFFFFFFFF);
	_EngineData->_PacketConfirm2.SetIv(_EngineData->_RandomInitialVector);

	hmlen = (_EngineData->_PacketConfirm2.GetLength() - 9) * ZRTP_WORD_SIZE;
	ZAes::Encrypt(_EngineData->_InitiatorConfirmZrtpKey, (_EngineData->_CommitedCipher == SymCipherSupported::Aes128) ? 16 : 32, _EngineData->_RandomInitialVector,
		_EngineData->_PacketConfirm2.GetHashH0(), hmlen);
	Hmac256::Compute(_EngineData->_InitiatorHmacKey, Sha256::DigestLength,
		(unsigned char*)_EngineData->_PacketConfirm2.GetHashH0(),
		hmlen, confMac, &macLen);

	_EngineData->_PacketConfirm2.SetHmac(confMac);
	return &_EngineData->_PacketConfirm2;
}

zConf2Ack* zRtpEngine::_MakeConf2AckPacket(zConfirm *confirm2, uint32_t* errMsg)
{
	_SendInformationMessageToHost(zCodes::MsgLevelInfo, zCodes::InfoRespConf2Receive);

	uint8_t confMac[Sha256::DigestLength];
	uint32_t macLen;

	int16_t hmlen = (confirm2->GetLength() - 9) * ZRTP_WORD_SIZE;

	Hmac256::Compute(_EngineData->_InitiatorHmacKey, Sha256::DigestLength,
		(unsigned char*)confirm2->GetHashH0(),
		hmlen, confMac, &macLen);

	if (memcmp(confMac, confirm2->GetHmac(), HMAC_SIZE) != 0)
	{
		*errMsg = zCodes::BadConfirmPktMAC;
		return NULL;
	}
	ZAes::Decrypt(_EngineData->_InitiatorConfirmZrtpKey, (_EngineData->_CommitedCipher == SymCipherSupported::Aes128) ? 16 : 32,
		confirm2->GetIv(),
		confirm2->GetHashH0(), hmlen);

	std::string cs(SymCipherSupported::ToString(_EngineData->_CommitedCipher));

	if (!_EngineData->_MultiStream)
	{
		if (!_CheckZrtpMessageHmac(confirm2->GetHashH0()))
		{
			_SendInformationMessageToHost(zCodes::MsgLevelFatal, zCodes::FatalDH2HMAC);
			*errMsg = zCodes::CriticalSoftwareError;
			return NULL;
		}

		bool sasFlag = confirm2->IsSASFlag();

		zRecord zidRec(_EngineData->_OtherEndpointZidData);

		zEndpointInfo *zid = zEndpointInfo::Instance();
		zid->GetRecord(&zidRec);

		if (!sasFlag)
		{
			zidRec.ResetSASVerified();
		}

		bool sasVerified = zidRec.IsSASVerified();
		cs.append("/").append(PubKeySupported::ToString(_EngineData->_CommitedPublicKey));
		_EngineData->_Callback->SecretsOn(cs, _EngineData->_SASValue, sasVerified);

		zidRec.SetNewRs1Value((const uint8_t*)_EngineData->_NewRS1);
		zid->SaveRecord(&zidRec);
	}
	else
	{
		uint8_t tmpHash[Sha256::DigestLength];
		Sha256::Compute(confirm2->GetHashH0(), HASH_IMAGE_SIZE, tmpHash);
		if (!_CheckZrtpMessageHmac(tmpHash))
		{
			_SendInformationMessageToHost(zCodes::MsgLevelFatal, zCodes::FatalCommitHMAC);
			*errMsg = zCodes::CriticalSoftwareError;
			return NULL;
		}
		std::string cs1("");
		_EngineData->_Callback->SecretsOn(cs, cs1, true);
	}
	return &_EngineData->_PacketConf2Ack;
}

zErrorAck* zRtpEngine::_MakeErrorAckPacket(zError* epkt)
{
	_SendInformationMessageToHost(zCodes::MsgLevelZrtpError, epkt->GetErrorCode() * -1);
	return &_EngineData->_PacketErrorAck;
}

zError* zRtpEngine::_MakeErrorPacket(uint32_t errMsg)
{
	_EngineData->_PacketError.SetErrorCode(errMsg);
	return &_EngineData->_PacketError;
}

zPingAck* zRtpEngine::_MakePingAckPacket(zPing* ppkt)
{
	_EngineData->_PacketPingAck.SetLocalEpHash(_EngineData->_MyOwnZidData);
	_EngineData->_PacketPingAck.SetRemoteEpHash(ppkt->GetEpHash());
	_EngineData->_PacketPingAck.SetSSRC(_EngineData->_PeerSSRC);
	return &_EngineData->_PacketPingAck;
}

zGoClearAck* zRtpEngine::_MakeClearAckPacket(zGoClear* gcpkt)
{
	(gcpkt);
	_SendInformationMessageToHost(zCodes::MsgLevelWarning, zCodes::WarningGoClear);
	return &_EngineData->_PacketGoClearAck;
}

zGoClear* zRtpEngine::_MakeGoClearPacket(uint32_t err)
{
	(err);
	zGoClear* gclr = &_EngineData->_PacketGoClear;
	gclr->ClrClearHmac();
	return gclr;
}

HashSupported::Enum zRtpEngine::_SearchHashAlgo(zHello *hello)
{
	int i;
	int ii;
	int num = hello->GetNumHashes();

	if(num == 0)
	{
		return HashSupported::Sha256;
	}
	for (i = 0; i < HashSupported::EndOfEnum; i++)
	{
		for(ii = 0; ii < num; ii++)
		{
			if(*(uint32_t*)hello->GetHashType(ii) == *(uint32_t*)HashSupported::ToString(i))
			{
				return (HashSupported::Enum)i;
			}
		}
	}
	return HashSupported::Sha256;
}

SymCipherSupported::Enum zRtpEngine::_SearchCipherAlgo(zHello *hello, PubKeySupported::Enum pk)
{
	int i;
	int ii;
	bool matchingCiphers[SymCipherSupported::EndOfEnum];
	int num = hello->GetNumCiphers();

	if(num == 0 || pk == PubKeySupported::Dh2048)
	{
		return SymCipherSupported::Aes128;
	}
	for(i = 0; i < SymCipherSupported::EndOfEnum; i++)
	{
		for(ii = 0; ii < num; ii++)
		{
			if(*(uint32_t*)hello->GetCipherType(ii) == *(uint32_t*)SymCipherSupported::ToString(i))
			{
				matchingCiphers[i] = true;
				break;
			}
			matchingCiphers[i] = false;
		}
	}
	if(matchingCiphers[SymCipherSupported::Aes256])
	{
		return SymCipherSupported::Aes256;
	}
	return SymCipherSupported::Aes128;
}

PubKeySupported::Enum zRtpEngine::_SearchPublicKeyAlgo(zHello *hello)
{
	int i;
	int ii;
	int num = hello->GetNumPubKeys();

	if(num == 0)
	{
		return PubKeySupported::Dh3072;
	}
	for(i = 0; i < PubKeySupported::EndOfEnum; i++)
	{
		for(ii = 0; ii < num; ii++)
		{
			if(0 == strcmp((const char *)hello->GetPubKeyType(ii), PubKeySupported::ToString(i)))
			{
				return (PubKeySupported::Enum)i;
			}
		}
	}
	return PubKeySupported::Dh3072;
}

SASTypeSupported::Enum zRtpEngine::_SearchSASAlgo(zHello *hello)
{
	int i;
	int ii;
	int num = hello->GetNumSAS();

	if(num == 0)
	{
		return SASTypeSupported::Libase32;
	}
	for(i = 0; i < SASTypeSupported::EndOfEnum; i++)
	{
		for(ii = 0; ii < num; ii++)
		{
			if(*(uint32_t*)hello->GetSASType(ii) == *(uint32_t*)SASTypeSupported::ToString(i))
			{
				return (SASTypeSupported::Enum)i;
			}
		}
	}
	return SASTypeSupported::Libase32;
}

AuthLengthSupported::Enum zRtpEngine::_SearchAuthentificationLength(zHello *hello)
{
	int i;
	int ii;
	int num = hello->GetNumAuth();

	if(num == 0)
	{
		return AuthLengthSupported::AuthLen32;
	}
	for(i = 0; i < AuthLengthSupported::EndOfEnum; i++)
	{
		for(ii= 0; ii < num; ii++)
		{
			if(*(uint32_t*)hello->GetAuthLen(ii) == *(uint32_t*)AuthLengthSupported::ToString(i))
			{
				return (AuthLengthSupported::Enum)i;
			}
		}
	}
	return AuthLengthSupported::AuthLen32;
}

/*

Copyright 2010-2011 iCall, Inc.

This file is part of Open ZRTP.

Open ZRTP is free software: you can redistribute it and/or modify it under the terms of the GNU Lesser General Public License as published bythe Free Software Foundation, either version 3 of the License, or(at your option) any later version.

Open ZRTP is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU Lesser General Public License for more details.

You should have received a copy of the GNU Lesser General Public Licensealong with Open ZRTP. If not, see http://www.gnu.org/licenses/.

*/


#ifndef __zRtpEngine_h__
#define __zRtpEngine_h__

#include <cstdlib>

#include "zopenssl.h"

#include "zHello.h"
#include "zHelloAck.h"
#include "zCommit.h"
#include "zDHPart.h"
#include "zConfirm.h"
#include "zConf2Ack.h"
#include "zGoClear.h"
#include "zError.h"
#include "zErrorAck.h"
#include "zPing.h"
#include "zPingAck.h"
#include "zCallback.h"
#include "zRecord.h"
#include "zEndpointInfo.h"
#include "zGoClearAck.h"

struct zRtpEngineData;
class zStateMachineDef;
class zDH;

struct zRtpEngine
{
public:
	zRtpEngine(int32_t call_id, const uint8_t* myZID, zCallback* cb, std::string id);
	~zRtpEngine();

	void StartEngine();
	void StopEngine();
	void ProcessMessage(uint8_t *extHdr, uint32_t peerSSRC);
	void ProcessTimeout();
	void SetAuxillarySecret(uint8_t* data, int32_t length);
	void SetPBXSecret(uint8_t* data, int32_t length);
	bool HandleGoClear(uint8_t *extHdr);
	bool CheckCurrentState(int32_t state);
	void SetSASVerified();
	void ResetSASVerifiedFlag();
	std::string GetHelloHashData();
	std::string GetMultiStreamParams();
	void SetMultiStreamParams(std::string parameters);
	bool CheckIsMultiStream();
	bool CheckIsMultiStreamAvailable();
	bool SetSignatureData(uint8_t* data, int32_t length);
	int32_t GetSignatureData(uint8_t* data);
	int32_t GetSignatureLength();
	void SetPBXEnroll(bool YesNo);
	void AcceptEnrollRequest(bool accepted);
	void Conf2AckSecure();
	int32_t GetOtherEndpointZidData(uint8_t* data);

private:
	friend class zStateMachineDef;

	void _EnterSynch();
	void _LeaveSynch();

	int32_t _TimerActive(int32_t tm);
	int32_t _TimerCancel();

	int32_t _SendZrtpPacket(zPacketBase *pkt);
	void _SendInformationMessageToHost(zCodes::ZRTPMessageLevel severity, int32_t subCode);
	void _NegotiationFail(zCodes::ZRTPMessageLevel severity, int32_t subCode);
	void _NoSupportOtherEndpoint();

	void _StoreZrtpMessageInTempBuffer(zPacketBase* pkt);

	int32_t _CompareCommit(zCommit *commit);
	bool _VerifyH2HashImage(zCommit *commit);

	bool _SecretsReady(EnableSecurity part);
	void _SetSecretsOff(EnableSecurity part);

	bool _CheckZrtpMessageHmac(uint8_t* key);
	void _SetClientIDForZrtpHelloMessage(std::string id);

	bool _CheckIsMultiStreamModeOffered(zHello* hello);
	void _ComputeHviValue(zDHPart* dh, zHello *hello);
	void _ComputeSharedSecret(zRecord& zidRec);
	void _ComputeSRTPKeys();

	void _GenerateInitiatorKeys(zDHPart *dhPart, zRecord& zidRec);
	void _GenerateResponderKeys(zDHPart *dhPart, zRecord& zidRec);
	void _GenerateMultiStreamKeys();

	zHello* _MakeHelloPacket();
	zHelloAck* _MakeHelloAckPacket();
	zCommit* _MakeCommitPacket(zHello *hello, uint32_t* errorMsg);
	zCommit* _MakeCommitPacketForMultistreamMode(zHello *hello);
	zDHPart* _MakeDHPart1Packet(zCommit *commit, uint32_t* errorMsg);
	zDHPart* _MakeDHPart2Packet(zDHPart *part, uint32_t* errorMsg);
	zConfirm* _MakeConfirm1Packet(zDHPart* dhpart2, uint32_t* errorMsg);
	zConfirm* _MakeConfirm2Packet(zConfirm* confirm1, uint32_t* errorMsg);
	zConfirm* _MakeConfirm1PacketForMultistreamMode(zCommit* commit, uint32_t* errorMsg);
	zConfirm* _MakeConfirm2PacketForMultistreamMode(zConfirm* confirm1, uint32_t* errorMsg);
	zConf2Ack* _MakeConf2AckPacket(zConfirm* confirm2, uint32_t* errorMsg);
	zError* _MakeErrorPacket(uint32_t errorMsg);
	zErrorAck* _MakeErrorAckPacket(zError* errorPkt);
	zGoClear* _MakeGoClearPacket(uint32_t errorMsg = 0);
	zGoClearAck* _MakeClearAckPacket(zGoClear* clearAckPkt);
	zPingAck* _MakePingAckPacket(zPing* pingPkt);

	HashSupported::Enum _SearchHashAlgo(zHello *hello);
	SymCipherSupported::Enum _SearchCipherAlgo(zHello *hello, PubKeySupported::Enum pk);
	PubKeySupported::Enum _SearchPublicKeyAlgo(zHello *hello);
	SASTypeSupported::Enum _SearchSASAlgo(zHello *hello);
	AuthLengthSupported::Enum _SearchAuthentificationLength(zHello *hello);

private:
	zRtpEngineData* _EngineData;
};

#endif // __zRtpEngine_h__

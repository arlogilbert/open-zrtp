/*

Copyright 2010-2011 iCall, Inc.

This file is part of Open ZRTP.

Open ZRTP is free software: you can redistribute it and/or modify it under the terms of the GNU Lesser General Public License as published bythe Free Software Foundation, either version 3 of the License, or(at your option) any later version.

Open ZRTP is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU Lesser General Public License for more details.

You should have received a copy of the GNU Lesser General Public Licensealong with Open ZRTP. If not, see http://www.gnu.org/licenses/.

*/


#include  <string>
#include <stdio.h>
#include "zRtpEngine.h"
#include "zQueue.h"
#include "zEndpointInfo.h"
#include "zTextData.h"
#include "zStateMachineDef.h"
#include "UserCallback.h"

#ifdef _WIN32
#include "stdafx.h"
#endif

static Timer<std::string, zQueue*>* staticTimer = NULL;

void* AVPQueue::dispatch_cb = NULL;

RTPApplication& defaultApplication()
{
	static RTPApplication app;
	return app;
};

zQueue::zQueue(uint32_t size, RTPApplication& app) : AVPQueue(size, app)
{
	init();
}

zQueue::zQueue(uint32_t ssrc, uint32_t size, RTPApplication& app) : AVPQueue( size, app, ssrc)
{
	init();
}

void zQueue::init()
{
	userCallback = NULL;
	enableZRTP = false;
	started = false;
	zrtpEngine = NULL;
	senderZrtpSeqNo = 1;

	clientIDString = clientID;
	peerSSRC = 0;
}

zQueue::~zQueue()
{
	endQueue();
	StopZRTP();

	if(userCallback != NULL)
	{
		delete userCallback;
		userCallback = NULL;
	}
}

int32_t zQueue::initialize(const char *zIDFilename, bool autoEnable)
{
	int32_t ret = 1;
	EnterSynch();

	enableZRTP = autoEnable;

	if(staticTimer == NULL)
	{
		staticTimer = new Timer<std::string, zQueue*>();
		//staticTimer->sta;
	}

	zEndpointInfo* EInfo = zEndpointInfo::Instance();
	if(!EInfo->IsOpen())
	{
		std::string fname;
		if(zIDFilename == NULL)
		{
			char *home = getenv("HOME");
			std::string baseDir = (home != NULL) ? (std::string(home) + std::string("/.")) : std::string(".");

			fname = baseDir + std::string("GNUccRTP.ZID");
			zIDFilename = fname.c_str();
		}
		if(EInfo->Open((char *)zIDFilename) < 0)
		{
			enableZRTP = false;
			ret = -1;
		}
	}

	if(ret > 0)
	{
		const uint8_t* ownZID = EInfo->GetZID();
		zrtpEngine = new zRtpEngine(0, (uint8_t*)ownZID, (zCallback*)this, clientIDString);
	}
	LeaveSynch();
	return ret;
}

void zQueue::StartZRTP()
{
	if(zrtpEngine != NULL)
	{
		zrtpEngine->StartEngine();
		started = true;
	}
}

void zQueue::StopZRTP()
{
	if(zrtpEngine != NULL)
	{
		delete zrtpEngine;
		zrtpEngine = NULL;
		started = false;
	}
}

size_t zQueue::TakeDataPacket(void)
{
	printf("\n received a datapacket");

	InetHostAddress network_add;
	tpport_t transport_port;

	uint32_t nextSize = (uint32_t)getNextDataPacketSize();
	unsigned char* buffer = new unsigned char[nextSize];
	int32_t rtn = (int32_t)recvData(buffer, nextSize, network_add, transport_port);
	if( (rtn<0) || ((uint32_t)rtn > getMaxRecvPacketSize()) )
	{
		delete buffer;
		return 0;
	}

	IncomingZRTPPkt* packet = NULL;
	if((*buffer & 0xf0) != 0x10)
	{
		IncomingRtpPkt* pkt = new IncomingRtpPkt(buffer, rtn);

		if(pkt->isHeaderValid())
		{
			return (rtpDataPacket(pkt, rtn, network_add, transport_port));
		}
		delete pkt;
		return 0;

	}

	if(enableZRTP)
	{
		uint16_t temp = static_cast<uint16_t>(rtn - CRC_SIZE);
		uint32_t crc = *(uint32_t*)(buffer + temp);
		crc = ntohl(crc);

		if(!zCRC32::Check(buffer, temp, crc))
		{
			delete buffer;
			//userCallback->
			userCallback->ShowMsg(zCodes::MsgLevelWarning, zCodes::WarningCRCMismatch);
			return 0;
		}

		packet = new IncomingZRTPPkt(buffer, rtn);

		uint32_t magic = packet->getZRTPMagic();

		if(magic != ZRTP_MAGIC || zrtpEngine == NULL)
		{
			delete packet;
			return 0;
		}

		if(!started)
		{
			StartZRTP();
		}

		unsigned char* extHdr = const_cast<unsigned char*>(packet->getHdrExtContent());
		extHdr -= 4;

		peerSSRC = packet->getSSRC();
		zrtpEngine->ProcessMessage(extHdr, peerSSRC);

	}
	delete packet;
	return 0;
}

size_t zQueue::rtpDataPacket(IncomingRtpPkt* packet, int32_t rtn, InetHostAddress network_add, tpport_t transport_port)
{
	zCryptoContext* pcc = getInQueueCryptContxt(packet->getSSRC());

	if(pcc == NULL)
	{
		pcc = getInQueueCryptContxt(0);
		if(pcc != NULL)
		{
			pcc = pcc->NewCryptContextForSSRC(packet->getSSRC(), 0, 0L);
			if(pcc != NULL)
			{
				pcc->DeriveSRTPKeys(0);
				setInQueueCryptContxt(pcc);
			}
		}
	}

	if(pcc != NULL)
	{
		int32_t ret;
		if((ret = packet->unprotect(pcc)) < 0)
		{
			if(!onSRTPPacketError(*packet, ret))
			{
				delete packet;
				return 0;
			}
		}
		if(started && zrtpEngine->CheckCurrentState(zCodes::StateWaitConfirmAck))
		{
			zrtpEngine->Conf2AckSecure();
		}
	}

   /*if(!onRTPPacketRecv(*packet))
   {
	   delete packet;
	   return 0;
   }*/

   struct timeval recvtime;

   gettimeofday(&recvtime, NULL);

   bool source_created = false;
   SyncSourceLink* sourceLink = getSourceBySSRC(packet->getSSRC(), source_created);
   SyncSource* s = sourceLink->getSource();
   if(source_created)
   {
	   setDataTransportPort(*s,transport_port);

	   setNetworkAddress(*s, network_add);
	   sourceLink->initStats();

	   sourceLink->setInitialDataTime(recvtime);
	   sourceLink->setProbation(getMinValidPacketSeq());
	   if(sourceLink->getHello())
		{
//			  onNewSyncSource(*s);
			  //TBD
		}
		else if(0 == s->getDataTransportPort())
		{
			setDataTransportPort(*s, transport_port);
		}

		if(checkSSRCInIncomingRTPPkt(*sourceLink, source_created, network_add, transport_port) &&
			recordReception(*sourceLink, *packet, recvtime))
			{
				/*IncomingRtpPktLink* packetLink = new IncomingRtpPktLink(packet, sourceLink, recvtime, packet->getTimestamp() - sourceLink->getInitialDataTimestamp(),
													NULL, NULL, NULL, NULL);*/
				IncomingRtpPktLink* packetLink = new IncomingRtpPktLink(packet, sourceLink, recvtime, packet->getTimestamp() - sourceLink->getInitialDataTimestamp());
				insertRecvPacket(packetLink);
			}
			else
			{
				delete packet;

				return 0;
			}

		if(!started && enableZRTP)
		{
			StartZRTP();
		}
		return rtn;
}
   return 0;
}

bool zQueue::onSRTPPacketError(IncomingRtpPkt&, int32_t errorCode)
{
	if( errorCode == -1)
	{
		SendInformationToTheHost(zCodes::MsgLevelWarning, zCodes::WarningSRTPAuthFail);
	}
	else
	{
		SendInformationToTheHost(zCodes::MsgLevelWarning, zCodes::WarningSRTPReplayFail);
	}
	return false;
}

void zQueue::putData(uint32_t stamp, const unsigned char* data, size_t len)
{
	OutgoingDataQueue::putData(stamp, data, len);
}

void zQueue::sendNow(uint32_t stamp, const unsigned char* data, size_t len)
{
	OutgoingDataQueue::sendImmediate(stamp, data, len);
}

int32_t zQueue::SendPacketThroughRTP(const unsigned char *data, int32_t length)
{
	OutgoingZRTPPkt* packet = new OutgoingZRTPPkt(data, length);

	packet->setSSRC(getLocalSSRC());
	packet->setSeqNum(senderZrtpSeqNo++);

	uint16_t temp = static_cast<uint16_t>(packet->getRawPacketSize() - CRC_SIZE);

	uint8_t* pt = (uint8_t*)packet->getRawPacket();
	uint32_t crc = zCRC32::Generate(pt, temp);

	crc = zCRC32::End(crc);

	pt+=temp;
	*(uint32_t*)pt = htonl(crc);

	dispatchPacket(packet);

	delete packet;

	return 1;
}


bool zQueue::SecretsReady(SRTPSecrets_t* secrets, EnableSecurity part)
{
	zCryptoContext* pcc;
	zCryptoContext* recvCryptoContext;
	zCryptoContext* senderCryptoContext;

	if(part == ForSender)
	{
		if(secrets->role == Initiator)
		{
			senderCryptoContext = new zCryptoContext(
									-1,
									0,
									0,
									0L,
									SrtpEncryptionAESCM,
									SrtpAuthenticationSha1Hmac,
									(unsigned char*) secrets->keyInit,
									secrets->initKeyLen / 8,
									(unsigned char*)secrets->saltInit,
									secrets->initSaltLen / 8,
									secrets->initKeyLen / 8,
									20,
									secrets->initSaltLen / 8,
									secrets->srtpAuthTagLen / 8);
		}
		else
		{
			senderCryptoContext = new zCryptoContext (
									-1,
									0,
									0,
									0L,
									SrtpEncryptionAESCM,
									SrtpAuthenticationSha1Hmac,
									(unsigned char*) secrets->keyResp,
									secrets->respKeyLen / 8,
									(unsigned char*) secrets->saltResp,
									secrets->respSaltLen / 8,
									secrets->respKeyLen / 8,
									20,
									secrets->respSaltLen / 8,
									secrets->srtpAuthTagLen / 8);
		}

		if(senderCryptoContext == NULL) {
			return false;
		}

		pcc = senderCryptoContext->NewCryptContextForSSRC(-1, getLocalSSRC(), 0, 0L);

		if(pcc == NULL)
		{
			return false;
		}

		pcc->DeriveSRTPKeys(0L);
		setOutQueueCryptoContext(pcc);
	}

	if(part == ForReceiver)
	{
		if(secrets->role == Initiator) {

			recvCryptoContext = new zCryptoContext(
								-1,
								0,
								0,
								0L,
								SrtpEncryptionAESCM,
								SrtpAuthenticationSha1Hmac,
								(unsigned char*) secrets->keyResp,
								secrets->respKeyLen / 8,
								(unsigned char*) secrets->saltResp,
								secrets->respSaltLen / 8,
								secrets->respKeyLen / 8,
								20,
								secrets->respSaltLen / 8,
								secrets->srtpAuthTagLen / 8);
		}
		else
		{
			recvCryptoContext = new zCryptoContext(
								-1,
								0,
								0,
								0L,
								SrtpEncryptionAESCM,
								SrtpAuthenticationSha1Hmac,
								(unsigned char*) secrets->keyInit,
								secrets->initKeyLen / 8,
								(unsigned char*) secrets->saltInit,
								secrets->initSaltLen / 8,
								secrets->initKeyLen / 8,
								20,
								secrets->initSaltLen / 8,
								secrets->srtpAuthTagLen / 8);
		}

		if(recvCryptoContext == NULL) {
			return false;
		}

		if(peerSSRC != 0) {
			pcc = recvCryptoContext->NewCryptContextForSSRC(-1, peerSSRC, 0, 0L);
			if(pcc == NULL) {
				return false;
			}
			pcc->DeriveSRTPKeys(0L);
			setInQueueCryptoContext(pcc);
		}
		else
		{
			setInQueueCryptoContext(recvCryptoContext);
		}
	}

	return true;
}


void zQueue::SecretsOn(std::string c, std::string s, bool verified)
{
	if(userCallback != NULL) {
		userCallback->SecureOn(c);
		if(!s.empty()) {

		userCallback->ShowSAS(s,verified);

		}
	}
}

void zQueue::SecretsOff(EnableSecurity part)
{
	if(part == ForSender) {
		removeOutQueueCryptoContext(NULL);
	}

	if(part == ForReceiver) {
		removeInQueueCryptoContext(NULL);
	}

	if(userCallback != NULL) {
		userCallback->SecureOff();
	}
}

int32_t zQueue::TimerActive(int32_t time)
{
	std::string s("zrtp");

	if(staticTimer != NULL) {
		staticTimer->ReqTimeout(time, this, s);
		//staticTimer->requestTimeout(time, this, s);
	}
	return 1;
}

int32_t zQueue::TimerCancel()
{
	std::string s("zrtp");

	if(staticTimer != NULL) {
		staticTimer->cancelReq(this,s);
		//staticTimer->cancelRequest(this,s);
	}
	return 1;
}

void zQueue::handleTimeout(const std::string &)
{
	if(zrtpEngine != NULL) {
		zrtpEngine->ProcessTimeout();
	}
}

void zQueue::HandleGoClear()
{
	//
}


void zQueue::SendInformationToTheHost(zCodes::ZRTPMessageLevel severity, int32_t subCode)
{
	if(userCallback != NULL) {
	userCallback->ShowMsg(severity, subCode);
	}
}

void zQueue::HandleNegotiationFail(zCodes::ZRTPMessageLevel severity, int32_t subCode)
{
	if(userCallback != NULL) {
	userCallback->zNegotiationFail(severity, subCode);
	}
}

void zQueue::HandleNoSupportOther()
{
	if(userCallback != NULL) {
	userCallback->zNoSupportOther();
	}
}

void zQueue::EnterSynch()
{
   // printf("\n Before sync.enter()");
	synchLock.Enter();
   // printf("\n after sync.enter()");
}

void zQueue::LeaveSynch()
{
	synchLock.Leave();
}

void zQueue::InformAboutPBXEnrollRequest(std::string info)
{
	if(userCallback != NULL)
	{
		userCallback->zAskEnroll(info);
	}
}

void zQueue::InformAboutPBXEnrollResult(std::string info)
{
	if(userCallback != NULL)
	{
		userCallback->zInfoEnroll(info);
	}
}

void zQueue::RequestSASSignature(std::string sas)
{
	if(userCallback != NULL)
	{
		userCallback->signSAS(sas);
	}
}

bool zQueue::CheckSASSignature(std::string sas)
{
	if(userCallback != NULL)
	{
		return userCallback->checkSASSignature(sas);
	}
	return false;
}

void zQueue::EnableZRTP(bool onOff)
{
	enableZRTP = onOff;
}

bool zQueue::isEnableZRTP()
{
	return enableZRTP;
}

void zQueue::SASVerified()
{
	if(zrtpEngine != NULL) {
		zrtpEngine->SetSASVerified();
		//zrtpEngine->
	}

}

void zQueue::resetSASVerified() {
	if (zrtpEngine != NULL)
		zrtpEngine->ResetSASVerifiedFlag();
}

void zQueue::goClearOk()	{  }

void zQueue::requestGoClear()  { }

void zQueue::setAUXSecret(uint8_t* data, int32_t length)  {
	if (zrtpEngine != NULL)
		zrtpEngine->SetAuxillarySecret(data, length);
}

void zQueue::setPBXSecret(uint8_t* data, int32_t length)  {
	if (zrtpEngine != NULL)
		zrtpEngine->SetPBXSecret(data, length);
}

void zQueue::setUserCallback(UserCallback* ucb) {
	userCallback = ucb;
}

void zQueue::setClientID(std::string id) {
	clientIDString = id;
}

std::string zQueue::getHelloHash()	{
	if (zrtpEngine != NULL)
		return zrtpEngine->GetHelloHashData();
	else
		return std::string();
}

std::string zQueue::getMultiStreamParams()	{
	if (zrtpEngine != NULL)
		return zrtpEngine->GetMultiStreamParams();
		//zrtpEngine->getMultiStreamParams
	else
		return std::string();
}

void zQueue::setMultiStreamParams(std::string parameters)  {
	if (zrtpEngine != NULL)
		zrtpEngine->SetMultiStreamParams(parameters);
}

bool zQueue::isMultiStream()  {
	if (zrtpEngine != NULL)
		return zrtpEngine->CheckIsMultiStream();
	return false;
}

void zQueue::EnrollAccept(bool accepted) {
	if (zrtpEngine != NULL)
		zrtpEngine->AcceptEnrollRequest(accepted);

}

bool zQueue::setSignData(uint8_t* data, uint32_t length) {
	if (zrtpEngine != NULL)
		return zrtpEngine->SetSignatureData(data, length);

	return 0;
}

int32_t zQueue::getSignatureData(uint8_t* data) {
	if (zrtpEngine != NULL)
		return zrtpEngine->GetSignatureData(data);
	return 0;
}

int32_t zQueue::getSignLength() {
	if (zrtpEngine != NULL)
		return zrtpEngine->GetSignatureLength();
	return 0;
}

void zQueue::setPBXEnroll(bool yesNo) {
	if (zrtpEngine != NULL)
	zrtpEngine->SetPBXEnroll(yesNo);
}


int32_t zQueue::getZID(uint8_t* data) {
	if (data == NULL)
		return 0;

	if (zrtpEngine != NULL)
		return zrtpEngine->GetOtherEndpointZidData(data);

	return 0;
}

IncomingZRTPPkt::IncomingZRTPPkt(const unsigned char* const block, size_t len) :
		IncomingRtpPkt(block,len) {
}

uint32_t IncomingZRTPPkt::getZRTPMagic() const {
	 return ntohl(getHeader()->ts);
}

uint32_t IncomingZRTPPkt::getSSRC() const	{
	 return ntohl(getHeader()->src[0]);
}

OutgoingZRTPPkt::OutgoingZRTPPkt(
	const unsigned char* const hdrext, uint32_t hdrextlen) :
		OutgoingRtpPkt(NULL, 0, hdrext, hdrextlen, NULL ,0, 0, NULL)
{
	getHeader()->ver = 0;
	getHeader()->ext = 1;
	getHeader()->ts = htonl(ZRTP_MAGIC);
}















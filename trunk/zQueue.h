/*

Copyright 2010-2011 iCall, Inc.

This file is part of Open ZRTP.

Open ZRTP is free software: you can redistribute it and/or modify it under the terms of the GNU Lesser General Public License as published bythe Free Software Foundation, either version 3 of the License, or(at your option) any later version.

Open ZRTP is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU Lesser General Public License for more details.

You should have received a copy of the GNU Lesser General Public Licensealong with Open ZRTP. If not, see http://www.gnu.org/licenses/.

*/


#ifndef _ZQUEUE_H_
#define _ZQUEUE_H_

#include "rtp.h"
#include "zCallback.h"
#include "zTimer2.h"
#include "synch.h"
#include "UserCallback.h"
#include "packetQueue.h"

extern RTPApplication& defaultApplication();

class RTPDataQueue
{
public:
	static const size_t defaultMemberHashSize = 100;
};

class zQueue : public AVPQueue, public zCallback
{
public:


	zQueue(uint32_t size = RTPDataQueue::defaultMemberHashSize,
		RTPApplication& app = defaultApplication());

	zQueue(uint32_t ssrc, uint32_t size = RTPDataQueue::defaultMemberHashSize,
		RTPApplication& app = defaultApplication());

	int32_t initialize(const char *zIDFilename, bool autoEnable = true);

	//Enable or disable ZRTP processing
	void EnableZRTP(bool OnOff);

	//return the zrtp enable state
	bool isEnableZRTP();

	//set SAS as verified
	void SASVerified();

	void resetSASVerified();

	//Confirm go clear request
	void goClearOk();

	//request Go clear to switch off secure mode
	void requestGoClear();

	//set the auxillary secret
	void setAUXSecret(uint8_t* data, int32_t length);

	//set PBX secret
	void setPBXSecret(uint8_t* data, int32_t length);

	//application callback class
	void setUserCallback(UserCallback* ucb);

	//to set the client ID for Hello message
	void setClientID(std::string id);

	//to get the Hello hash data
	std::string getHelloHash();

	//to get the multistream parameters
	std::string getMultiStreamParams();

	//set the multistream parameters
	void setMultiStreamParams(std::string params);


	bool isMultiStream();

	//Accept the PBX enrollment request
	void EnrollAccept(bool accepted);

	//set signature data
	bool setSignData(uint8_t* data, uint32_t length);

	//to get the signature data
	int32_t getSignatureData(uint8_t* data);

	//to get the length of the signature data
	int32_t getSignLength();

	//to enable the PBX enrollment
	void setPBXEnroll(bool YesNo);

	//putting the data into RTP queue of outputs
	void putData(uint32_t stamp, const unsigned char* data = NULL, size_t len = 0);

	//To send a packet immediately
	void sendNow(uint32_t stamp, const unsigned char* data = NULL, size_t len = 0);

	// process next incoming packet and place it in recieve list
	virtual size_t TakeDataPacket();
	// To start the ZRTP protocol engine
	void StartZRTP();

	//Stop the ZRTP engine
	void StopZRTP();

	//To get the other party's ZID
	int32_t getZID(uint8_t* data);

	virtual ~zQueue();

protected:
	friend class Timer<std::string, zQueue*>;

	// this method is called if decoding of an incoming SRTP message was erroneous
	virtual bool onSRTPPacketError(IncomingRtpPkt& pkt, int32_t errorCode);

	//to handle time out event forwarded by ztimer
	void handleTimeout(const std::string &c);



	//callback interface
	int32_t SendPacketThroughRTP(const unsigned char* data, int32_t length);

	int32_t TimerActive(int32_t time);

	int32_t TimerCancel();

	void SendInformationToTheHost(zCodes::ZRTPMessageLevel severity, int32_t subCode);

	bool SecretsReady(SRTPSecrets_t* secrets, EnableSecurity part);

	void SecretsOff(EnableSecurity part);

	void SecretsOn(std::string c, std::string s, bool verified);

	void HandleGoClear();

	void HandleNegotiationFail(zCodes::ZRTPMessageLevel severity, int32_t subCode);

	void HandleNoSupportOther();

	void EnterSynch();

	void LeaveSynch();

	void InformAboutPBXEnrollRequest(std::string info);

	void InformAboutPBXEnrollResult(std::string info);

	void RequestSASSignature(std::string sas);

	bool CheckSASSignature(std::string sas);

	//End of the ZRTP callback functions




private:
	void init();
	size_t rtpDataPacket(IncomingRtpPkt* packet, int32_t rtn,
		InetHostAddress network_add,
		tpport_t transport_port);

	zRtpEngine *zrtpEngine;
	UserCallback* userCallback;

	std::string clientIDString;

	bool enableZRTP;

	int32_t SecureParts;

	int16_t senderZrtpSeqNo;
	Sync synchLock;
	uint32_t peerSSRC;
	bool started;
};

class IncomingZRTPPkt : public IncomingRtpPkt
{
public:

	IncomingZRTPPkt(const unsigned char* block, size_t len);

	~IncomingZRTPPkt()
	{ }

	uint32_t
		getZRTPMagic() const;

	uint32_t
		getSSRC() const;
};

class OutgoingZRTPPkt : public OutgoingRtpPkt
{
public:

	OutgoingZRTPPkt(const unsigned char* const hdrext, uint32_t len);
	~OutgoingZRTPPkt()
	{ }

};

#endif









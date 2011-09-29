/*

Copyright 2010-2011 iCall, Inc.

This file is part of Open ZRTP.

Open ZRTP is free software: you can redistribute it and/or modify it under the terms of the GNU Lesser General Public License as published bythe Free Software Foundation, either version 3 of the License, or(at your option) any later version.

Open ZRTP is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU Lesser General Public License for more details.

You should have received a copy of the GNU Lesser General Public Licensealong with Open ZRTP. If not, see http://www.gnu.org/licenses/.

*/


#ifndef __zCodes_h__
#define __zCodes_h__

struct zCodes
{
	enum ZRTPMessageLevel
	{
		MsgLevelInfo = 1,
		MsgLevelWarning,
		MsgLevelFatal,
		MsgLevelZrtpError,

		CountOf_ZRTPMessageLevel
	};

	enum ZRTPInfoCodes
	{
		InfoHelloReceive = 1,
		InfoCommitDHGenerate,
		InfoRespCommitReceive,
		InfoDH1DHGenerate,
		InfoInitDH1Receive,
		InfoRespDH2Receive,
		InfoInitConf1Receive,
		InfoRespConf2Receive,
		InfoRSMatchFound,
		InfoSecureStateOn,
		InfoSecureStateOff,

		CountOf_ZRTPInfoCodes
	};

	enum ZRTPWarningCodes
	{
		WarningDHAESmismatch = 1,
		WarningGoClear,
		WarningDHShort,
		WarningNoRSMatch,
		WarningCRCMismatch,
		WarningSRTPAuthFail,
		WarningSRTPReplayFail,
		WarningNoExpectedRSMatch,

		CountOf_ZRTPWarningCodes
	};

	enum ZRTPFatalCodes
	{
		FatalHelloHMAC = 1,
		FatalCommitHMAC,
		FatalDH1HMAC,
		FatalDH2HMAC,
		FatalCannotSend,
		FatalProtocolError,
		FatalNoTimer,
		FatalRetrySaturation,
		FatalSWERROR,

		CountOf_ZRTPFatalCodes
	};

	enum ZRTPErrorCodes
	{
		MalformedPacket					= 0x10,		// Malformed packet (CRC OK, but wrong structure)
		CriticalSoftwareError			= 0x20,		// Critical software error
		UnsupportedZrtpVersion			= 0x30,		// Unsupported ZRTP version
		HelloComponentsMismatch			= 0x40,		// Hello components mismatch
		UnsupportedHashType				= 0x51,		// Hash type not supported
		UnsupportedCipherType			= 0x52,		// Cipher type not supported
		UnsupportedPublicKeyExchange	= 0x53,		// Public key exchange not supported
		UnsupportedSRTPAuthTag			= 0x54,		// SRTP auth. tag not supported
		UnsupportedSASRenderScheme		= 0x55,		// SAS rendering scheme not supported
		UnavailableSharedSecret			= 0x56,		// No shared secret available, DH mode required
		BadPviOrPvR						= 0x61,		// DH Error: bad pvi or pvr ( == 1, 0, or p-1)
		MismatchHviAndHash				= 0x62,		// DH Error: hvi != hashed data
		RelayedSASFromUntrustedMiTM		= 0x63,		// Received relayed SAS from untrusted MiTM
		BadConfirmPktMAC				= 0x70,		// Auth. Error: Bad Confirm pkt MAC
		NonceReuse						= 0x80,		// Nonce reuse
		EqualZidsInHello				= 0x90,		// Equal ZIDs in Hello
		SSRCCollision					= 0x91,		// SSRC collision
		UnavailableService				= 0xA0,		// Service unavailable
		ProtocolTimeoutError			= 0xB0,		// Protocol timeout error
		UnallowedGoClearMessage			= 0x100,	// GoClear message received, but not allowed
		IgnorePacket					= 0x7fffffff
	};

	enum ZRTPStates
	{
		StateStart,
		StateDetect,
		StateAckDetected,
		StateAckSent,
		StateWaitCommit,
		StateSentCommit,
		StateWaitDH2,
		StateWaitConfirm1,
		StateWaitConfirm2,
		StateWaitConfirmAck,
		StateWaitClearAck,
		StateSecure,
		StateWaitErrorAck,
		
		CountOf_ZRTPStates
	};

	enum ZRTPEventType
	{
		ZrtpEventTypeStart = 1,
		ZrtpEventTypeClose,
		ZrtpEventTypePacket,
		ZrtpEventTypeTimer,
		ZrtpEventTypeErrorPacket,

		CountOf_ZRTPEventType
	};
};

#endif // __zCodes_h__

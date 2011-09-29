/*

Copyright 2010-2011 iCall, Inc.

This file is part of Open ZRTP.

Open ZRTP is free software: you can redistribute it and/or modify it under the terms of the GNU Lesser General Public License as published bythe Free Software Foundation, either version 3 of the License, or(at your option) any later version.

Open ZRTP is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU Lesser General Public License for more details.

You should have received a copy of the GNU Lesser General Public Licensealong with Open ZRTP. If not, see http://www.gnu.org/licenses/.

*/

#ifndef __pj_zrtpadapter_h__
#define __pj_zrtpadapter_h__

#include "int.h"
#include "zRtpConfig.h"

typedef struct c_srtp_secrets
{
	const uint8_t* keyInit;
	int32_t initKeyLen;
	const uint8_t* saltInit;
	int32_t initSaltLen;
	const uint8_t* keyResp;
	int32_t respKeyLen;
	const uint8_t* saltResp;
	int32_t respSaltLen;
	int32_t srtpAuthTagLen;
	char* sas;
	int32_t role;
} c_srtp_secrets_t;

#ifdef __cplusplus
extern "C"
{
#endif

	typedef struct zRtpEngine zRtpEngine;
	typedef struct pj_CallbackAdapter pj_CallbackAdapter;

	typedef struct ZrtpAdapterCtx
	{
		int32_t callId;
		zRtpEngine* zrtpEngine;
		pj_CallbackAdapter* zrtpCallback;
		void* userData;
	} zZrtpAdapterCtx;

	typedef struct zrtp_Callbacks
	{
		int32_t (*SendDataZRTP) (zZrtpAdapterCtx* ctx, const uint8_t* data, int32_t length);
		int32_t (*ActivateTimer) (zZrtpAdapterCtx* ctx, int32_t time);
		int32_t (*CancelTimer)(zZrtpAdapterCtx* ctx);
		void (*SendInfo) (zZrtpAdapterCtx* ctx, int32_t severity, int32_t subCode);
		int32_t (*SrtpSecretsReady) (zZrtpAdapterCtx* ctx, c_srtp_secrets_t* secrets, int32_t part);
		void (*SrtpSecretsOff) (zZrtpAdapterCtx* ctx, int32_t part);
		void (*RtpSecretsOn) (zZrtpAdapterCtx* ctx, char* c, char* s, int32_t verified);
		void (*HandleGoClear)(zZrtpAdapterCtx* ctx);
		void (*NegotiationFailed) (zZrtpAdapterCtx* ctx, int32_t severity, int32_t subCode);
		void (*NotSuppOther)(zZrtpAdapterCtx* ctx);
		void (*SynchEnter)(zZrtpAdapterCtx* ctx);
		void (*SynchLeave)(zZrtpAdapterCtx* ctx);
		void (*AskEnrollment) (zZrtpAdapterCtx* ctx, char* info);
		void (*InformEnrollment) (zZrtpAdapterCtx* ctx, char* info);
		void (*SignSAS)(zZrtpAdapterCtx* ctx, char* sas);
		int32_t (*CheckSASSignature) (zZrtpAdapterCtx* ctx, char* sas);
	} zrtp_Callbacks;

	zZrtpAdapterCtx* CreateZrtpAdapter(int32_t callId);

	void InitializeZrtpEngine (
		int32_t call_id,
		zZrtpAdapterCtx* ZrtpAdapterCtx,
		zrtp_Callbacks *cb,
		char* id,
		const char* zidFilename,
		void* userData );

	void DestroyZrtpWrapper (zZrtpAdapterCtx* ZrtpAdapterCtx);

	int32_t ZrtpAdapter_CheckCksum(uint8_t* buffer, uint16_t length, uint32_t crc);
	uint32_t ZrtpAdapter_GenerateCksum(uint8_t* buffer, uint16_t length);
	uint32_t ZrtpAdapter_EndCksum(uint32_t crc);
	void ZrtpAdapter_StartZrtpEngine(zZrtpAdapterCtx* ZrtpAdapterCtx);
	void ZrtpAdapter_StopZrtpEngine(zZrtpAdapterCtx* ZrtpAdapterCtx);
	void ZrtpAdapter_ProcessZrtpMessage(zZrtpAdapterCtx* ZrtpAdapterCtx, uint8_t *extHeader, uint32_t peerSSRC);
	void ZrtpAdapter_ProcessTimeout(zZrtpAdapterCtx* ZrtpAdapterCtx);
	void ZrtpAdapter_SetAuxSecret(zZrtpAdapterCtx* ZrtpAdapterCtx, uint8_t* data, int32_t length);
	void ZrtpAdapter_SetPbxSecret(zZrtpAdapterCtx* ZrtpAdapterCtx, uint8_t* data, int32_t length);
	int32_t ZrtpAdapter_InState(zZrtpAdapterCtx* ZrtpAdapterCtx, int32_t state);
	void ZrtpAdapter_SASVerified(zZrtpAdapterCtx* ZrtpAdapterCtx);
	void ZrtpAdapter_ResetSASVerified(zZrtpAdapterCtx* ZrtpAdapterCtx);
	char* ZrtpAdapter_GetHelloHash(zZrtpAdapterCtx* ZrtpAdapterCtx);
	char* ZrtpAdapter_GetMultiStrParams(zZrtpAdapterCtx* ZrtpAdapterCtx, int32_t *length);
	void ZrtpAdapter_SetMultiStrParams(zZrtpAdapterCtx* ZrtpAdapterCtx, char* parameters, int32_t length);
	int32_t ZrtpAdapter_IsMultiStream(zZrtpAdapterCtx* ZrtpAdapterCtx);
	int32_t ZrtpAdapter_IsMultiStreamAvailable(zZrtpAdapterCtx* ZrtpAdapterCtx);
	void ZrtpAdapter_AcceptEnrollment(zZrtpAdapterCtx* ZrtpAdapterCtx, int32_t accepted);
	void ZrtpAdapter_SetPBXEnrollment(zZrtpAdapterCtx* ZrtpAdapterCtx, int32_t yesNo);
	int32_t ZrtpAdapter_SetSignatureData(zZrtpAdapterCtx* ZrtpAdapterCtx, uint8_t* data, int32_t length);
	int32_t ZrtpAdapter_GetSignatureData(zZrtpAdapterCtx* ZrtpAdapterCtx, uint8_t* data);
	int32_t ZrtpAdapter_GetSignatureLength(zZrtpAdapterCtx* ZrtpAdapterCtx);
	void ZrtpAdapter_Conf2AckSecure(zZrtpAdapterCtx* ZrtpAdapterCtx);
	int32_t ZrtpAdapter_GetZid(zZrtpAdapterCtx* ZrtpAdapterCtx, uint8_t* data);

#ifdef __cplusplus
}
#endif

#endif // __pj_zrtpadapter_h__

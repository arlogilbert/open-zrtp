/*

Copyright 2010-2011 iCall, Inc.

This file is part of Open ZRTP.

Open ZRTP is free software: you can redistribute it and/or modify it under the terms of the GNU Lesser General Public License as published bythe Free Software Foundation, either version 3 of the License, or(at your option) any later version.

Open ZRTP is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU Lesser General Public License for more details.

You should have received a copy of the GNU Lesser General Public Licensealong with Open ZRTP. If not, see http://www.gnu.org/licenses/.

*/


#include "network.h"
#include "pj_zrtpadapter.h"
#include "pj_callbackadapter.h"
#include "zEndpointInfo.h"
#include "zRtpEngine.h"

namespace
{
	int32_t initialized = 0;

	int32_t ZrtpAdapter_InitZidFile(const char* zidFilename)
	{
		zEndpointInfo* endpointInfo = zEndpointInfo::Instance();

		if (!endpointInfo->IsOpen())
		{
			std::string fname;
			if (zidFilename == NULL)
			{
				char *home = getenv("HOME");
				std::string baseDir = (home != NULL) ? (std::string(home) + std::string("/."))
					: std::string(".");
				fname = baseDir + std::string("GNUccRTP.zid");
				zidFilename = fname.c_str();
			}
			return endpointInfo->Open((char *)zidFilename);
		}
		return 0;
	}

	const int g_HelloHashRetBuffSize = (ZRTP_WORD_SIZE * 2) + (Sha256::DigestLength * 2) + 2;
	char g_HelloHashRetBuff[g_HelloHashRetBuffSize];

	const int g_MultiStrParamsRetBuffSize = (ZRTP_WORD_SIZE + Sha256::DigestLength) + 2;
	char g_MultiStrParamsRetBuff[g_MultiStrParamsRetBuffSize];
}

zZrtpAdapterCtx* CreateZrtpAdapter(int32_t callId) 
{
	zZrtpAdapterCtx* adapterCtx = new zZrtpAdapterCtx;
	memset(adapterCtx, 0, sizeof(zZrtpAdapterCtx));

	adapterCtx->callId = callId;

	return adapterCtx;
}

void InitializeZrtpEngine (
	int32_t call_id,
	zZrtpAdapterCtx* zrtpContext, 
	zrtp_Callbacks *cb, char* clientId,
	const char* zidFilename,
	void* userData )
{
	zrtpContext->zrtpCallback = new pj_CallbackAdapter(cb, zrtpContext);
	zrtpContext->userData = userData;
	zrtpContext->callId = call_id;

	ZrtpAdapter_InitZidFile(zidFilename);
	zEndpointInfo* endpointInfo = zEndpointInfo::Instance();
	const unsigned char* myZid = endpointInfo->GetZID();

	zrtpContext->zrtpEngine = new zRtpEngine (
		call_id,
		(uint8_t*)(myZid),
		zrtpContext->zrtpCallback,
		std::string(clientId) );

	initialized = 1;
}

void DestroyZrtpWrapper(zZrtpAdapterCtx* zrtpContext)
{
	if (zrtpContext == NULL)
		return;

	delete zrtpContext->zrtpEngine;
	zrtpContext->zrtpEngine = NULL;

	delete zrtpContext->zrtpCallback;
	zrtpContext->zrtpCallback = NULL;

	delete zrtpContext;

	initialized = 0;
}

int32_t ZrtpAdapter_CheckCksum(uint8_t* buffer, uint16_t temp, uint32_t crc) 
{
	return zCRC32::Check(buffer, temp, crc);
}

uint32_t ZrtpAdapter_GenerateCksum(uint8_t* buffer, uint16_t temp)
{
	return zCRC32::Generate(buffer, temp);
}

uint32_t ZrtpAdapter_EndCksum(uint32_t crc)
{
	return zCRC32::End(crc);
}

void ZrtpAdapter_StartZrtpEngine(zZrtpAdapterCtx* zrtpContext)
{
	if (initialized)
		zrtpContext->zrtpEngine->StartEngine();
}

void ZrtpAdapter_StopZrtpEngine(zZrtpAdapterCtx* zrtpContext)
{
	if (initialized)
		zrtpContext->zrtpEngine->StopEngine();
}

void ZrtpAdapter_ProcessZrtpMessage(zZrtpAdapterCtx* zrtpContext, uint8_t *extHeader, uint32_t peerSSRC)
{
	if (initialized)
		zrtpContext->zrtpEngine->ProcessMessage(extHeader, peerSSRC);
}

void ZrtpAdapter_ProcessTimeout(zZrtpAdapterCtx* zrtpContext)
{
	if (initialized)
		zrtpContext->zrtpEngine->ProcessTimeout();
}

void ZrtpAdapter_SetAuxSecret(zZrtpAdapterCtx* zrtpContext, uint8_t* data, int32_t length)
{
	if (initialized)
		zrtpContext->zrtpEngine->SetAuxillarySecret(data, length);
}

void ZrtpAdapter_SetPbxSecret(zZrtpAdapterCtx* zrtpContext, uint8_t* data, int32_t length)
{
	if (initialized)
		zrtpContext->zrtpEngine->SetPBXSecret(data, length);
}

int32_t ZrtpAdapter_InState(zZrtpAdapterCtx* zrtpContext, int32_t state)
{
	if (initialized)
		return (zrtpContext->zrtpEngine->CheckCurrentState(state) ? 1 : 0);

	return 0;
}

void ZrtpAdapter_SASVerified(zZrtpAdapterCtx* zrtpContext)
{
	if (initialized)
		zrtpContext->zrtpEngine->SetSASVerified();
}

void ZrtpAdapter_ResetSASVerified(zZrtpAdapterCtx* zrtpContext)
{
	if (initialized)
		zrtpContext->zrtpEngine->ResetSASVerifiedFlag();
}

char* ZrtpAdapter_GetHelloHash(zZrtpAdapterCtx* zrtpContext)
{
	std::string ret;

	if (initialized)
		ret.assign(zrtpContext->zrtpEngine->GetHelloHashData());
	else
		return NULL;

	if (ret.size() == 0)
		return NULL;

	memset(g_HelloHashRetBuff, 0, g_HelloHashRetBuffSize);
	strcpy(g_HelloHashRetBuff, ret.c_str());

	return g_HelloHashRetBuff;
}

char* ZrtpAdapter_GetMultiStrParams(zZrtpAdapterCtx* zrtpContext, int32_t *length)
{
	std::string ret;

	*length = 0;
	if (initialized)
		ret.assign(zrtpContext->zrtpEngine->GetMultiStreamParams());
	else
		return NULL;

	if (ret.size() == 0)
		return NULL;

	memset(g_MultiStrParamsRetBuff, 0, g_MultiStrParamsRetBuffSize);
	strcpy(g_MultiStrParamsRetBuff, ret.c_str());

	return g_MultiStrParamsRetBuff;
}

void ZrtpAdapter_SetMultiStrParams(zZrtpAdapterCtx* zrtpContext, char* parameters, int32_t length)
{
	if (!initialized)
		return;

	if (parameters == NULL)
		return;

	zrtpContext->zrtpEngine->SetMultiStreamParams(std::string(parameters, length));
}

int32_t ZrtpAdapter_IsMultiStream(zZrtpAdapterCtx* zrtpContext)
{
	if (initialized)
		return zrtpContext->zrtpEngine->CheckIsMultiStream() ? 1 : 0;

	return 0;
}

int32_t ZrtpAdapter_IsMultiStreamAvailable(zZrtpAdapterCtx* zrtpContext)
{
	if (initialized)
		return (zrtpContext->zrtpEngine->CheckIsMultiStreamAvailable() ? 1 : 0);

	return 0;
}

void ZrtpAdapter_AcceptEnrollment(zZrtpAdapterCtx* zrtpContext, int32_t accepted)
{
	if (initialized)
		return zrtpContext->zrtpEngine->AcceptEnrollRequest(accepted == 0 ? false : true);
}

void ZrtpAdapter_SetPBXEnrollment(zZrtpAdapterCtx* zrtpContext, int32_t yesNo)
{
	if (initialized)
		return zrtpContext->zrtpEngine->SetPBXEnroll(yesNo == 0 ? false : true);
}

int32_t ZrtpAdapter_SetSignatureData(zZrtpAdapterCtx* zrtpContext, uint8_t* data, int32_t length)
{
	if (initialized)
		return zrtpContext->zrtpEngine->SetSignatureData(data, length) ? 1 : 0;

	return 0;
}

int32_t ZrtpAdapter_GetSignatureData(zZrtpAdapterCtx* zrtpContext, uint8_t* data)
{
	if (initialized)
		return zrtpContext->zrtpEngine->GetSignatureData(data);

	return 0;
}

int32_t ZrtpAdapter_GetSignatureLength(zZrtpAdapterCtx* zrtpContext)
{
	if (initialized)
		return zrtpContext->zrtpEngine->GetSignatureLength();

	return 0;
}

void ZrtpAdapter_Conf2AckSecure(zZrtpAdapterCtx* zrtpContext)
{
	if (initialized)
		zrtpContext->zrtpEngine->Conf2AckSecure();
}

int32_t ZrtpAdapter_GetZid(zZrtpAdapterCtx* zrtpContext, uint8_t* data)
{
	if (data == NULL)
		return 0;

	if (initialized)
		return zrtpContext->zrtpEngine->GetOtherEndpointZidData(data);

	return 0;
}

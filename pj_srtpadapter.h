/*

Copyright 2010-2011 iCall, Inc.

This file is part of Open ZRTP.

Open ZRTP is free software: you can redistribute it and/or modify it under the terms of the GNU Lesser General Public License as published bythe Free Software Foundation, either version 3 of the License, or(at your option) any later version.

Open ZRTP is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU Lesser General Public License for more details.

You should have received a copy of the GNU Lesser General Public Licensealong with Open ZRTP. If not, see http://www.gnu.org/licenses/.

*/

#ifndef __pj_srtpadapter_h__
#define __pj_srtpadapter_h__

#include "int.h"

#ifdef __cplusplus
extern "C"
{
#endif

	typedef struct zCryptoContext zCryptoContext;

	typedef struct SrtpAdapterCtx
	{
		int32_t	 callId;
		zCryptoContext* srtp;
		void* userData;
	} SrtpAdapterCtx_t;

	SrtpAdapterCtx_t* CreateSrtpAdapterCtx (
		int32_t	 callId,
		uint32_t ssrc,
		int32_t roc,
		int64_t	 keyDerivRate,
		const  int32_t ealg,
		const  int32_t aalg,
		uint8_t* masterKey,
		int32_t	 masterKeyLength,
		uint8_t* masterSalt,
		int32_t	 masterSaltLength,
		int32_t	 ekeyl,
		int32_t	 akeyl,
		int32_t	 skeyl,
		int32_t	 tagLength);

	void SrtpDestroyWrapper (
		SrtpAdapterCtx_t* ctx );

	int32_t SrtpProtect (
		SrtpAdapterCtx_t* ctx,
		uint8_t* buffer,
		int32_t length,
		int32_t* newLength );

	int32_t SrtpUnprotect (
		SrtpAdapterCtx_t* ctx,
		uint8_t* buffer,
		int32_t length,
		int32_t* newLength );

	void SrtpNewCryptoContextForSSRC (
		SrtpAdapterCtx_t* ctx,
		uint32_t ssrc,
		int32_t roc,
		int64_t keyDerivRate );

	void SrtpDeriveSrtpKeys (
		SrtpAdapterCtx_t* ctx,
		uint64_t index );

#ifdef __cplusplus
}
#endif


#endif // __pj_srtpadapter_h__

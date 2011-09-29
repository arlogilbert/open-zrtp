/*

Copyright 2010-2011 iCall, Inc.

This file is part of Open ZRTP.

Open ZRTP is free software: you can redistribute it and/or modify it under the terms of the GNU Lesser General Public License as published bythe Free Software Foundation, either version 3 of the License, or(at your option) any later version.

Open ZRTP is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU Lesser General Public License for more details.

You should have received a copy of the GNU Lesser General Public Licensealong with Open ZRTP. If not, see http://www.gnu.org/licenses/.

*/


#ifndef __zopenssl_h__
#define __zopenssl_h__

#include <stdio.h>
#include <openssl/evp.h>

#include "int.h"
#include "zAlgoSupported.h"
#include "zRtpConfig.h"

#ifdef OPENSSL_SYS_WIN32
#include <windows.h>
#endif

#if defined SOLARIS && !defined HAVE_PTHREAD_H
#include <synch.h>
#include <thread.h>
#endif

#if defined HAVE_PTHREAD_H && !defined SOLARIS
#include <pthread.h>
#endif

#ifdef const
#undef const
#endif

#include "synch.h"

class ZOpenSSL
{
public:
	~ZOpenSSL();
	static ZOpenSSL* GetInstance();

private:
	static ZOpenSSL* instance;

	static Sync mutex;

#ifdef OPENSSL_SYS_WIN32
	HANDLE* lock_cs;
#else
	void* lock_cs;
#endif

	long* lock_count;

	void ThreadLockSetup(void);
	void ThreadLockCleanup(void);
	void MyLockingCallback(int, int, const char*, int);

	static void g_myLockingCallback(int, int, const char*, int);

	ZOpenSSL();
};

struct Sha256
{
	static const int DigestLength = 32;

	static void Compute(unsigned char *data, unsigned int dataLength, unsigned char* hashImage );
	static void Compute(unsigned char * data_chunks[], unsigned int dataChunckLength[], unsigned char* hashImage);
	static void* CreateSha256Context();
	static void CloseSha256Context(void* ctx, unsigned char* hashImage);
	static void UpdateShaContext(void* ctx, unsigned char* data, unsigned int dataLength);
	static void UpdateShaContext(void* ctx, unsigned char* dataChunks[], unsigned int dataChunkLength[]);
};

struct Hmac256
{
	static void* CreateSha1HmacContext(uint8_t* key, int32_t keyLength);
	static void UpdateSha1Ctx(void* ctx, const uint8_t* data, uint32_t dataLength, uint8_t* mac, int32_t* macLength);
	static void UpdateSha1Ctx(void* ctx, const uint8_t* data[], uint32_t dataLength[], uint8_t* mac, int32_t* macLength);
	static void FreeSha1HmacContext(void* ctx);

	static void Compute(uint8_t* key, uint32_t keyLength, uint8_t* data, int32_t dataLength, uint8_t* mac, uint32_t* macLength);
	static void Compute(uint8_t* key, uint32_t keyLength, uint8_t* dataChunks[], uint32_t dataChuncksLength[], uint8_t* mac, uint32_t* macLength);
};

typedef struct F8ChiperCtx {
	unsigned char *S;			
	unsigned char *ivAccent;	
	uint32_t J;					
} F8ChiperCtx_t;

struct zAesSrtp
{
public:
	zAesSrtp(int algo = SrtpEncryptionAESCM);
	zAesSrtp(uint8_t* key, int32_t key_length, int algo = SrtpEncryptionAESCM);
	~zAesSrtp();

	void Encrypt(const uint8_t* input, uint8_t* output );
	bool SetNewKey(const uint8_t* key, int32_t keyLength);
	void GetCipherStream(uint8_t* output, uint32_t length, uint8_t* iv);

	void EncryptCtr (
		const uint8_t* input,
		uint32_t inputLen,
		uint8_t* output, uint8_t* iv );

	void EncryptCtr (
		uint8_t* data,
		uint32_t data_length,
		uint8_t* iv );

	void EncryptF8 (
		const uint8_t* data,
		uint32_t dataLen,
		uint8_t* iv,
		uint8_t* key,
		int32_t	 keyLen,
		uint8_t* salt,
		int32_t	 saltLen,
		zAesSrtp* f8Cipher);

	void EncryptF8 (
		const uint8_t* data,
		uint32_t dataLen,
		uint8_t* out,
		uint8_t* iv,
		uint8_t* key,
		int32_t	 keyLen,
		uint8_t* salt,
		int32_t	 saltLen,
		zAesSrtp* f8Cipher);

private:
	int doProcessBlock (
		F8ChiperCtx_t* f8ctx,
		const uint8_t* in,
		int32_t length,
		uint8_t* out );

	void* key;
	int32_t algorithm;
};

struct ZAes
{
	static void Encrypt(uint8_t* key, int32_t keyLength, uint8_t* IV, uint8_t *data, int32_t dataLength);
	static void Decrypt(uint8_t* key, int32_t keyLength, const uint8_t* IV, uint8_t *data, int32_t dataLength);
};

#endif // __zopenssl_h__

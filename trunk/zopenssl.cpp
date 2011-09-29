/*

Copyright 2010-2011 iCall, Inc.

This file is part of Open ZRTP.

Open ZRTP is free software: you can redistribute it and/or modify it under the terms of the GNU Lesser General Public License as published bythe Free Software Foundation, either version 3 of the License, or(at your option) any later version.

Open ZRTP is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU Lesser General Public License for more details.

You should have received a copy of the GNU Lesser General Public Licensealong with Open ZRTP. If not, see http://www.gnu.org/licenses/.

*/


#include "network.h"
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <openssl/crypto.h>
#include <openssl/sha.h>
#include <openssl/hmac.h>
#include <openssl/aes.h>
#include "zopenssl.h"

Sync ZOpenSSL::mutex;
ZOpenSSL* ZOpenSSL::instance;

ZOpenSSL::ZOpenSSL()
{
	ThreadLockSetup();
}

ZOpenSSL::~ZOpenSSL()
{
	ThreadLockCleanup();
}

ZOpenSSL* ZOpenSSL::GetInstance()
{
	if(instance==NULL)
	{
		mutex.Enter();
		if(instance == NULL)
		{
			instance = new ZOpenSSL();
		}
		mutex.Leave();
	}
	return instance;
}

void ZOpenSSL::ThreadLockSetup(void)
{
	int i = 0;

#ifdef OPENSSL_SYS_WIN32

	lock_cs=(HANDLE*)OPENSSL_malloc(CRYPTO_num_locks() * sizeof(HANDLE));
	for(i=0; i<CRYPTO_num_locks(); i++)
	{
		lock_cs[i] = CreateMutex(NULL, FALSE, NULL);
	}

	CRYPTO_set_locking_callback(&g_myLockingCallback);

#endif

#if defined SOLARIS && !defined HAVE_PTHREAD_H

	lock_cs = OPENSSL_malloc(CRYPTO_num_locks() * sizeof(mutex_t));
	lock_count = OPENSSL_malloc(CRYPTO_num_locks() * sizeof(long));
	for(i=0; i<CRYPTO_num_locks(); i++)
	{
		lock_count[i] = 0;
		mutex_init(&(((pthread_mutex_t*)lock_cs)[i]), USYNC_THREAD, NULL);
	}
	CRYPTO_set_locking_callback((void (*)(int, int, const char *, int))MyLockingCallback);
#endif

#if defined HAVE_PTHREAD_H && !defined SOLARIS && !defined WIN32

	lock_cs = (pthread_mutex_t*)OPENSSL_malloc(CRYPTO_num_locks() * sizeof(pthread_mutex_t));
	lock_count = (long*)OPENSSL_malloc(CRYPTO_num_locks() * sizeof(long));

	for(i=0; i<CRYPTO_num_locks(); i++)
	{
		lock_count[i] = 0;
		pthread_mutex_init(&(((pthread_mutex_t*)lock_cs)[i]), NULL);
	}

	CRYPTO_set_locking_callback((void (*)(int, int, const char*, int))MyLockingCallback);

#endif

}

void ZOpenSSL::ThreadLockCleanup(void)
{
	int i = 0;

#ifdef OPENSSL_SYS_WIN32
	CRYPTO_set_locking_callback(NULL);
	for(i=0; i<CRYPTO_num_locks(); i++)
	{
		CloseHandle(((HANDLE*)lock_cs)[i]);
	}

	OPENSSL_free((HANDLE*)lock_cs);
#endif

#if defined SOLARIS && !defined HAVE_PTHREAD_H

	CRYPTO_set_locking_callback(NULL);

	fprintf(stderr,"cleanup\n");

	for(i=0; i<CRYPTO_num_locks(); i++)
	{
		mutex_destroy(&(((pthread_mutex_t*)lock_cs)[i]));
		fprintf(stderr,"%8ld:%s\n", lock_count[i],CRPTO_get_lock_name(i));
	}


	OPENSSL_free(((pthread_mutex_t*)lock_cs));
	OPENSSL_free(lock_count);

#endif

#if defined HAVE_PTHREAD_H && !defined SOLARIS && !defined WIN32


	CRYPTO_set_locking_callback(NULL);
	fprintf(stderr,"cleanup\n");
	for(i=0; i<CRYPTO_num_locks(); i++)
	{
		pthread_mutex_destroy(&(((pthread_mutex_t*)lock_cs)[i]));
		fprintf(stderr, "%8ld:%s\n", lock_count[i],
			CRYPTO_get_lock_name(i));
	}

	OPENSSL_free(((pthread_mutex_t*)lock_cs));
	OPENSSL_free(lock_count);
#endif

}

void ZOpenSSL::g_myLockingCallback(int mode, int type, const char *file, int line)
{
	ZOpenSSL::GetInstance()->MyLockingCallback(mode, type, file, line);
}

void ZOpenSSL::MyLockingCallback(int mode, int type, const char *file, int line)
{
    (mode);
	(line);
	(file);

#ifdef OPENSSL_SYS_WIN32
	if(mode & CRYPTO_LOCK)
	{
		WaitForSingleObject(((HANDLE*)lock_cs)[type], INFINITE);
	}
	else ReleaseMutex(((HANDLE*)lock_cs)[type]);
#endif

#if defined SOLARIS && !defined HAVE_PTHREAD_H
	if(mode & CRYPTO_LOCK)
	{
		mutex_lock(&(((pthread_mutex_t*)lock_cs)[type]));
		lock_count[type]++;
	}
	else mutex_unlock(&(((pthread_mutex_t*)lock_cs)[type]));
#endif

#if defined HAVE_PTHREAD_H && !defined SOLARIS && !defined WIN32
	if(mode & CRYPTO_LOCK)
	{
		pthread_mutex_lock(&(((pthread_mutex_t*)lock_cs)[type]));
		lock_count[type]++;
	}
	else pthread_mutex_unlock(&(((pthread_mutex_t*)lock_cs)[type]));
#endif
}

void Sha256::Compute (
	unsigned char *data, unsigned int data_length,
	unsigned char *digest )
{
	SHA256(data, data_length, digest);
}

void Sha256::Compute (
	unsigned char * data_chunks[],
	unsigned int data_chunck_length[],
	unsigned char *digest )
{
	SHA256_CTX ctx;
	SHA256_Init( &ctx);
	while(*data_chunks)
	{
		SHA256_Update(&ctx, *data_chunks, *data_chunck_length);
		data_chunks++;
		data_chunck_length++;
	}
	SHA256_Final(digest, &ctx);
}

void* Sha256::CreateSha256Context()
{
	SHA256_CTX* ctx = (SHA256_CTX*)malloc(sizeof (SHA256_CTX));
	SHA256_Init(ctx);
	return (void*)ctx;
}

void Sha256::CloseSha256Context (
	void* ctx,
	unsigned char* digest )
{
	SHA256_CTX* hd = (SHA256_CTX*)ctx;

	if (digest != NULL)
	{
		SHA256_Final(digest, hd);
	}
	free(hd);
}

void Sha256::UpdateShaContext (
	void* ctx, unsigned char* data,
	unsigned int dataLength )
{
	SHA256_CTX* hd = (SHA256_CTX*)ctx;
	SHA256_Update(hd, data, dataLength);
}

void Sha256::UpdateShaContext (
	void* ctx, unsigned char* dataChunks[],
	unsigned int dataChunkLength[] )
{
	SHA256_CTX* hd = (SHA256_CTX*)ctx;

	while (*dataChunks)
	{
		SHA256_Update (hd, *dataChunks, *dataChunkLength);
		dataChunks++;
		dataChunkLength++;
	}
}

void* Hmac256::CreateSha1HmacContext (
	uint8_t* key,
	int32_t key_length )
{
	HMAC_CTX* ctx = (HMAC_CTX*)malloc(sizeof(HMAC_CTX));

	HMAC_CTX_init(ctx);
	HMAC_Init_ex(ctx, key, key_length, EVP_sha1(), NULL);
	return ctx;
}

void Hmac256::UpdateSha1Ctx (
	void* ctx, const uint8_t* data, uint32_t data_length,
	uint8_t* mac, int32_t* mac_length )
{
	HMAC_CTX* pctx = (HMAC_CTX*)ctx;

	HMAC_Init_ex(pctx, NULL, 0, NULL, NULL );
	HMAC_Update(pctx, data, data_length );
	HMAC_Final(pctx, mac, reinterpret_cast<uint32_t*>(mac_length) );
}

void Hmac256::UpdateSha1Ctx (
	void* ctx, const uint8_t* data[], uint32_t data_length[],
	uint8_t* mac, int32_t* mac_length )
{
	HMAC_CTX* pctx = (HMAC_CTX*)ctx;

	HMAC_Init_ex(pctx, NULL, 0, NULL, NULL );
	while (*data)
	{
		HMAC_Update(pctx, *data, *data_length);
		data++;
		data_length++;
	}
	HMAC_Final(pctx, mac, reinterpret_cast<uint32_t*>(mac_length) );
}

void Hmac256::FreeSha1HmacContext (
	void* ctx )
{
	if (ctx)
	{
		HMAC_CTX_cleanup((HMAC_CTX*)ctx);
		free(ctx);
	}
}

void Hmac256::Compute (
	uint8_t* key, uint32_t key_length,
	uint8_t* data, int32_t data_length,
	uint8_t* mac, uint32_t* mac_length )
{
	unsigned int tmp;
	HMAC( EVP_sha256(), key, key_length, data, data_length, mac, &tmp );
	*mac_length = tmp;
}

void Hmac256::Compute (
	uint8_t* key, uint32_t key_length,
	uint8_t* data_chunks[],
	uint32_t data_chunck_length[],
	uint8_t* mac, uint32_t* mac_length )
{
	unsigned int tmp;
	HMAC_CTX ctx;
	HMAC_CTX_init( &ctx );
	HMAC_Init_ex( &ctx, key, key_length, EVP_sha256(), NULL );
	while( *data_chunks ){
		HMAC_Update( &ctx, *data_chunks, *data_chunck_length );
		data_chunks ++;
		data_chunck_length ++;
	}
	HMAC_Final( &ctx, mac, &tmp);
	*mac_length = tmp;
	HMAC_CTX_cleanup( &ctx );
}

zAesSrtp::zAesSrtp(int algo)
	: key(NULL)
	, algorithm(algo)
{
}

zAesSrtp::zAesSrtp( uint8_t* k, int32_t keyLength, int algo )
	: key(NULL)
	, algorithm(algo)
{
	SetNewKey(k, keyLength);
}

zAesSrtp::~zAesSrtp()
{
	if (key != NULL)
		delete[] (uint8_t*)key;
}

bool zAesSrtp::SetNewKey (
	const uint8_t* k,
	int32_t keyLength )
{
	// release an existing key before setting a new one
	if (key != NULL)
		delete[] (uint8_t*)key;

	if (!(keyLength == 16 || keyLength == 32))
	{
		return false;
	}
	if (algorithm == SrtpEncryptionAESCM)
	{
		key = new uint8_t[sizeof(AES_KEY)];
		memset(key, 0, sizeof(AES_KEY) );
		AES_set_encrypt_key(k, keyLength*8, (AES_KEY *)key);
	}
	else
	{
		return false;
	}

	return true;
}


void zAesSrtp::Encrypt (
	const uint8_t* input,
	uint8_t* output )
{
	if (algorithm == SrtpEncryptionAESCM)
	{
		AES_encrypt(input, output, (AES_KEY *)key);
	}
	else
	{
	}
}

void zAesSrtp::GetCipherStream (
	uint8_t* output, uint32_t length,
	uint8_t* iv )
{
	uint16_t ctr = 0;
	unsigned char temp[SRTP_BLOCK_SIZE];

	for(ctr = 0; ctr < length/SRTP_BLOCK_SIZE; ctr++)
	{
		//compute the cipher stream
		iv[14] = (uint8_t)((ctr & 0xFF00) >>  8);
		iv[15] = (uint8_t)((ctr & 0x00FF));

		Encrypt(iv, &output[ctr*SRTP_BLOCK_SIZE]);
	}
	if ((length % SRTP_BLOCK_SIZE) > 0)
	{
		// Treat the last bytes:
		iv[14] = (uint8_t)((ctr & 0xFF00) >>  8);
		iv[15] = (uint8_t)((ctr & 0x00FF));

		Encrypt(iv, temp);
		memcpy(&output[ctr*SRTP_BLOCK_SIZE], temp, length % SRTP_BLOCK_SIZE );
	}
}

void zAesSrtp::EncryptCtr (
	const uint8_t* input, uint32_t input_length,
	uint8_t* output, uint8_t* iv )
{
	if (key == NULL)
		return;

	uint16_t ctr = 0;
	unsigned char temp[SRTP_BLOCK_SIZE];

	int l = input_length/SRTP_BLOCK_SIZE;
	for (ctr = 0; ctr < l; ctr++ )
	{
		iv[14] = (uint8_t)((ctr & 0xFF00) >>  8);
		iv[15] = (uint8_t)((ctr & 0x00FF));

		Encrypt(iv, temp);
		for (int i = 0; i < SRTP_BLOCK_SIZE; i++ )
		{
			*output++ = temp[i] ^ *input++;
		}

	}
	l = input_length % SRTP_BLOCK_SIZE;
	if (l > 0)
	{
		// Treat the last bytes:
		iv[14] = (uint8_t)((ctr & 0xFF00) >>  8);
		iv[15] = (uint8_t)((ctr & 0x00FF));

		Encrypt(iv, temp);
		for (int i = 0; i < l; i++ )
		{
			*output++ = temp[i] ^ *input++;
		}
	}
}

void zAesSrtp::EncryptCtr (
	uint8_t* data,
	uint32_t data_length,
	uint8_t* iv )
{
	if (key == NULL)
		return;

	uint16_t ctr = 0;
	unsigned char temp[SRTP_BLOCK_SIZE];

	int l = data_length/SRTP_BLOCK_SIZE;
	for (ctr = 0; ctr < l; ctr++ )
	{
		iv[14] = (uint8_t)((ctr & 0xFF00) >>  8);
		iv[15] = (uint8_t)((ctr & 0x00FF));

		Encrypt(iv, temp);
		for (int i = 0; i < SRTP_BLOCK_SIZE; i++ )
		{
			*data++ ^= temp[i];
		}

	}
	l = data_length % SRTP_BLOCK_SIZE;
	if (l > 0)
	{
		// Treat the last bytes:
		iv[14] = (uint8_t)((ctr & 0xFF00) >>  8);
		iv[15] = (uint8_t)((ctr & 0x00FF));

		Encrypt(iv, temp);
		for (int i = 0; i < l; i++ )
		{
			*data++ ^= temp[i];
		}
	}
}

void zAesSrtp::EncryptF8 (
	const uint8_t* data, uint32_t data_length,
	uint8_t* iv, uint8_t* origKey, int32_t keyLen,
	uint8_t* salt, int32_t saltLen, zAesSrtp* f8Cipher )
{
	EncryptF8(data, data_length, const_cast<uint8_t*>(data), iv, origKey, keyLen, salt, saltLen, f8Cipher);
}

#define MAX_KEYLEN 32

void zAesSrtp::EncryptF8 (
	const uint8_t* in, uint32_t in_length, uint8_t* out,
	uint8_t* iv, uint8_t* origKey, int32_t keyLen,
	uint8_t* salt, int32_t saltLen, zAesSrtp* f8Cipher )
{
	unsigned char *cp_in, *cp_in1, *cp_out;
	int i;
	int offset = 0;

	unsigned char ivAccent[SRTP_BLOCK_SIZE];
	unsigned char maskedKey[MAX_KEYLEN];
	unsigned char saltMask[MAX_KEYLEN];
	unsigned char S[SRTP_BLOCK_SIZE];

	F8ChiperCtx_t f8ctx;

	if (key == NULL)
		return;

	if (keyLen > MAX_KEYLEN)
		return;

	if (saltLen > keyLen)
		return;


	f8ctx.ivAccent = ivAccent;


	memcpy(saltMask, salt, saltLen);
	memset(saltMask+saltLen, 0x55, keyLen-saltLen);


	cp_out = maskedKey;
	cp_in = origKey;
	cp_in1 = saltMask;
	for (i = 0; i < keyLen; i++)
	{
		*cp_out++ = *cp_in++ ^ *cp_in1++;
	}

	f8Cipher->SetNewKey(maskedKey, keyLen);


	f8Cipher->Encrypt(iv, f8ctx.ivAccent);

	f8ctx.J = 0;					   // initialize the counter
	f8ctx.S = S;			   // get the key stream buffer

	memset(f8ctx.S, 0, SRTP_BLOCK_SIZE); // initial value for key stream

	while (in_length >= SRTP_BLOCK_SIZE)
	{
		doProcessBlock(&f8ctx, in+offset, SRTP_BLOCK_SIZE, out+offset);
		in_length -= SRTP_BLOCK_SIZE;
		offset += SRTP_BLOCK_SIZE;
	}
	if (in_length > 0)
	{
		doProcessBlock(&f8ctx, in+offset, in_length, out+offset);
	}
}

int zAesSrtp::doProcessBlock (
	F8ChiperCtx_t *f8ctx,
	const uint8_t* in,
	int32_t length,
	uint8_t* out )
{
	int i;
	const uint8_t *cp_in;
	uint8_t* cp_in1, *cp_out;
	uint32_t *ui32p;


	cp_in = f8ctx->ivAccent;
	cp_out = f8ctx->S;
	for (i = 0; i < SRTP_BLOCK_SIZE; i++)
	{
		*cp_out++ ^= *cp_in++;
	}

	ui32p = (uint32_t *)f8ctx->S;
	ui32p[3] ^= htonl(f8ctx->J);
	f8ctx->J++;

	Encrypt(f8ctx->S, f8ctx->S);

	cp_out = out;
	cp_in = in;
	cp_in1 = f8ctx->S;
	for (i = 0; i < length; i++)
	{
		*cp_out++ = *cp_in++ ^ *cp_in1++;
	}
	return length;
}


void ZAes::Encrypt (
	uint8_t* key, int32_t keyLength,
	uint8_t* IV, uint8_t *data,
	int32_t dataLength )
{
	AES_KEY aesKey;
	int usedBytes = 0;

	memset(&aesKey, 0, sizeof( AES_KEY ) );
	if (keyLength == 16)
	{
		AES_set_encrypt_key(key, 128, &aesKey);
	}
	else if (keyLength == 32)
	{
		AES_set_encrypt_key(key, 256, &aesKey);
	}
	else
	{
		return;
	}
	AES_cfb128_encrypt(data, data, dataLength, &aesKey,
		IV, &usedBytes, AES_ENCRYPT);
}


void ZAes::Decrypt (
	uint8_t* key, int32_t keyLength,
	const uint8_t* IV, uint8_t *data,
	int32_t dataLength )
{
	AES_KEY aesKey;
	int usedBytes = 0;

	memset(&aesKey, 0, sizeof( AES_KEY ) );
	if (keyLength == 16)
	{
		AES_set_encrypt_key(key, 128, &aesKey);
	}
	else if (keyLength == 32)
	{
		AES_set_encrypt_key(key, 256, &aesKey);
	}
	else
	{
		return;
	}
	AES_cfb128_encrypt(data, data, dataLength, &aesKey,
		(unsigned char*)IV, &usedBytes, AES_DECRYPT);
}

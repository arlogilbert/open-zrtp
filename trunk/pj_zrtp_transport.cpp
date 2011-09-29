/*

Copyright 2010-2011 iCall, Inc.

This file is part of Open ZRTP.

Open ZRTP is free software: you can redistribute it and/or modify it under the terms of the GNU Lesser General Public License as published bythe Free Software Foundation, either version 3 of the License, or(at your option) any later version.

Open ZRTP is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU Lesser General Public License for more details.

You should have received a copy of the GNU Lesser General Public Licensealong with Open ZRTP. If not, see http://www.gnu.org/licenses/.

*/


#include <pj/config.h>
#include <pj/types.h>
#include <pjmedia/endpoint.h>
#include <pjmedia/transport.h>
#include <pjlib.h>
#include <pjlib-util.h>

#include "zCodes.h"
#include "pj_zrtpadapter.h"
#include "pj_srtpadapter.h"
#include "pj_zrtp_transport.h"
#include "zTextData.h"

#define THIS_FILE "pj_zrtp_transport.cpp"

static pj_status_t transport_get_info (
	pjmedia_transport* tp,
	pjmedia_transport_info* info );

static pj_status_t transport_attach (
	pjmedia_transport* tp,
	void* user_data,
	const pj_sockaddr_t* rem_addr,
	const pj_sockaddr_t* rem_rtcp,
	unsigned addr_len,
	void (*rtp_cb)(void*, void*, pj_ssize_t),
	void (*rtcp_cb)(void*, void*, pj_ssize_t) );

static void transport_detach (
	pjmedia_transport* tp,
	void* strm );

static pj_status_t transport_send_rtp (
	pjmedia_transport* tp,
	const void* pkt,
	pj_size_t size );

static pj_status_t transport_send_rtcp (
	pjmedia_transport* tp,
	const void* pkt,
	pj_size_t size );

static pj_status_t transport_send_rtcp2 (
	pjmedia_transport* tp,
	const pj_sockaddr_t* addr,
	unsigned addr_len,
	const void* pkt,
	pj_size_t size );

static pj_status_t transport_media_create (
	pjmedia_transport* tp,
	pj_pool_t* sdp_pool,
	unsigned options,
	const pjmedia_sdp_session* rem_sdp,
	unsigned media_index );

static pj_status_t transport_encode_sdp (
	pjmedia_transport* tp,
	pj_pool_t* sdp_pool,
	pjmedia_sdp_session* local_sdp,
	const pjmedia_sdp_session* rem_sdp,
	unsigned media_index );

static pj_status_t transport_media_start (
	pjmedia_transport* tp,
	pj_pool_t* pool,
	const pjmedia_sdp_session* local_sdp,
	const pjmedia_sdp_session* rem_sdp,
	unsigned media_index );

static pj_status_t transport_media_stop (
	pjmedia_transport* tp );

static pj_status_t transport_simulate_lost (
	pjmedia_transport* tp,
	pjmedia_dir dir,
	unsigned pct_lost );

static pj_status_t transport_destroy (
	pjmedia_transport* tp );

static struct pjmedia_transport_op tp_zrtp_op =
{
	&transport_get_info,
	&transport_attach,
	&transport_detach,
	&transport_send_rtp,
	&transport_send_rtcp,
	&transport_send_rtcp2,
	&transport_media_create,
	&transport_encode_sdp,
	&transport_media_start,
	&transport_media_stop,
	&transport_simulate_lost,
	&transport_destroy
};

struct tp_zrtp
{
	pjmedia_transport base;
	pj_pool_t* pool;
	void* stream_user_data;

	void (*stream_rtp_cb) (
		void* user_data,
		void* pkt,
		pj_ssize_t );

	void (*stream_rtcp_cb) (
		void* user_data,
		void* pkt,
		pj_ssize_t );

	int32_t callId;
	uint64_t protect;
	uint64_t unprotect;
	int32_t	 unprotect_err;
	int32_t refcount;
	pj_timer_entry timeoutEntry;
	pj_mutex_t* zrtpMutex;
	SrtpAdapterCtx_t* srtpReceive;
	SrtpAdapterCtx_t* srtpSend;
	void* sendBuffer;
	pj_uint8_t* zrtpBuffer;
	pj_int32_t sendBufferLen;
	pj_uint32_t peerSSRC;		
	pj_uint32_t localSSRC;		
	const pj_char_t* clientIdString;
	pjmedia_transport  * slave_tp;
	zrtp_UserCallbacks* userCallback;
	zZrtpAdapterCtx* zrtpCtx;
	pj_uint16_t zrtpSeq;
	pj_bool_t enableZrtp;
	pj_bool_t started;
	pj_bool_t close_slave;
};

static int32_t zrtp_sendDataZRTP (
	zZrtpAdapterCtx* ctx,
	const uint8_t* data,
	int32_t length );

static int32_t zrtp_activateTimer (
	zZrtpAdapterCtx* ctx,
	int32_t time );

static int32_t zrtp_cancelTimer (
	zZrtpAdapterCtx* ctx );

static void zrtp_sendInfo (
	zZrtpAdapterCtx* ctx,
	int32_t severity,
	int32_t subCode );

static int32_t zrtp_srtpSecretsReady (
	zZrtpAdapterCtx* ctx,
	c_srtp_secrets_t* secrets,
	int32_t part );

static void zrtp_srtpSecretsOff (
	zZrtpAdapterCtx* ctx,
	int32_t part );

static void zrtp_srtpSecretsOn (
	zZrtpAdapterCtx* ctx,
	char* c,
	char* s,
	int32_t verified );

static void zrtp_handleGoClear (
	zZrtpAdapterCtx* ctx );

static void zrtp_zrtpNegotiationFailed (
	zZrtpAdapterCtx* ctx,
	int32_t severity,
	int32_t subCode );

static void zrtp_zrtpNotSuppOther (
	zZrtpAdapterCtx* ctx );

static void zrtp_synchEnter (
	zZrtpAdapterCtx* ctx );

static void zrtp_synchLeave (
	zZrtpAdapterCtx* ctx );

static void zrtp_zrtpAskEnrollment (
	zZrtpAdapterCtx* ctx,
	char* info );

static void zrtp_zrtpInformEnrollment (
	zZrtpAdapterCtx* ctx,
	char* info );

static void zrtp_signSAS (
	zZrtpAdapterCtx* ctx,
	char* sas );

static int32_t zrtp_checkSASSignature (
	zZrtpAdapterCtx* ctx,
	char* sas );

static zrtp_Callbacks c_callbacks =
{
	&zrtp_sendDataZRTP,
	&zrtp_activateTimer,
	&zrtp_cancelTimer,
	&zrtp_sendInfo,
	&zrtp_srtpSecretsReady,
	&zrtp_srtpSecretsOff,
	&zrtp_srtpSecretsOn,
	&zrtp_handleGoClear,
	&zrtp_zrtpNegotiationFailed,
	&zrtp_zrtpNotSuppOther,
	&zrtp_synchEnter,
	&zrtp_synchLeave,
	&zrtp_zrtpAskEnrollment,
	&zrtp_zrtpInformEnrollment,
	&zrtp_signSAS,
	&zrtp_checkSASSignature
};

static void timer_callback (
	pj_timer_heap_t* ht,
	pj_timer_entry* e );

static pj_thread_t* thread_run;
static pj_pool_t* timer_pool;
static pj_timer_heap_t* timer;
static pj_sem_t* timer_sem;
static pj_bool_t timer_running;
static pj_bool_t timer_initialized = 0;
static pj_mutex_t* timer_mutex;

static void timer_stop()
{
	timer_running = 0;
	pj_sem_post(timer_sem);
}

static int timer_thread_run(void*)
{
	pj_status_t rc;
	pj_time_val tick = {0, 10};

	timer_running = 1;

	while (timer_running)
	{
		if (pj_timer_heap_count(timer) == 0)

		{
			pj_sem_wait(timer_sem);
		}
		else

		{
			rc = pj_thread_sleep(PJ_TIME_VAL_MSEC(tick));
			rc = pj_timer_heap_poll(timer, NULL);
		}
	}
	pj_timer_heap_destroy(timer);
	timer = NULL;
	pj_sem_destroy(timer_sem);
	timer_sem = NULL;
	pj_pool_release(timer_pool);
	timer_pool = NULL;
	timer_initialized = 0;
	return 0;
}

static int timer_initialize()
{
	pj_status_t rc;
	pj_mutex_t* temp_mutex;

	while (true)
	{
		rc = pj_mutex_create_simple(timer_pool, "zrtp_timer", &temp_mutex);
		if (rc != PJ_SUCCESS)
			return rc;

		pj_enter_critical_section();
		if (timer_mutex == NULL)
			timer_mutex = temp_mutex;
		else
			pj_mutex_destroy(temp_mutex);
		pj_leave_critical_section();

		pj_mutex_lock(timer_mutex);

		if (timer_initialized)
		{
			pj_mutex_unlock(timer_mutex);
			return PJ_SUCCESS;
		}

		rc = pj_timer_heap_create(timer_pool, 4, &timer);
		if (rc != PJ_SUCCESS)
			break;

		rc = pj_sem_create(timer_pool, "zrtp_timer", 0, 1, &timer_sem);
		if (rc != PJ_SUCCESS)
			break;

		rc = pj_thread_create(timer_pool, "zrtp_timer", &timer_thread_run, NULL,
			PJ_THREAD_DEFAULT_STACK_SIZE, 0, &thread_run);
		if (rc != PJ_SUCCESS)
			break;

		timer_initialized = 1;
		pj_mutex_unlock(timer_mutex);

		return PJ_SUCCESS;
	}

	if (timer != NULL)
	{
		pj_timer_heap_destroy(timer);
		timer = NULL;
	}

	if (timer_sem != NULL)
	{
		pj_sem_destroy(timer_sem);
		timer_sem = NULL;
	}

	if (timer_mutex != NULL)
	{
		pj_mutex_unlock(timer_mutex);
		pj_mutex_destroy(timer_mutex);
		timer_mutex = NULL;
	}

	return rc;
}

static int timer_add_entry (
	pj_timer_entry* entry,
	pj_time_val* delay )
{
	pj_status_t rc;

	if (timer_initialized && timer != NULL)
	{
		rc = pj_timer_heap_schedule(timer, entry, delay);
		pj_sem_post(timer_sem);
		return rc;
	}
	else
		return PJ_EIGNORED;
}

static int timer_cancel_entry (
	pj_timer_entry* entry )
{
	if (timer_initialized && timer != NULL)
		return pj_timer_heap_cancel(timer, entry);
	else
		return PJ_EIGNORED;
}

PJ_DEF(pj_status_t) pjmedia_transport_zrtp_create (
	int32_t callId,
	pjmedia_endpt *endpt,
	const char *name,
	pjmedia_transport *transport,
	pjmedia_transport **p_tp,
	pj_bool_t close_slave )
{
	pj_pool_t *pool;
	struct tp_zrtp *zrtp;
	pj_status_t rc;

	if (name == NULL)
		name = "tzrtp%p";

	pool = pjmedia_endpt_create_pool(endpt, name, 5*1024, 512);
	zrtp = PJ_POOL_ZALLOC_T(pool, struct tp_zrtp);
	memset(zrtp, 0, sizeof(tp_zrtp));
	zrtp->pool = pool;

	pj_ansi_strncpy(zrtp->base.name, pool->obj_name, sizeof(zrtp->base.name));
	zrtp->base.type = (pjmedia_transport_type) (PJMEDIA_TRANSPORT_TYPE_USER + 2);
	zrtp->base.op = &tp_zrtp_op;

	if (timer_pool == NULL)
	{
		timer_pool = pjmedia_endpt_create_pool(endpt, "zrtp_timer", 256, 256);
		rc = timer_initialize();
		if (rc != PJ_SUCCESS)
		{
			pj_pool_release(timer_pool);
			pj_pool_release(zrtp->pool);
			return rc;
		}
	}

	zrtp->zrtpCtx = CreateZrtpAdapter(callId);

	zrtp->clientIdString = clientID;
	zrtp->zrtpSeq = 1;					
	rc = pj_mutex_create_simple(zrtp->pool, "zrtp", &zrtp->zrtpMutex);
	zrtp->zrtpBuffer = (pj_uint8_t*)pj_pool_zalloc(pool, MAX_ZRTP_SIZE);
	zrtp->sendBuffer = pj_pool_zalloc(pool, MAX_RTP_BUFFER_LEN);

	zrtp->slave_tp = transport;
	zrtp->close_slave = close_slave;

	zrtp->refcount++;
	*p_tp = &zrtp->base;

	return PJ_SUCCESS;
}

PJ_DECL(pj_status_t) pjmedia_transport_zrtp_initialize (
	int32_t call_id,
	pjmedia_transport *tp,
	const char *zidFilename,
	pj_bool_t autoEnable )
{
	struct tp_zrtp *zrtp = (struct tp_zrtp*)tp;
	PJ_ASSERT_RETURN(tp, PJ_EINVAL);

	zrtp->callId = call_id;

	InitializeZrtpEngine(call_id, zrtp->zrtpCtx, &c_callbacks, (char*)zrtp->clientIdString, zidFilename, zrtp);

	zrtp->enableZrtp = autoEnable;

	return PJ_SUCCESS;
}

static void timer_callback (
	pj_timer_heap_t *ht,
	pj_timer_entry *e )
{
	struct tp_zrtp *zrtp = (struct tp_zrtp*)e->user_data;

	ZrtpAdapter_ProcessTimeout(zrtp->zrtpCtx);

	PJ_UNUSED_ARG(ht);
}

static int32_t zrtp_sendDataZRTP (
	zZrtpAdapterCtx* ctx,
	const uint8_t* data,
	int32_t length )
{
	struct tp_zrtp *zrtp = (struct tp_zrtp*)ctx->userData;
	pj_uint16_t totalLen = static_cast<pj_uint16_t>(length + 12);
	pj_uint32_t crc;
	pj_uint8_t* buffer = zrtp->zrtpBuffer;
	pj_uint16_t* pus;
	pj_uint32_t* pui;

	if ((totalLen) > MAX_ZRTP_SIZE)
		return 0;

	pus = (pj_uint16_t*)buffer;
	pui = (pj_uint32_t*)buffer;

	*buffer = 0x10;		
	*(buffer + 1) = 0;
	pus[1] = pj_htons(zrtp->zrtpSeq++);
	pui[1] = pj_htonl(ZRTP_MAGIC);
	pui[2] = pj_htonl(zrtp->localSSRC);

	pj_memcpy(buffer+12, data, length);

	crc = ZrtpAdapter_GenerateCksum(buffer, totalLen-CRC_SIZE);

	crc = ZrtpAdapter_EndCksum(crc);
	*(uint32_t*)(buffer+totalLen-CRC_SIZE) = pj_htonl(crc);

	return (pjmedia_transport_send_rtp(zrtp->slave_tp, buffer, totalLen) == PJ_SUCCESS) ? 1 : 0;
}

static int32_t zrtp_activateTimer (
	zZrtpAdapterCtx* ctx,
	int32_t time )
{
	pj_time_val timeout;
	struct tp_zrtp *zrtp = (struct tp_zrtp*)ctx->userData;

	timeout.sec = time / 1000;
	timeout.msec = time % 1000;

	pj_timer_entry_init(&zrtp->timeoutEntry, 0, zrtp, &timer_callback);
	timer_add_entry(&zrtp->timeoutEntry, &timeout);

	return 1;
}

static int32_t zrtp_cancelTimer (
	zZrtpAdapterCtx* ctx )
{
	struct tp_zrtp *zrtp = (struct tp_zrtp*)ctx->userData;

	timer_cancel_entry(&zrtp->timeoutEntry);

	return 1;
}

static void zrtp_sendInfo (
	zZrtpAdapterCtx* ctx,
	int32_t severity,
	int32_t subCode )
{
	struct tp_zrtp *zrtp = (struct tp_zrtp*)ctx->userData;

	if (NULL != zrtp->userCallback)
		zrtp->userCallback->ShowMessage(zrtp->callId, zrtp->userCallback->userData, severity, subCode);
}

#define Responder 1
#define Initiator 2

#define ForReceiver 1
#define ForSender	2

static int32_t zrtp_srtpSecretsReady (
	zZrtpAdapterCtx* ctx,
	c_srtp_secrets_t* secrets,
	int32_t part )
{
	struct tp_zrtp *zrtp = (struct tp_zrtp*)ctx->userData;

	SrtpAdapterCtx_t* recvCryptoContext;
	SrtpAdapterCtx_t* senderCryptoContext;
	int cipher = SrtpEncryptionAESCM;
	int authn = SrtpAuthenticationSha1Hmac;
	int authKeyLen = 20;

	if (part == ForSender)
	{
		// To encrypt packets: intiator uses initiator keys, responder uses responder keys
		// Create a "half baked" crypto context first and store it. This is the main crypto context for the sending part of the connection.
		if (secrets->role == Initiator)
		{
			senderCryptoContext = CreateSrtpAdapterCtx (
				zrtp->callId,
				zrtp->localSSRC,
				0,
				0L,										 // keyderivation << 48,
				cipher,									 // encryption algo
				authn,									 // authtentication algo
				(unsigned char*)secrets->keyInit,		 // Master Key
				secrets->initKeyLen / 8,				 // Master Key length
				(unsigned char*)secrets->saltInit,		 // Master Salt
				secrets->initSaltLen / 8,				 // Master Salt length
				secrets->initKeyLen / 8,				 // encryption keyl
				authKeyLen,								 // authentication key len
				secrets->initSaltLen / 8,				 // session salt len
				secrets->srtpAuthTagLen / 8);			 // authentication tag lenA
		}
		else
		{
			senderCryptoContext = CreateSrtpAdapterCtx (
				zrtp->callId,
				zrtp->localSSRC,
				0,
				0L,										 // keyderivation << 48,
				cipher,									 // encryption algo
				authn,									 // authtentication algo
				(unsigned char*)secrets->keyResp,		 // Master Key
				secrets->respKeyLen / 8,				 // Master Key length
				(unsigned char*)secrets->saltResp,		 // Master Salt
				secrets->respSaltLen / 8,				 // Master Salt length
				secrets->respKeyLen / 8,				 // encryption keyl
				authKeyLen,								 // authentication key len
				secrets->respSaltLen / 8,				 // session salt len
				secrets->srtpAuthTagLen / 8);			 // authentication tag len
		}

		if (senderCryptoContext == NULL)
		{
			return 0;
		}

		// Create a SRTP crypto context for real SSRC sender stream.
		// Note: key derivation can be done at this time only if the
		// key derivation rate is 0 (disabled). For ZRTP this is the
		// case: the key derivation is defined as 2^48
		// which is effectively 0.
		SrtpDeriveSrtpKeys(senderCryptoContext, 0L);
		zrtp->srtpSend = senderCryptoContext;
	}
	if (part == ForReceiver)
	{
		// To decrypt packets: intiator uses responder keys, responder initiator keys
		if (secrets->role == Initiator)
		{
			recvCryptoContext = CreateSrtpAdapterCtx (
				zrtp->callId,
				zrtp->peerSSRC,
				0,
				0L,										 // keyderivation << 48,
				cipher,									 // encryption algo
				authn,									 // authtentication algo
				(unsigned char*)secrets->keyResp,		 // Master Key
				secrets->respKeyLen / 8,				 // Master Key length
				(unsigned char*)secrets->saltResp,		 // Master Salt
				secrets->respSaltLen / 8,				 // Master Salt length
				secrets->respKeyLen / 8,				 // encryption keyl
				authKeyLen,								 // authentication key len
				secrets->respSaltLen / 8,				 // session salt len
				secrets->srtpAuthTagLen / 8);			 // authentication tag len
		}
		else
		{
			recvCryptoContext = CreateSrtpAdapterCtx (
				zrtp->callId,
				zrtp->peerSSRC,
				0,
				0L,										 // keyderivation << 48,
				cipher,									 // encryption algo
				authn,									 // authtentication algo
				(unsigned char*)secrets->keyInit,		 // Master Key
				secrets->initKeyLen / 8,				 // Master Key length
				(unsigned char*)secrets->saltInit,		 // Master Salt
				secrets->initSaltLen / 8,				 // Master Salt length
				secrets->initKeyLen / 8,				 // encryption keyl
				authKeyLen,								 // authentication key len
				secrets->initSaltLen / 8,				 // session salt len
				secrets->srtpAuthTagLen / 8);			 // authentication tag len
		}
		if (recvCryptoContext == NULL)
		{
			return 0;
		}
		// Create a SRTP crypto context for real SSRC input stream.
		// If the sender didn't provide a SSRC just insert the template
		// into the queue. After we received the first packet the real
		// crypto context will be created.
		//
		// Note: key derivation can be done at this time only if the
		// key derivation rate is 0 (disabled). For ZRTP this is the
		// case: the key derivation is defined as 2^48
		// which is effectively 0.
		SrtpDeriveSrtpKeys(recvCryptoContext, 0L);
		zrtp->srtpReceive = recvCryptoContext;
	}
	return 1;
}

static void zrtp_srtpSecretsOff (
	zZrtpAdapterCtx* ctx,
	int32_t part )
{
	struct tp_zrtp *zrtp = (struct tp_zrtp*)ctx->userData;

	if (part == ForSender)
	{
		SrtpDestroyWrapper(zrtp->srtpSend);
		zrtp->srtpSend = NULL;
	}

	if (part == ForReceiver)
	{
		SrtpDestroyWrapper(zrtp->srtpReceive);
		zrtp->srtpReceive = NULL;
	}

	if (zrtp->userCallback != NULL)
	{
		zrtp->userCallback->SecureOff(zrtp->callId, zrtp->userCallback->userData);
	}
}

static void zrtp_srtpSecretsOn (
	zZrtpAdapterCtx* ctx,
	char* c,
	char* s,
	int32_t verified )
{
	struct tp_zrtp *zrtp = (struct tp_zrtp*)ctx->userData;

	if (zrtp->userCallback != NULL)
	{
		zrtp->userCallback->SecureOn(zrtp->callId, zrtp->userCallback->userData, c);

		if (strlen(s) > 0)
			zrtp->userCallback->ShowSAS(zrtp->callId, zrtp->userCallback->userData, s, verified);
	}
}

static void zrtp_handleGoClear (
	zZrtpAdapterCtx* )
{
}

static void zrtp_zrtpNegotiationFailed (
	zZrtpAdapterCtx* ctx,
	int32_t severity,
	int32_t subCode )
{
	struct tp_zrtp *zrtp = (struct tp_zrtp*)ctx->userData;

	if (zrtp->userCallback != NULL)
		zrtp->userCallback->NegotiationFailed(zrtp->callId, zrtp->userCallback->userData, severity, subCode);
}

static void zrtp_zrtpNotSuppOther (
	zZrtpAdapterCtx* ctx )
{
	struct tp_zrtp *zrtp = (struct tp_zrtp*)ctx->userData;

	if (zrtp->userCallback != NULL)
		zrtp->userCallback->NotSuppOther(zrtp->callId, zrtp->userCallback->userData);
}

static void zrtp_synchEnter (
	zZrtpAdapterCtx* ctx )
{
	struct tp_zrtp *zrtp = (struct tp_zrtp*)ctx->userData;
	pj_mutex_lock(zrtp->zrtpMutex);
}

static void zrtp_synchLeave (
	zZrtpAdapterCtx* ctx )
{
	struct tp_zrtp *zrtp = (struct tp_zrtp*)ctx->userData;
	pj_mutex_unlock(zrtp->zrtpMutex);
}

static void zrtp_zrtpAskEnrollment (
	zZrtpAdapterCtx* ctx,
	char* info )
{
	struct tp_zrtp *zrtp = (struct tp_zrtp*)ctx->userData;

	if (zrtp->userCallback != NULL)
		zrtp->userCallback->AskEnrollment(zrtp->callId, zrtp->userCallback->userData, info);
}

static void zrtp_zrtpInformEnrollment (
	zZrtpAdapterCtx* ctx,
	char* info )
{
	struct tp_zrtp *zrtp = (struct tp_zrtp*)ctx->userData;

	if (zrtp->userCallback != NULL)
		zrtp->userCallback->InformEnrollment(zrtp->callId, zrtp->userCallback->userData, info);
}

static void zrtp_signSAS (
	zZrtpAdapterCtx* ctx,
	char* sas )
{
	struct tp_zrtp *zrtp = (struct tp_zrtp*)ctx->userData;

	if (zrtp->userCallback != NULL)
		zrtp->userCallback->SignSAS(zrtp->callId, zrtp->userCallback->userData, sas);
}

static int32_t zrtp_checkSASSignature (
	zZrtpAdapterCtx* ctx,
	char* sas )
{
	struct tp_zrtp *zrtp = (struct tp_zrtp*)ctx->userData;

	if (zrtp->userCallback != NULL)
		return zrtp->userCallback->CheckSASSignature(zrtp->callId, zrtp->userCallback->userData, sas);

	return 0;
}

PJ_DECL(void) pjmedia_transport_zrtp_setEnableZrtp (
	pjmedia_transport *tp,
	pj_bool_t onOff )
{
	struct tp_zrtp *zrtp = (struct tp_zrtp*)tp;
	pj_assert(tp);

	zrtp->enableZrtp = onOff;
}

PJ_DECL(pj_bool_t) pjmedia_transport_zrtp_isEnableZrtp (
	pjmedia_transport *tp )
{
	struct tp_zrtp *zrtp = (struct tp_zrtp*)tp;
	PJ_ASSERT_RETURN(tp, PJ_FALSE);

	return zrtp->enableZrtp;
}

PJ_DEF(void) pjmedia_transport_zrtp_setUserCallback (
	int32_t callId,
	pjmedia_transport *tp,
	zrtp_UserCallbacks* ucb )
{
	struct tp_zrtp *zrtp = (struct tp_zrtp*)tp;
	pj_assert(tp);

	zrtp->userCallback = ucb;
}

PJ_DEF(void) pjmedia_transport_zrtp_start (
	pjmedia_transport *tp )
{
	struct tp_zrtp *zrtp = (struct tp_zrtp*)tp;

	pj_assert(tp && zrtp->zrtpCtx);

	ZrtpAdapter_StartZrtpEngine(zrtp->zrtpCtx);
	zrtp->started = 1;
}

PJ_DEF(void) pjmedia_transport_zrtp_stop (
	pjmedia_transport *tp )
{
	struct tp_zrtp *zrtp = (struct tp_zrtp*)tp;

	pj_assert(tp && zrtp->zrtpCtx);

	DestroyZrtpWrapper(zrtp->zrtpCtx);
	zrtp->zrtpCtx = NULL;
	zrtp->started = 0;
}

PJ_DECL(void) pjmedia_transport_zrtp_setLocalSSRC (
	pjmedia_transport *tp,
	uint32_t ssrc )
{
	struct tp_zrtp *zrtp = (struct tp_zrtp*)tp;
	pj_assert(tp);

	zrtp->localSSRC = ssrc;
}

PJ_DECL(zZrtpAdapterCtx*) pjmedia_transport_zrtp_getZrtpContext (
	pjmedia_transport *tp )
{
	struct tp_zrtp *zrtp = (struct tp_zrtp*)tp;
	PJ_ASSERT_RETURN(tp, NULL);

	return zrtp->zrtpCtx;
}

static pj_status_t transport_get_info (
	pjmedia_transport *tp,
	pjmedia_transport_info *info )
{
	struct tp_zrtp *zrtp = (struct tp_zrtp*)tp;
	pjmedia_zrtp_info zrtp_info;
	int spc_info_idx;

	PJ_ASSERT_RETURN(tp && info, PJ_EINVAL);
	PJ_ASSERT_RETURN(info->specific_info_cnt < PJMEDIA_TRANSPORT_SPECIFIC_INFO_MAXCNT, PJ_ETOOMANY);

	zrtp_info.active = ZrtpAdapter_InState(zrtp->zrtpCtx, zCodes::StateSecure) ? PJ_TRUE : PJ_FALSE;

	spc_info_idx = info->specific_info_cnt++;
	info->spc_info[spc_info_idx].type = static_cast<pjmedia_transport_type>(PJMEDIA_TRANSPORT_TYPE_ZRTP);

	pj_memcpy(&info->spc_info[spc_info_idx].buffer, &zrtp_info, sizeof(zrtp_info));

	return pjmedia_transport_get_info(zrtp->slave_tp, info);
}

static void transport_rtp_cb (
	void *user_data,
	void *pkt,
	pj_ssize_t size )
{
	struct tp_zrtp *zrtp = (struct tp_zrtp*)user_data;

	pj_uint8_t* buffer = (pj_uint8_t*)pkt;
	int32_t newLen = 0;
	pj_status_t rc = PJ_SUCCESS;

	pj_assert(zrtp && zrtp->stream_rtcp_cb && pkt);

	if ((*buffer & 0xf0) != 0x10) //< check if this could be a real RTP/SRTP packet.
	{
		if (zrtp->srtpReceive == NULL) //< Could be real RTP, check if we are in secure mode
		{
			zrtp->stream_rtp_cb(zrtp->stream_user_data, pkt, size);
		}
		else
		{
			rc = SrtpUnprotect(zrtp->srtpReceive, (uint8_t*)pkt, size, &newLen);
			if (rc == 1)
			{
				zrtp->unprotect++;
				zrtp->stream_rtp_cb(zrtp->stream_user_data, pkt, newLen);
				zrtp->unprotect_err = 0;
			}
			else
			{
				if (rc == -1)
				{
					zrtp->userCallback->ShowMessage (
						zrtp->callId, 
						zrtp->userCallback->userData,
						zCodes::MsgLevelWarning, 
						zCodes::WarningSRTPAuthFail);
				}
				else
				{
					zrtp->userCallback->ShowMessage (
						zrtp->callId, 
						zrtp->userCallback->userData,
						zCodes::MsgLevelWarning,
						zCodes::WarningSRTPReplayFail);
				}
				zrtp->unprotect_err = rc;
			}
		}
		if (!zrtp->started && zrtp->enableZrtp)
			pjmedia_transport_zrtp_start((pjmedia_transport *)zrtp);

		return;
	}

	// We assume all other packets are ZRTP packets here. Process
	// if ZRTP processing is enabled. Because valid RTP packets are
	// already handled we delete any packets here after processing.
	if (zrtp->enableZrtp && zrtp->zrtpCtx != NULL)
	{
		// Get CRC value into crc (see above how to compute the offset)
		uint16_t temp = (uint16_t)size - CRC_SIZE;
		uint32_t crc = *(uint32_t*)(buffer + temp);
		crc = pj_ntohl(crc);

		if (!ZrtpAdapter_CheckCksum(buffer, temp, crc))
		{
			if (zrtp->userCallback != NULL)
			{
				zrtp->userCallback->ShowMessage (
					zrtp->callId, 
					zrtp->userCallback->userData,
					zCodes::MsgLevelWarning,
					zCodes::WarningCRCMismatch );
			}
			return;
		}

		uint32_t magic = *(uint32_t*)(buffer + 4);
		magic = pj_ntohl(magic);

		if (magic != ZRTP_MAGIC || zrtp->zrtpCtx == NULL) // Check if it is really a ZRTP packet
		{
			return;
		}

		if (!zrtp->started)
		{
			// cover the case if the other party sends _only_ ZRTP packets at the beginning of a session.
			// Start ZRTP in this case as well.
			pjmedia_transport_zrtp_start((pjmedia_transport *)zrtp);
		}

		// this now points beyond the undefined and length field.
		// We need them, thus adjust
		unsigned char* zrtpMsg = (buffer + 12);

		// store peer's SSRC in host order, used when creating the CryptoContext
		zrtp->peerSSRC = *(pj_uint32_t*)(buffer + 8);
		zrtp->peerSSRC = pj_ntohl(zrtp->peerSSRC);
		ZrtpAdapter_ProcessZrtpMessage(zrtp->zrtpCtx, zrtpMsg, zrtp->peerSSRC);
	}
}

static void transport_rtcp_cb (
	void *user_data,
	void *pkt,
	pj_ssize_t size )
{
	struct tp_zrtp *zrtp = (struct tp_zrtp*)user_data;

	pj_assert(zrtp && zrtp->stream_rtcp_cb);

	zrtp->stream_rtcp_cb(zrtp->stream_user_data, pkt, size);
}

static pj_status_t transport_attach (
	pjmedia_transport *tp,
	void *user_data,
	const pj_sockaddr_t *rem_addr,
	const pj_sockaddr_t *rem_rtcp,
	unsigned addr_len,
	void (*rtp_cb)(void*, void*, pj_ssize_t),
	void (*rtcp_cb)(void*, void*, pj_ssize_t) )
{
	struct tp_zrtp *zrtp = (struct tp_zrtp*)tp;
	pj_status_t status;

	PJ_ASSERT_RETURN(tp && rem_addr && addr_len, PJ_EINVAL);

	pj_assert(zrtp->stream_user_data == NULL);
	zrtp->stream_user_data = user_data;
	zrtp->stream_rtp_cb = rtp_cb;
	zrtp->stream_rtcp_cb = rtcp_cb;

	status = pjmedia_transport_attach(zrtp->slave_tp, zrtp, rem_addr,
		rem_rtcp, addr_len, &transport_rtp_cb,
		&transport_rtcp_cb);

	if (status != PJ_SUCCESS)
	{
		zrtp->stream_user_data = NULL;
		zrtp->stream_rtp_cb = NULL;
		zrtp->stream_rtcp_cb = NULL;
		return status;
	}

	return PJ_SUCCESS;
}

static void transport_detach (
	pjmedia_transport *tp,
	void *strm )
{
	struct tp_zrtp *zrtp = (struct tp_zrtp*)tp;

	PJ_UNUSED_ARG(strm);
	PJ_ASSERT_ON_FAIL(tp, return);

	if (zrtp->stream_user_data != NULL)
	{
		pjmedia_transport_detach(zrtp->slave_tp, zrtp);
		zrtp->stream_user_data = NULL;
		zrtp->stream_rtp_cb = NULL;
		zrtp->stream_rtcp_cb = NULL;
	}
}

static pj_status_t transport_send_rtp (
	pjmedia_transport *tp,
	const void *pkt,
	pj_size_t size )
{
	struct tp_zrtp *zrtp = (struct tp_zrtp*)tp;
	pj_uint32_t* pui = (pj_uint32_t*)pkt;
	int32_t newLen = size;
	pj_status_t rc = PJ_SUCCESS;

	PJ_ASSERT_RETURN(tp && pkt, PJ_EINVAL);

	if (!zrtp->started && zrtp->enableZrtp)
	{
		if (zrtp->localSSRC == 0)
			zrtp->localSSRC = pj_ntohl(pui[2]);	  

		pjmedia_transport_zrtp_start((pjmedia_transport *)zrtp);
	}

	if (zrtp->srtpSend == NULL)
	{
		return pjmedia_transport_send_rtp(zrtp->slave_tp, pkt, size);
	}
	else
	{
		if (size+80 > MAX_RTP_BUFFER_LEN)
			return PJ_ETOOBIG;

		pj_memcpy(zrtp->sendBuffer, pkt, size);
		rc = SrtpProtect(zrtp->srtpSend, (uint8_t*)zrtp->sendBuffer, size, &newLen);
		zrtp->protect++;

		if (rc == 1)
			return pjmedia_transport_send_rtp(zrtp->slave_tp, zrtp->sendBuffer, newLen);
		else
			return PJ_EIGNORED;
	}
}

static pj_status_t transport_send_rtcp (
	pjmedia_transport *tp,
	const void *pkt,
	pj_size_t size )
{
	struct tp_zrtp *zrtp = (struct tp_zrtp*)tp;

	PJ_ASSERT_RETURN(tp, PJ_EINVAL);

	return pjmedia_transport_send_rtcp(zrtp->slave_tp, pkt, size);
}

static pj_status_t transport_send_rtcp2 (
	pjmedia_transport *tp,
	const pj_sockaddr_t *addr,
	unsigned addr_len,
	const void *pkt,
	pj_size_t size )
{
	struct tp_zrtp *zrtp = (struct tp_zrtp*)tp;
	PJ_ASSERT_RETURN(tp, PJ_EINVAL);

	return pjmedia_transport_send_rtcp2(zrtp->slave_tp, addr, addr_len, pkt, size);
}

static pj_status_t transport_media_create (
	pjmedia_transport *tp,
	pj_pool_t *sdp_pool,
	unsigned options,
	const pjmedia_sdp_session *rem_sdp,
	unsigned media_index )
{
	struct tp_zrtp *zrtp = (struct tp_zrtp*)tp;
	PJ_ASSERT_RETURN(tp, PJ_EINVAL);

	if (rem_sdp)
	{
		// TODO: If the SDP is not acceptable, we can reject the SDP by returning non-PJ_SUCCESS.
	}

	return pjmedia_transport_media_create(zrtp->slave_tp, sdp_pool, options, rem_sdp, media_index);
}

static pj_status_t transport_encode_sdp (
	pjmedia_transport *tp,
	pj_pool_t *sdp_pool,
	pjmedia_sdp_session *local_sdp,
	const pjmedia_sdp_session *rem_sdp,
	unsigned media_index )
{
	struct tp_zrtp *zrtp = (struct tp_zrtp*)tp;
	PJ_ASSERT_RETURN(tp, PJ_EINVAL);

	// 8. Signaling Interactions
	// ZRTP endpoints that have control over the signaling path include a ZRTP SDP attributes in their SDP offers and answers.
	// The ZRTP attribute, a=zrtp-hash, is used to indicate support for ZRTP and to convey a hash of the Hello message.
	// The hash is computed according to Section 8.1.
	{
		char* helloHash = ZrtpAdapter_GetHelloHash(zrtp->zrtpCtx);

		pjmedia_sdp_attr *my_attr;
		my_attr = PJ_POOL_ALLOC_T(sdp_pool, pjmedia_sdp_attr);
		pj_strdup2(sdp_pool, &my_attr->name, "zrtp-hash");
		pj_strdup2(sdp_pool, &my_attr->value, helloHash );

		pjmedia_sdp_attr_add (
			&local_sdp->media[media_index]->attr_count,
			local_sdp->media[media_index]->attr,
			my_attr );
	}

	return pjmedia_transport_encode_sdp(zrtp->slave_tp, sdp_pool, local_sdp, rem_sdp, media_index);
}

static pj_status_t transport_media_start (
	pjmedia_transport *tp,
	pj_pool_t *pool,
	const pjmedia_sdp_session *local_sdp,
	const pjmedia_sdp_session *rem_sdp,
	unsigned media_index )
{
	struct tp_zrtp *zrtp = (struct tp_zrtp*)tp;
	PJ_ASSERT_RETURN(tp, PJ_EINVAL);

	return pjmedia_transport_media_start(zrtp->slave_tp, pool, local_sdp, rem_sdp, media_index);
}

static pj_status_t transport_media_stop (
	pjmedia_transport *tp )
{
	struct tp_zrtp *zrtp = (struct tp_zrtp*)tp;
	PJ_ASSERT_RETURN(tp, PJ_EINVAL);

	PJ_LOG(4, (THIS_FILE, "Media stop."));
	PJ_LOG(4, (THIS_FILE, "ZRTP Encrypted packets: %d", zrtp->protect));
	PJ_LOG(4, (THIS_FILE, "ZRTP Decrypted packets: %d", zrtp->unprotect));
	PJ_LOG(4, (THIS_FILE, "ZRTP Decryption errors: %d", zrtp->unprotect_err));

	return pjmedia_transport_media_stop(zrtp->slave_tp);
}

static pj_status_t transport_simulate_lost (
	pjmedia_transport *tp,
	pjmedia_dir dir,
	unsigned pct_lost )
{
	struct tp_zrtp *zrtp = (struct tp_zrtp*)tp;

	PJ_ASSERT_RETURN(tp, PJ_EINVAL);

	return pjmedia_transport_simulate_lost(zrtp->slave_tp, dir, pct_lost);
}

static pj_status_t transport_destroy (
	pjmedia_transport *tp )
{
	struct tp_zrtp *zrtp = (struct tp_zrtp*)tp;

	PJ_ASSERT_RETURN(tp, PJ_EINVAL);

	PJ_LOG(4, (THIS_FILE, "Destroy"));

	if (zrtp->close_slave && zrtp->slave_tp)

	{
		pjmedia_transport_close(zrtp->slave_tp);
	}

	DestroyZrtpWrapper(zrtp->zrtpCtx);


	pj_mutex_lock(zrtp->zrtpMutex);
	pj_mutex_unlock(zrtp->zrtpMutex);
	pj_mutex_destroy(zrtp->zrtpMutex);

	pj_pool_release(zrtp->pool);

	return PJ_SUCCESS;
}


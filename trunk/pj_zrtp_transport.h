/*

Copyright 2010-2011 iCall, Inc.

This file is part of Open ZRTP.

Open ZRTP is free software: you can redistribute it and/or modify it under the terms of the GNU Lesser General Public License as published bythe Free Software Foundation, either version 3 of the License, or(at your option) any later version.

Open ZRTP is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU Lesser General Public License for more details.

You should have received a copy of the GNU Lesser General Public Licensealong with Open ZRTP. If not, see http://www.gnu.org/licenses/.

*/

#ifndef __pj_zrtp_transport_h__
#define __pj_zrtp_transport_h__

#include <pj/config.h>
#include <pj/types.h>
#include <pjmedia/transport.h>

#include "pj_zrtpadapter.h"

#define PJMEDIA_TRANSPORT_TYPE_ZRTP PJMEDIA_TRANSPORT_TYPE_USER + 2

PJ_BEGIN_DECL

typedef enum pjmedia_zrtp_use
{
	PJMEDIA_NO_ZRTP =		1,
	PJMEDIA_CREATE_ZRTP =	2,
} pjmedia_zrtp_use;

typedef struct pjmedia_zrtp_info
{
	pj_bool_t active;
} pjmedia_zrtp_info;

typedef struct zrtp_UserCallbacks
{
	void (*SecureOn)(int32_t callId, void* data, char* cipher);
	void (*SecureOff)(int32_t callId, void* data);
	void (*ShowSAS)(int32_t callId, void* data, char* sas, int32_t verified);
	void (*ConfirmGoClear)(int32_t callId, void* data);
	void (*ShowMessage)(int32_t callId, void* data, int32_t sev, int32_t subCode);
	void (*NegotiationFailed)(int32_t callId, void* data, int32_t severity, int32_t subCode);
	void (*NotSuppOther)(int32_t callId, void* data);
	void (*AskEnrollment)(int32_t callId, void* data, char* info);
	void (*InformEnrollment)(int32_t callId, void* data, char* info);
	void (*SignSAS)(int32_t callId, void* data, char* sas);
	int32_t (*CheckSASSignature)(int32_t callId, void* data, char* sas);
	void* userData;
} zrtp_UserCallbacks;

PJ_DECL(pj_status_t) pjmedia_transport_zrtp_create (
	int32_t callId,
	pjmedia_endpt *endpt,
	const char *name,
	pjmedia_transport *transport,
	pjmedia_transport **p_tp,
	pj_bool_t close_slave );

PJ_DECL(pj_status_t) pjmedia_transport_zrtp_initialize (
	int32_t callId,
	pjmedia_transport *tp,
	const char *zidFilename,
	pj_bool_t autoEnable );

PJ_DECL(void) pjmedia_transport_zrtp_setEnableZrtp (
	pjmedia_transport *tp,
	pj_bool_t onOff );

PJ_DECL(pj_bool_t) pjmedia_transport_zrtp_isEnableZrtp (
	pjmedia_transport *tp );

PJ_DECL(void) pjmedia_transport_zrtp_setUserCallback (
	int32_t callId,
	pjmedia_transport *tp,
	zrtp_UserCallbacks* ucb );

PJ_DECL(void) pjmedia_transport_zrtp_start (
	pjmedia_transport *tp );

PJ_DECL(void) pjmedia_transport_zrtp_stop (
	pjmedia_transport *tp );

PJ_DECL(void) pjmedia_transport_zrtp_setLocalSSRC (
	pjmedia_transport *tp, uint32_t ssrc );

PJ_DECL(zZrtpAdapterCtx*) pjmedia_transport_zrtp_getZrtpContext (
	pjmedia_transport *tp );

PJ_END_DECL

#endif // __pj_zrtp_transport_h__
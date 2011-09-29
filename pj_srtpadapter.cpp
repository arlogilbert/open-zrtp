/*

Copyright 2010-2011 iCall, Inc.

This file is part of Open ZRTP.

Open ZRTP is free software: you can redistribute it and/or modify it under the terms of the GNU Lesser General Public License as published bythe Free Software Foundation, either version 3 of the License, or(at your option) any later version.

Open ZRTP is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU Lesser General Public License for more details.

You should have received a copy of the GNU Lesser General Public Licensealong with Open ZRTP. If not, see http://www.gnu.org/licenses/.

*/


#include "zCryptoContext.h"
#include "pj_srtpadapter.h"
#include <pjmedia/rtp.h>
#include <pjmedia/errno.h>
#include "network.h"

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
	int32_t	 tagLength )
{
	SrtpAdapterCtx_t* zc = new SrtpAdapterCtx_t;

	zc->callId = callId;
	zc->srtp = new zCryptoContext (
		callId, ssrc, roc, keyDerivRate,
		(SrtpEncryption_t)ealg, (SrtpAuthentication_t)aalg,
		masterKey, masterKeyLength, masterSalt,
		masterSaltLength, ekeyl, akeyl, skeyl,
		tagLength );

	return zc;
}

void SrtpDestroyWrapper (SrtpAdapterCtx_t* ctx)
{
	if (ctx == NULL)
		return;

	delete ctx->srtp;
	ctx->srtp = NULL;

	delete ctx;
}

#define RTP_VERSION	  2
static pj_status_t zsrtp_decode_rtp (
	uint8_t* pkt, int32_t pkt_len,
	const pjmedia_rtp_hdr **hdr,
	uint8_t** payload,
	int32_t *payloadlen )
{
	int offset;

	*hdr = (pjmedia_rtp_hdr*)pkt;

	if ((*hdr)->v != RTP_VERSION)
		return PJMEDIA_RTP_EINVER;

	offset = sizeof(pjmedia_rtp_hdr) + ((*hdr)->cc * sizeof(pj_uint32_t));

	if ((*hdr)->x)
	{
		pjmedia_rtp_ext_hdr *ext = (pjmedia_rtp_ext_hdr*)
			(((pj_uint8_t*)pkt) + offset);
		offset += ((pj_ntohs(ext->length)+1) * sizeof(pj_uint32_t));
	}

	if (offset > pkt_len)
		return PJMEDIA_RTP_EINLEN;

	*payload = pkt + offset;
	*payloadlen = pkt_len - offset;

	return PJ_SUCCESS;
}

int32_t SrtpProtect (
	SrtpAdapterCtx_t* ctx,
	uint8_t* buffer,
	int32_t length,
	int32_t* newLength )
{
	zCryptoContext* pcc = ctx->srtp;
	const pjmedia_rtp_hdr *hdr;
	uint8_t* payload = NULL;
	int32_t payloadlen = 0;
	pj_status_t rc;
	uint16_t seqnum;
	uint32_t ssrc;

	if (pcc == NULL)
		return 0;

	rc = zsrtp_decode_rtp(buffer, length, &hdr, &payload, &payloadlen);

	seqnum = hdr->seq;
	seqnum = ntohs(seqnum);

	uint64_t index = ((uint64_t)pcc->GetRoc() << 16) | (uint64_t)seqnum;

	ssrc = hdr->ssrc;
	ssrc = ntohl(ssrc);
	pcc->SrtpEncrypt(buffer, payload, payloadlen, index, ssrc);

	// NO MKI support yet - here we assume MKI is zero. To build in MKI
	// take MKI length into account when storing the authentication tag.

	pcc->SrtpAuthenticate(buffer, length, pcc->GetRoc(), buffer+length);

	*newLength = length + pcc->GetTagLength();

	if (seqnum == 0xFFFF )
		pcc->SetRoc(pcc->GetRoc() + 1);

	return 1;
}

int32_t SrtpUnprotect (
	SrtpAdapterCtx_t* ctx,
	uint8_t* buffer,
	int32_t length,
	int32_t* newLength)
{
	zCryptoContext* pcc = ctx->srtp;
	const pjmedia_rtp_hdr *hdr;
	uint8_t* payload = NULL;
	int32_t payloadlen = 0;
	pj_status_t rc;
	uint16_t seqnum;
	uint32_t ssrc;

	if (pcc == NULL)
		return 0;

	rc = zsrtp_decode_rtp(buffer, length, &hdr, &payload, &payloadlen);

	uint32_t srtpDataIndex = length - (pcc->GetTagLength() + pcc->GetMkiLength());

	// now adjust length because some RTP functions rely on the fact that
	// total is the full length of data without SRTP data.
	length -= pcc->GetTagLength() + pcc->GetMkiLength();
	*newLength = length;

	// recompute payloadlen by subtracting SRTP data
	payloadlen -= pcc->GetTagLength() + pcc->GetMkiLength();

	// unused??
	// const uint8* mki = getRawPacket() + srtpDataIndex;
	uint8_t* tag = buffer + srtpDataIndex + pcc->GetMkiLength();

	seqnum = hdr->seq;
	seqnum = ntohs(seqnum);
	if (!pcc->CheckReplay(seqnum))
		return -2;

	uint64_t guessedIndex = pcc->GuessIndex(seqnum);

	uint32_t guessedRoc = (uint32_t)guessedIndex >> 16;
	uint8_t* mac = new uint8_t[pcc->GetTagLength()];

	pcc->SrtpAuthenticate(buffer, length, guessedRoc, mac);
	if (memcmp(tag, mac, pcc->GetTagLength()) != 0)
	{
		delete[] mac;
		return -1;
	}
	delete[] mac;


	ssrc = hdr->ssrc;
	ssrc = ntohl(ssrc);
	pcc->SrtpEncrypt(buffer, payload, payloadlen, guessedIndex, ssrc);

	pcc->Update(seqnum);

	return 1;
}

void SrtpNewCryptoContextForSSRC (
	SrtpAdapterCtx_t* ctx,
	uint32_t ssrc,
	int32_t roc,
	int64_t keyDerivRate )
{
    (roc);
    (keyDerivRate);

	zCryptoContext* newCrypto = ctx->srtp->NewCryptContextForSSRC(ctx->callId, ssrc, 0, 0L);
	ctx->srtp = newCrypto;
}

void SrtpDeriveSrtpKeys (
	SrtpAdapterCtx_t* ctx,
	uint64_t index )
{
	ctx->srtp->DeriveSRTPKeys(index);
}

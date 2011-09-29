/*

Copyright 2010-2011 iCall, Inc.

This file is part of Open ZRTP.

Open ZRTP is free software: you can redistribute it and/or modify it under the terms of the GNU Lesser General Public License as published bythe Free Software Foundation, either version 3 of the License, or(at your option) any later version.

Open ZRTP is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU Lesser General Public License for more details.

You should have received a copy of the GNU Lesser General Public Licensealong with Open ZRTP. If not, see http://www.gnu.org/licenses/.

*/

#ifndef RTP_H_INCLUDED
#define RTP_H_INCLUDED

#include <stdio.h>
#include <string.h>
#include "network.h"
#include "zCryptoContext.h"

struct RTPFixedHeader
{
#if __BYTE_ORDER == __BIG_ENDIAN
	unsigned char ver:2;
	unsigned char pad:1;
	unsigned char ext:1;
	unsigned char cc:4;
	unsigned char marker:1;
	unsigned char payload:7;
#else
	unsigned char cc:4;
	unsigned char ext:1;
	unsigned char pad:1;
	unsigned char ver:2;
	unsigned char payload:7;
	unsigned char marker:1;
#endif
	uint16_t seq;
	uint32_t ts;
	uint32_t src[1];
};

struct RFC2833Payload
{
#if __BYTE_ORDER == __BIG_ENDIAN
	uint8_t evt : 8;
	bool ebit: 1;
	bool rbit: 1;
	uint8_t vol : 6;
	uint16_t duration : 16;
#else
	uint8_t evt : 8;
	uint8_t vol : 6;
	bool rbit : 1;
	bool ebit : 1;
	uint16_t duration: 16;
#endif
};

struct RtpHeaderExt
{
	uint16_t undefined;
	uint16_t length;
};



class RtpPkt
{
public:
	RtpPkt()
	{

	}
	RtpPkt(const unsigned char* const blk, size_t len, bool dup = false)
	{

		const RTPFixedHeader* header = reinterpret_cast<const RTPFixedHeader*>(blk);

		hdrSize = sizeof(RTPFixedHeader)+header->cc << 2;

		if(header->ext)
		{
			RtpHeaderExt *ext = (RtpHeaderExt*)(blk+hdrSize);
			hdrSize =  hdrSize + sizeof(uint32_t)+(ntohs(ext->length) * 4);
		}

		if(header->pad)
		{
			len -=blk[len-1];

		}

		payloadSize = (uint32_t)(len-hdrSize);
		if(dup)
		{
			buffer = new unsigned char[len];
			setbuffer(blk,len,0);
		}
		else
			buffer = const_cast<unsigned char*>(blk);
	}

	RtpPkt(size_t hdrlen, size_t plen, uint8_t pad_len, zCryptoContext* pcc= NULL):payloadSize(plen),buffer(NULL),hdrSize(hdrlen),duplicated(false)
	{
		(pcc);
        (pad_len);

		total =(uint32_t)(hdrlen+payloadSize);
		uint8_t padding = 0;

		if(plen != 0)
		{
			padding = (uint8_t)(plen - (total % plen));
			total += padding;
		}

		srtpLength = 0;
		srtpDataOffset =0;

		buffer = new unsigned char[total + srtpLength];
		*(reinterpret_cast<uint32_t*>(getHeader()))=0;
		getHeader()->ver = 0;
		if(padding != 0)
		{
			memset(buffer+total-padding, 0, padding-1);
			buffer[total-1]=padding;
			getHeader()->pad = 1;
		}
		else
		{
			getHeader()->pad = 0;
		}
		getHeader()->ext = 1;

	}

    inline uint32_t getHeaderSize() const
	{
		return hdrSize;
	}


    inline uint8_t* const getPayload() const
	{
		return (uint8_t*)(buffer + getHeaderSize());
	}

    inline uint32_t getPayloadSize() const
	{
		return payloadSize;
	}

/*				  inline PayloadType
	getPayloadType const
	{
		return static_cast<PayloadType>(getHeader()->payload);
	}*/

	inline uint32_t
	getTimestamp() const
	{
		return cachedTimestamp;
	}

	inline uint8_t
	getProtocolVersion() const
	{
		return getHeader()->ver;
	}

	inline bool
	isPadded() const
	{
		return getHeader()->pad;
	}

	inline uint8_t
	getPaddingSize() const
	{
		return buffer[total - 1];
	}

	inline bool
	isMarked() const
	{
		return getHeader()->marker;
	}

	inline bool
	isExtended() const
	{
		return getHeader()->ext;
	}

	inline uint16_t
	getCSRCsCount() const
	{
		return getHeader()->cc;
	}

	inline const uint32_t*
	getCSRCs() const
	{
		return static_cast<const uint32_t*>(&(getHeader()->src[1]));
	}

	inline uint16_t
	getHdrExtUndefined() const
	{
		return (isExtended() ? getHeaderExt()->undefined:0);
	}

	inline uint32_t
	getHdrExtSize() const
	{
		return (isExtended() ? (static_cast<uint32_t>(ntohs(getHeaderExt()->length)) << 2):0);
	}

	inline const unsigned char*
	getHdrExtContent() const
	{
		return (isExtended() ?
		(reinterpret_cast<const unsigned char*>(getHeaderExt())+sizeof(RtpHeaderExt)):0);
	}

	inline const unsigned char* const
	getRawPacket() const
	{
		return buffer;
	}

	inline uint32_t
	getRawPacketSize() const
	{
		return total;
	}

	inline uint32_t
	getRawPacketSizeSrtp() const
	{
		return total+srtpLength;
	}

	inline size_t
	getSizeOfFixedHeader() const
	{
		return sizeof(RTPFixedHeader);
	}

	void reComputePayLength(bool padding);

	inline struct RFC2833Payload *getRaw2833Payload(void)
	{
		return (struct RFC2833Payload *)getPayload();
	}

	inline uint16_t get2833Duration(void)
	{
		return ntohs(getRaw2833Payload()->duration);
	}

	inline void set2833Duration(uint16_t timestamp)
	{
		getRaw2833Payload()->duration = htons(timestamp);
	}

	inline uint16_t getSeqNum() const
	{
		return cachedSeqNum;
	}

protected:

	inline virtual ~RtpPkt()
	{
		endPacket();
	}

	void endPacket()
	{
	}

	inline RTPFixedHeader*
	getHeader() const
	{
		return reinterpret_cast<RTPFixedHeader*>(buffer);
	}

	inline void
	setExtension(bool e)
	{
		getHeader()->ext = e;
	}

	inline const RtpHeaderExt*
	getHeaderExt() const
	{
		uint32_t fixsize = sizeof(RTPFixedHeader)+ (getHeader()->cc << 2);
		return (reinterpret_cast<RtpHeaderExt*>(buffer + fixsize));
	}

	inline int32_t getRawTimestamp() const
	{
		return ntohl(getHeader()->ts);
	}

	inline void
	setbuffer(const void* src, size_t len, size_t pos)
	{
		memcpy(buffer+pos, src, len);
	}

	uint16_t cachedSeqNum;
	uint32_t cachedTimestamp;

	uint32_t srtpDataOffset;

	uint32_t srtpLength;
	uint32_t total;

	uint32_t payloadSize;

private:
	unsigned char* buffer;
	uint32_t hdrSize;
	bool duplicated;
};

class OutgoingRtpPkt : public RtpPkt
{
public:

	OutgoingRtpPkt(const uint32_t* const csrcs, uint16_t numcsrc,
				   const unsigned char* const hdrext, uint32_t hdrextlen,
				   const unsigned char* const data, size_t datalen,
				   uint8_t paddinglen = 0, zCryptoContext* pcc= NULL):RtpPkt((getSizeOfFixedHeader()+sizeof(uint32_t)*numcsrc+hdrextlen), datalen,paddinglen,pcc)
				   {
					   setbuffer(hdrext, hdrextlen,getSizeOfFixedHeader());
				   }

	OutgoingRtpPkt(const uint32_t* csrcs, uint16_t numcsrc,
				   const unsigned char* const data, size_t datalen,
				   uint8_t paddinglen=0, zCryptoContext* pcc = NULL)
				   {
				   }

	OutgoingRtpPkt(const unsigned char* const data, size_t datalen,
				   uint8_t paddinglen = 0, zCryptoContext* pcc = NULL)
				   {
				   }

	~OutgoingRtpPkt()
	{ };

/*	  inline void
	setPayloadType(PayloadType pt)
	{
		getHeader()->payload = pt;
	}*/

	inline void
	setSeqNum(uint16_t seq)
	{
		cachedSeqNum = seq;
		getHeader()->seq = htons(seq);
	}

	inline void
	setTimestamp(uint32_t pts)
	{
		cachedTimestamp = pts;
		getHeader()->ts = htonl(pts);
	}

	inline void
	setSSRC(uint32_t ssrc) const
	{
		getHeader()->src[0]=htonl(ssrc);
	}

	inline void
	setSSRCNetwork(uint32_t ssrc) const
	{
		getHeader()->src[0] = ssrc;
	}

	inline void
	setMarker(bool mark)
	{
		getHeader()->marker = mark;
	}

	inline bool
	operator ==(const OutgoingRtpPkt &p) const
	{
		return (this->getSeqNum() == p.getSeqNum());
	}

	inline bool
	operator !=(const OutgoingRtpPkt &p) const
	{
		return (this->getSeqNum() != p.getSeqNum());
	}
private:

	OutgoingRtpPkt(const OutgoingRtpPkt &o);

	OutgoingRtpPkt&
	operator =(const OutgoingRtpPkt &o);

	void setCSRCArray(const uint32_t* const csrcs, uint16_t numcsrc);
};

class IncomingRtpPkt : public RtpPkt
{
public:
	IncomingRtpPkt(const unsigned char* block, size_t len):RtpPkt(block,len,false)
	{
	}

	~IncomingRtpPkt()
	{ };

	inline bool
	isHeaderValid()
	{
		return headerValid;
	}

	inline uint32_t
	getSSRC() const
	{
	   return cachedSSRC;
	}

	int32_t
	unprotect(zCryptoContext* pcc)
	{
		return 0;
	}

	inline bool
	operator ==(const IncomingRtpPkt &p) const
	{
		return ((this->getSeqNum() == p.getSeqNum()) &&
				(this->getSSRC() == p.getSSRC()));
	}

	inline bool
	operator !=(const IncomingRtpPkt &p) const
	{
		return !(*this == p);
	}
private:

	IncomingRtpPkt(const IncomingRtpPkt &ip);

	IncomingRtpPkt&
	operator = (const IncomingRtpPkt &ip);

	bool headerValid;

	uint32_t cachedSSRC;

	static const uint16_t RTP_INVALID_PT_MASK;
	static const uint16_t RTP_INVALID_PT_VALUE;
};
#endif // RTP_H_INCLUDED

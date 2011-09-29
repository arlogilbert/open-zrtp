/*

Copyright 2010-2011 iCall, Inc.

This file is part of Open ZRTP.

Open ZRTP is free software: you can redistribute it and/or modify it under the terms of the GNU Lesser General Public License as published bythe Free Software Foundation, either version 3 of the License, or(at your option) any later version.

Open ZRTP is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU Lesser General Public License for more details.

You should have received a copy of the GNU Lesser General Public Licensealong with Open ZRTP. If not, see http://www.gnu.org/licenses/.

*/

#ifndef PACKETQUEUE_H_INCLUDED
#define PACKETQUEUE_H_INCLUDED

#include "rtp.h"
#include "zCryptoContext.h"

class RTPApplication
{
};

class SyncSource
{
public:
	uint32_t getDataTransportPort()
	{
		return 0;
	}
};

class SyncSourceLink
{
	public:
	SyncSource* getSource()
	{
	   return new SyncSource();
	}

	void initStats()
	{
	}

	void setInitialDataTime(struct timeval rectime)
	{
	}

	void setProbation(uint32_t minValidSeq)
	{
	}

	bool getHello()
	{
		return true;
	}

	uint32_t getInitialDataTimestamp()
	{
		return 0;
	}
};



class InetHostAddress
{
};

class tpport_t
{
};

class AVPQueue
{
	private:
		uint32_t next_packet_size;
		unsigned char* buffer;

	public:
	static void* dispatch_cb;

	public:
	  AVPQueue(uint32_t size, RTPApplication& app)
	  {
		  next_packet_size=0; buffer = NULL;
	  }

	  AVPQueue(uint32_t size, RTPApplication& app, uint32_t ssrc)
	  {
	  }

	  void endQueue()
	  {
	  }

	  void setNextDataPacketSize(uint32_t size)
	  {
		  next_packet_size = size;
	  }

	  void setNextDataPacket(unsigned char* buf, uint32_t size)
	  {
		  if(buffer != NULL) delete[] buffer;

		  buffer = new unsigned char[size];
		  memcpy(buffer, buf,size);
		  next_packet_size = size;
	  }

	  uint32_t getNextDataPacketSize()
	  {
		  return next_packet_size;
	  }

	  uint32_t getMaxRecvPacketSize()
	  {
		  return 20000;
	  }

	int32_t recvData(unsigned char* buf, uint32_t next_size, InetHostAddress network, tpport_t transport)
	{
		memcpy(buf, buffer, next_size);
		return next_size;
	}
	zCryptoContext* getInQueueCryptContxt(uint32_t ssrc)
	{

		return new zCryptoContext();
	}

	void setInQueueCryptContxt(zCryptoContext *pcc)
	{
	}

	SyncSourceLink* getSourceBySSRC(uint32_t ssrc, bool source_created)
	{
		return new SyncSourceLink();
	}

	void setDataTransportPort(SyncSource src,tpport_t transport)
	{
	}

	void setNetworkAddress(SyncSource src, InetHostAddress address)
	{
	}

	uint32_t getMinValidPacketSeq()
	{
		return 10000L;
	}

	bool checkSSRCInIncomingRTPPkt(SyncSourceLink& sourceLink, bool source_created, InetHostAddress network_add, tpport_t transport_port)
	{
		return true;
	}

	bool recordReception(SyncSourceLink& sourceLink, IncomingRtpPkt& packet, struct timeval recvtime)
	{
		return true;
	}

	void insertRecvPacket(void* ptr)
	{
	}

	uint32_t getLocalSSRC()
	{
		return 100;
	}

	void dispatchPacket(void* pkt)
	{
		void (*pFunc)(uint8_t*,uint32_t) = (void(*)(uint8_t*,uint32_t))(AVPQueue::dispatch_cb);
		OutgoingRtpPkt* zpkt = (OutgoingRtpPkt*)pkt;
		if(pFunc!=NULL)
		 (*pFunc)((uint8_t*)zpkt->getRawPacket(),zpkt->getRawPacketSize());
		//printf("\n dispatch packet called");
	}

	void setOutQueueCryptoContext(zCryptoContext* pcc)
	{
	}

	void setInQueueCryptoContext(zCryptoContext* pcc)
	{
	}

	void removeOutQueueCryptoContext(zCryptoContext* pcc)
	{
	}

	void removeInQueueCryptoContext(zCryptoContext* pcc)
	{
	}
};

class IncomingRtpPktLink
{
public:
	IncomingRtpPktLink(IncomingRtpPkt* packet, SyncSourceLink* sourceLink, struct timeval recvtime, uint32_t ts)
	{
	}
};

class OutgoingDataQueue
{
public:
	static void putData(uint32_t stamp, const unsigned char* data, size_t len)
	{
	}

	static void sendImmediate(uint32_t stamp, const unsigned char* data, size_t len)
	{
	}
};

#endif // PACKETQUEUE_H_INCLUDED

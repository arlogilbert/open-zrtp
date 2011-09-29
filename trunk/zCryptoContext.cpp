/*

Copyright 2010-2011 iCall, Inc.

This file is part of Open ZRTP.

Open ZRTP is free software: you can redistribute it and/or modify it under the terms of the GNU Lesser General Public License as published bythe Free Software Foundation, either version 3 of the License, or(at your option) any later version.

Open ZRTP is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU Lesser General Public License for more details.

You should have received a copy of the GNU Lesser General Public Licensealong with Open ZRTP. If not, see http://www.gnu.org/licenses/.

*/


#include <string.h>
#include <stdio.h>

#include "network.h"
#include "zCryptoContext.h"
#include "zopenssl.h"
#include "zAlgoSupported.h"

namespace
{
	void __ComputeInitialVector(unsigned char* iv, uint64_t label, uint64_t index,
		int64_t kdv, unsigned char* master_salt)
	{
		uint64_t key_id;

		if (kdv == 0)
		{
			key_id = label << 48;
		}
		else
		{
			key_id = ((label << 48) | (index / kdv));
		}

		int i;
		for (i = 0; i < 7 ; i++ )
		{
			iv[i] = master_salt[i];
		}

		for (i = 7; i < 14 ; i++ )
		{
			iv[i] = (unsigned char)(0xFF & (key_id >> (8*(13-i)))) ^
				master_salt[i];
		}

		iv[14] = iv[15] = 0;
	}
}

struct zCryptoContextData
{
	uint16_t	_s_1;

	int32_t		_n_e;
	uint8_t*	_k_e;
	int32_t		_n_a;
	uint8_t*	_k_a;
	int32_t		_n_s;
	uint8_t*	_k_s;

	zAesSrtp*	_CipherAES;
	zAesSrtp*	_CipherF8AES;

	void*		_MacCtx;

	uint32_t	_SSRC;
	bool		_UsingMki;
	uint32_t	_MkiLength;
	uint8_t*	_Mki;

	uint32_t	_RollOverCounter;
	uint32_t	_GuessedRollOverCounter;

	int64_t		_KeyDerivationRate;

	uint64_t	_ReplayWindow;

	uint8_t*	_SRTPCryptCtxMasterKey;

	uint32_t	_SRTPCryptCtxMasterKeyLength;
	uint32_t	_SRTPCryptCtxMasterKeyUseNb;
	uint32_t	_SRTCPCryptCtxMasterKeyUseNb;

	uint8_t*	_SessionMasterSalt;
	uint32_t	_SessionMasterSaltLength;

	SrtpEncryption_t		_SrtpEncryptionAlgo;
	SrtpAuthentication_t	_SrtpAuthenticationAlgo;

	uint8_t _SrtpEncryptionKeyLength;		// session encryption key length used by SRTP
	uint8_t _SrtpAuthenticationKeyLength;	// session authentication key length used by sRTP
	uint8_t _SessionSatlKeyLength;			// session salt key length
	uint8_t _AuthTagLegth;					// length of authentication tag appended to SRTP packet

	bool _SeqNumSet;

	int32_t _CallID;

	zCryptoContextData (
		int32_t	callId, uint32_t ssrc, int32_t roc, int64_t keyderivrate,
		SrtpEncryption_t ealg, SrtpAuthentication_t aalg,
		uint8_t* master_key, int32_t master_key_length,
		uint8_t* master_salt, int32_t master_salt_length,
		int32_t ekeyl, int32_t akeyl, int32_t skeyl, int32_t tagLength)
     : _s_1(0)
	 , _SSRC(ssrc)
	 , _UsingMki(false)
	 , _MkiLength(0)
	 , _Mki(NULL)
	 , _RollOverCounter(roc)
	 , _GuessedRollOverCounter(0)
	 , _KeyDerivationRate(keyderivrate)
	 , _CipherAES(NULL)
	 , _CipherF8AES(NULL)
     , _ReplayWindow(0)
     , _SRTPCryptCtxMasterKeyUseNb(0)
     , _SRTCPCryptCtxMasterKeyUseNb(0)
	 , _SeqNumSet(false)
	 , _CallID(callId)
	{
		this->_SrtpEncryptionAlgo = ealg;
		this->_SrtpAuthenticationAlgo = aalg;

		this->_SrtpEncryptionKeyLength = static_cast<uint8_t>(ekeyl);
		this->_SrtpAuthenticationKeyLength = static_cast<uint8_t>(akeyl);
		this->_SessionSatlKeyLength = static_cast<uint8_t>(skeyl);

		this->_SRTPCryptCtxMasterKeyLength = master_key_length;
		this->_SRTPCryptCtxMasterKey = new uint8_t[master_key_length];
		memcpy(this->_SRTPCryptCtxMasterKey, master_key, master_key_length);

		this->_SessionMasterSaltLength = master_salt_length;
		this->_SessionMasterSalt = new uint8_t[master_salt_length];
		memcpy(this->_SessionMasterSalt, master_salt, master_salt_length);

		switch ( ealg )
		{
		case SrtpEncryptionNull:
			_n_e = 0;
			_k_e = NULL;
			_n_s = 0;
			_k_s = NULL;
			break;

		case SrtpEncryptionAESF8:
			_CipherF8AES = new zAesSrtp(SrtpEncryptionAESCM);

		case SrtpEncryptionAESCM:
			_n_e = ekeyl;
			_k_e = new uint8_t[_n_e];
			_n_s = skeyl;
			_k_s = new uint8_t[_n_s];
			_CipherAES = new zAesSrtp(SrtpEncryptionAESCM);
			break;
		}

		switch ( aalg )
		{
		case SrtpAuthenticationNull:
			_n_a = 0;
			_k_a = NULL;
			this->_AuthTagLegth = 0;
			break;

		case SrtpAuthenticationSha1Hmac:
			_n_a = akeyl;
			_k_a = new uint8_t[_n_a];
			this->_AuthTagLegth = static_cast<uint8_t>(tagLength);
			break;
		}
	}

	~zCryptoContextData()
	{
		_SrtpEncryptionAlgo = SrtpEncryptionNull;
		_SrtpAuthenticationAlgo = SrtpAuthenticationNull;

		if (_Mki)
			delete [] _Mki;

		if (_SRTPCryptCtxMasterKeyLength > 0)
		{
			_SRTPCryptCtxMasterKeyLength = 0;
			delete [] _SRTPCryptCtxMasterKey;
		}
		if (_SessionMasterSaltLength > 0)
		{
			_SessionMasterSaltLength = 0;
			delete [] _SessionMasterSalt;
		}
		if (_n_e > 0)
		{
			_n_e = 0;
			delete [] _k_e;
		}
		if (_n_s > 0)
		{
			_n_s = 0;
			delete [] _k_s;
		}
		if (_n_a > 0)
		{
			_n_a = 0;
			delete [] _k_a;
		}
		if (_CipherAES != NULL)
		{
			delete _CipherAES;
			_CipherAES = NULL;
		}
		if (_CipherF8AES != NULL)
		{
			delete _CipherF8AES;
			_CipherF8AES = NULL;
		}
		if (_MacCtx != NULL)
		{
			switch(_SrtpAuthenticationAlgo)
			{
			case SrtpAuthenticationSha1Hmac:
				Hmac256::FreeSha1HmacContext(_MacCtx);
				break;

			default:
				break;
			}
		}
	}
};

zCryptoContext::zCryptoContext()
 :_Data(new zCryptoContextData(-1, 0, 0, 0, SrtpEncryptionNull, SrtpAuthenticationNull, NULL, 0, NULL, 0, 0, 0, 0, 0 ))
{
}

zCryptoContext::zCryptoContext (
	int32_t	callId, uint32_t ssrc, int32_t roc, int64_t keyderivrate,
	SrtpEncryption_t ealg, SrtpAuthentication_t aalg,
	uint8_t* master_key, int32_t master_key_length,
	uint8_t* master_salt, int32_t master_salt_length,
	int32_t ekeyl, int32_t akeyl, int32_t skeyl, int32_t tagLength )
 : _Data ( new zCryptoContextData (
		callId, ssrc, roc, keyderivrate,
		ealg, aalg,
		master_key, master_key_length,
		master_salt, master_salt_length,
		ekeyl, akeyl, skeyl, tagLength ) )
{
}

zCryptoContext::~zCryptoContext()
{
	delete _Data;
}

void zCryptoContext::SrtpEncrypt (
	uint8_t* packet,
	uint8_t* payload, uint32_t payloadLength,
	uint64_t index, uint32_t ssrc )
{
	if (_Data->_SrtpEncryptionAlgo == SrtpEncryptionNull)
	{
		return;
	}
	if (_Data->_SrtpEncryptionAlgo == SrtpEncryptionAESCM)
	{
		unsigned char iv[16];
		memcpy( iv, _Data->_k_s, 4 );

		int i;
		for (i = 4; i < 8; i++ )
		{
			iv[i] = ( 0xFF & ( ssrc >> ((7-i)*8) ) ) ^ _Data->_k_s[i];
		}
		for (i = 8; i < 14; i++ )
		{
			iv[i] = ( 0xFF & (unsigned char)( index >> ((13-i)*8) ) ) ^ _Data->_k_s[i];
		}
		iv[14] = iv[15] = 0;

		_Data->_CipherAES->EncryptCtr(payload, payloadLength, iv);
	}

	if (_Data->_SrtpEncryptionAlgo == SrtpEncryptionAESF8)
	{
		unsigned char iv[16];
		uint32_t *ui32p = (uint32_t *)iv;

		memcpy(iv, packet, 12);
		iv[0] = 0;

		// set ROC in network order into IV
		ui32p[3] = htonl(_Data->_RollOverCounter);

		_Data->_CipherAES->EncryptF8(payload, payloadLength,
			iv, _Data->_k_e, _Data->_n_e, _Data->_k_s, _Data->_n_s, _Data->_CipherF8AES);
	}
}

void zCryptoContext::SrtpAuthenticate (
	uint8_t* packet, uint32_t packetLength,
	uint32_t rollOverCounter, uint8_t* tag )
{
	if (_Data->_SrtpAuthenticationAlgo == SrtpAuthenticationNull)
	{
		return;
	}
	int32_t macL;

	unsigned char temp[20];
	const unsigned char* chunks[3];
	unsigned int chunkLength[3];
	uint32_t beRoc = htonl(rollOverCounter);

	chunks[0] = packet;
	chunkLength[0] = packetLength;

	chunks[1] = (unsigned char *)&beRoc;
	chunkLength[1] = 4;
	chunks[2] = NULL;

	switch (_Data->_SrtpAuthenticationAlgo)
	{
	case SrtpAuthenticationSha1Hmac:
		Hmac256::UpdateSha1Ctx(_Data->_MacCtx,
			chunks,			  // data chunks to hash
			chunkLength,	  // length of the data to hash
			temp, &macL);

		memcpy(tag, temp, GetTagLength());
		break;
	default:
		break;
	}
}

void zCryptoContext::DeriveSRTPKeys(uint64_t idx)
{
	uint8_t initizlvector[16];

	// prepare AES cipher to compute derived keys.
	_Data->_CipherAES->SetNewKey(_Data->_SRTPCryptCtxMasterKey, _Data->_SRTPCryptCtxMasterKeyLength);

	// compute the session encryption key
	uint64_t label = 0;
	__ComputeInitialVector(initizlvector, label, idx, _Data->_KeyDerivationRate, _Data->_SessionMasterSalt);
	_Data->_CipherAES->GetCipherStream(_Data->_k_e, _Data->_n_e, initizlvector);

	// compute the session authentication key
	label = 0x01;
	__ComputeInitialVector(initizlvector, label, idx, _Data->_KeyDerivationRate, _Data->_SessionMasterSalt);
	_Data->_CipherAES->GetCipherStream(_Data->_k_a, _Data->_n_a, initizlvector);
	// Initialize MAC context with the derived key
	switch (_Data->_SrtpAuthenticationAlgo)
	{
	case SrtpAuthenticationSha1Hmac:
		_Data->_MacCtx = Hmac256::CreateSha1HmacContext(_Data->_k_a, _Data->_n_a);
		break;
	default:
		break;
	}
	// compute the session salt
	label = 0x02;
	__ComputeInitialVector(initizlvector, label, idx, _Data->_KeyDerivationRate, _Data->_SessionMasterSalt);
	_Data->_CipherAES->GetCipherStream(_Data->_k_s, _Data->_n_s, initizlvector);

	// as last step prepare AES cipher with derived key.
	_Data->_CipherAES->SetNewKey(_Data->_k_e, _Data->_n_e);
}

uint64_t zCryptoContext::GuessIndex(uint16_t newSeqNb )
{
	if (!_Data->_SeqNumSet)
	{
		_Data->_SeqNumSet = true;
		_Data->_s_1 = newSeqNb;
	}
	if (_Data->_s_1 < 32768)
	{
		if (newSeqNb - _Data->_s_1 > 32768)
		{
			_Data->_GuessedRollOverCounter = _Data->_RollOverCounter - 1;
		}
		else
		{
			_Data->_GuessedRollOverCounter = _Data->_RollOverCounter;
		}
	}
	else
	{
		if (_Data->_s_1 - 32768 > newSeqNb)
		{
			_Data->_GuessedRollOverCounter = _Data->_RollOverCounter + 1;
		}
		else
		{
			_Data->_GuessedRollOverCounter = _Data->_RollOverCounter;
		}
	}

	return ((uint64_t)_Data->_GuessedRollOverCounter) << 16 | newSeqNb;
}

bool zCryptoContext::CheckReplay( uint16_t newSeqNb )
{
	if ( _Data->_SrtpAuthenticationAlgo == SrtpAuthenticationNull && _Data->_SrtpEncryptionAlgo == SrtpEncryptionNull )
	{
		return true;
	}

	if (!_Data->_SeqNumSet)
	{
		_Data->_SeqNumSet = true;
		_Data->_s_1 = newSeqNb;
	}
	uint64_t guessed_index = GuessIndex( newSeqNb );
	uint64_t local_index = (((uint64_t)_Data->_RollOverCounter) << 16) | _Data->_s_1;

	int64_t d = guessed_index - local_index;
	if (d > 0)
	{
		return true;
	}
	else
	{
		if ( -d > REPLAY_WINDOW_SIZE )
		{
			return false;
		}
		else
		{
			if ((_Data->_ReplayWindow >> (-d)) & 0x1)
			{
				return false;
			}
			else
			{
				return true;
			}
		}
	}
}

void zCryptoContext::Update(uint16_t newSeqNb)
{
	int64_t d = GuessIndex(newSeqNb) - (((uint64_t)_Data->_RollOverCounter) << 16 | _Data->_s_1 );

	if ( d > 0 )
	{
		_Data->_ReplayWindow = _Data->_ReplayWindow << d;
		_Data->_ReplayWindow |= 1;
	}
	else
	{
		_Data->_ReplayWindow |= ( 1 << d );
	}

	if ( newSeqNb > _Data->_s_1 )
	{
		_Data->_s_1 = newSeqNb;
	}
	if ( _Data->_GuessedRollOverCounter > _Data->_RollOverCounter )
	{
		_Data->_RollOverCounter = _Data->_GuessedRollOverCounter;
		_Data->_s_1 = newSeqNb;
	}
}

void zCryptoContext::SetRoc(uint32_t r)
{
	_Data->_RollOverCounter = r;
}

uint32_t zCryptoContext::GetRoc() const
{
	return _Data->_RollOverCounter;
}

int32_t zCryptoContext::GetTagLength() const
{
	return _Data->_AuthTagLegth;
}

int32_t zCryptoContext::GetMkiLength() const
{
	return _Data->_MkiLength;
}

uint32_t zCryptoContext::GetSsrc() const
{
	return _Data->_SSRC;
}

zCryptoContext* zCryptoContext::NewCryptContextForSSRC (
	uint32_t ssrc,
	uint16_t roc,
	int64_t key_derivation_rate )
{
	return this->NewCryptContextForSSRC(_Data->_CallID, ssrc, roc, key_derivation_rate);
}

zCryptoContext* zCryptoContext::NewCryptContextForSSRC (
	int32_t callId, uint32_t ssrc,
	uint16_t roc, int64_t keyDerivRate )
{
	// This method will return new cryptographic context
	// with data of current context replacing
	// key derivation rate, roc and ssrc.

	zCryptoContext* pCryptoContext = new zCryptoContext (
		callId, ssrc, roc, keyDerivRate,
		this->_Data->_SrtpEncryptionAlgo,
		this->_Data->_SrtpAuthenticationAlgo,
		this->_Data->_SRTPCryptCtxMasterKey,
		this->_Data->_SRTPCryptCtxMasterKeyLength,
		this->_Data->_SessionMasterSalt,
		this->_Data->_SessionMasterSaltLength,
		this->_Data->_SrtpEncryptionKeyLength,
		this->_Data->_SrtpAuthenticationKeyLength,
		this->_Data->_SessionSatlKeyLength,
		this->_Data->_AuthTagLegth );

	return pCryptoContext;
}

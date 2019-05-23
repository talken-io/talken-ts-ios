/******************************************************************************
 * TrustSigner Library (BTC,ETH,XLM Keypair/Signature Maker)
 *
 * Description : Coin keypair and signature create header
 *
 * Copyright (C) 2018-2019 NexL Corporation. All rights reserved.
 * http://www.nexl.kr (myseo@nexl.kr)
 ******************************************************************************
 * Edit History
 * When            Who         What, Where, Why
 * 2019/01/01      myseo       create.
 * 2019/01/31      myseo       BIP44 spec added.
 ******************************************************************************/

#ifndef TRUST_SINER_COIN_H
#define TRUST_SINER_COIN_H

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "bip32_bip39.h"

#if defined(__cplusplus)
extern "C" {
#endif

#define BIP39_KEY_STRENGTH_64		64  // 6 keyword
#define BIP39_KEY_STRENGTH_128		128 // 12 keyword
#define BIP39_KEY_STRENGTH_256		256 // 24 keyword // default

#define BIP39_KEY_STRENGTH			BIP39_KEY_STRENGTH_256
#define BIP32_KEY_LENGTH			64

#define BIP44_PATH_DEPTH_MAX		5

#define BIP44_PATH_PURPOSE			0
#define BIP44_PATH_COIN_TYPE		1
#define BIP44_PATH_ACCOUNT			2
#define BIP44_PATH_CHANGE			3
#define BIP44_PATH_ADDR_INDEX		4

#define BIP44_VAL_HARDENED			0x80000000
#define BIP44_VAL_PURPOSE			44
#ifdef NDEBUG // MAINNET
#define BIP44_VAL_BITCOIN			0
#else // TESTNET
#define BIP44_VAL_BITCOIN			1
#endif
#define BIP44_VAL_ETHEREUM			60
#define BIP44_VAL_STELLAR			148

#define SIGN_HASH_LENGTH			32
#define SIGN_SIGNATURE_LENGTH		64
#define SIGN_SIGNATURE_MAX			32
#define SIGN_SIGNATURE_MAX_LENGTH	((SIGN_SIGNATURE_LENGTH+1)*SIGN_SIGNATURE_MAX)

#define MNEMONIC_MAX_LENGTH			1024 // magic number calculated from wordlists

#define RANDOM_NONCE_LENGTH			32
#define AES256_IV_LENGTH			16
#define AES256_ENCRYPT_LENGTH		64

#define RECOVERY_BUFFER_LENGTH		1024
#define TEMP_BUFFER_LENGTH			512

#define ETHEREUM_ADDRESS_LENGTH		20

#define STELLAR_ADDRESS_LENGTH		56
#define STELLAR_ADDRESS_RAW_LENGTH	35
#define STELLAR_KEY_LENGTH 			32


#define COIN_TYPE_BITCOIN			0x1100
#define COIN_TYPE_ETHEREUM			0x1200
#define COIN_TYPE_STELLAR			0x1300
#define COIN_TYPE_EOS				0x1400

#define COIN_TYPE_ICON				0x2100



typedef struct _CoinInfo {
	const char *coin_name;
	const char *coin_shortcut;
	uint64_t maxfee_kb;
	const char *signed_message_header;
	bool has_address_type;
	bool has_address_type_p2sh;
	bool has_segwit;
	bool has_forkid;
	bool force_bip143;
	uint32_t address_type;
	uint32_t address_type_p2sh;
	uint32_t xpub_magic;
	uint32_t xprv_magic;
	uint32_t forkid;
	const char *bech32_prefix;
	uint32_t coin_type;
	const char *curve_name;
	const curve_info *curve;
} CoinInfo;

void bitcoin_message_sign(const HDNode *node, const uint8_t *message, const uint32_t message_len, uint8_t *signature);
int bitcoin_message_verify(const uint8_t *message, const uint32_t message_len, uint8_t *signature, uint8_t *address);
void bitcoin_hash_sign(const HDNode *node, const uint8_t *hash, uint8_t *signature);

void ethereum_message_sign(const HDNode *node, const uint8_t *message, const uint32_t message_len, uint8_t *signature, uint8_t *address);
int ethereum_message_verify(const uint8_t *message, const uint32_t message_len, uint8_t *signature, uint8_t *address);
void ethereum_hash_sign(const HDNode *node, const uint8_t *hash, uint8_t *signature);

size_t stellar_publicAddressAsStr(const uint8_t *bytes, char *out, size_t outlen);
bool stellar_validateAddress(const char *str_address);
bool stellar_getAddressBytes(const char* str_address, uint8_t *out_bytes);
void stellar_message_sign(const HDNode *node, const uint8_t *message, const uint32_t message_len, uint8_t *signature);
void stellar_hash_sign(const HDNode *node, const uint8_t *hash, uint8_t *signature);

unsigned int coin_derive_node(HDNode *node, const uint32_t *address, const size_t length);

#if defined(__cplusplus)
}
#endif

#endif

/******************************************************************************
 * TrustSigner Library (BTC,ETH,XLM Keypair/Signature Maker)
 *
 * Description : Coin keypair and signature create function
 *
 * Copyright (C) 2018-2019 NexL Corporation. All rights reserved.
 * http://www.nexl.kr (myseo@nexl.kr)
 ******************************************************************************
 * Edit History
 * When            Who         What, Where, Why
 * 2019/01/01      myseo       create.
 * 2019/01/31      myseo       BIP44 spec added.
 ******************************************************************************/


#include "coin.h"

#include "secp256k1.h"
#include "base32.h"
#include "base58.h"
#include "hasher.h"
#include "address.h"
#include "memzero.h"

#define COIN_INFOR_BITCOIN		0
#define COIN_INFOR_TESTNET		1
#define COIN_INFOR_BITCOINCASH	2
#define COIN_INFOR_LITECOIN		3
#define COIN_INFOR_DASH			4
#define COIN_INFOR_ZCASH		5
#define COIN_INFOR_BITCOINGOLD	6

#define COIN_INFOR_COUNT		(COIN_INFOR_BITCOINGOLD+1)

const CoinInfo coins[COIN_INFOR_COUNT] = {
	{"Bitcoin",      " BTC",     2000000, "\x18" "Bitcoin Signed Message:\n",      true, true, true,  false, false,    0,    5, 0x0488b21e, 0x0488ade4,  0, "bc",   0x80000000, SECP256K1_NAME, &secp256k1_info, },
	{"Testnet",      " TEST",   10000000, "\x18" "Bitcoin Signed Message:\n",      true, true, true,  false, false,  111,  196, 0x043587cf, 0x04358394,  0, "tb",   0x80000001, SECP256K1_NAME, &secp256k1_info, },
	{"Bcash",        " BCH",      500000, "\x18" "Bitcoin Signed Message:\n",      true, true, false, true,  true,     0,    5, 0x0488b21e, 0x0488ade4,  0, NULL,   0x80000091, SECP256K1_NAME, &secp256k1_info, },
	{"Litecoin",     " LTC",    40000000, "\x19" "Litecoin Signed Message:\n",     true, true, true,  false, false,   48,   50, 0x019da462, 0x019d9cfe,  0, "ltc",  0x80000002, SECP256K1_NAME, &secp256k1_info, },
	{"Dash",         " DASH",     100000, "\x19" "DarkCoin Signed Message:\n",     true, true, false, false, false,   76,   16, 0x02fe52cc, 0x02fe52f8,  0, NULL,   0x80000005, SECP256K1_NAME, &secp256k1_info, },
	{"Zcash",        " ZEC",     1000000, "\x16" "Zcash Signed Message:\n",        true, true, false, false, false, 7352, 7357, 0x0488b21e, 0x0488ade4,  0, NULL,   0x80000085, SECP256K1_NAME, &secp256k1_info, },
	{"Bitcoin Gold", " BTG",      500000, "\x1d" "Bitcoin Gold Signed Message:\n", true, true, true,  true,  true,    38,   23, 0x0488b21e, 0x0488ade4, 79, "btg",  0x8000009c, SECP256K1_NAME, &secp256k1_info, },
};

#if 0 // DEBUG
#include "bip32_bip39.h"
char hexbuf[256];
#endif

static uint32_t ser_length(uint32_t len, uint8_t *out)
{
	if (len < 253) {
		out[0] = len & 0xFF;
		return 1;
	}
	if (len < 0x10000) {
		out[0] = 253;
		out[1] = len & 0xFF;
		out[2] = (len >> 8) & 0xFF;
		return 3;
	}
	out[0] = 254;
	out[1] = len & 0xFF;
	out[2] = (len >> 8) & 0xFF;
	out[3] = (len >> 16) & 0xFF;
	out[4] = (len >> 24) & 0xFF;
	return 5;
}

static void bitcoin_message_hash(const uint8_t *message, size_t message_len, uint8_t hash[HASHER_DIGEST_LENGTH])
{
	uint8_t varint[5] = {0};
	uint32_t l = 0;
	Hasher hasher;

	hasher_Init(&hasher, coins[COIN_INFOR_BITCOIN].curve->hasher_sign);
	hasher_Update(&hasher, (const uint8_t *)coins[COIN_INFOR_BITCOIN].signed_message_header, strlen(coins[COIN_INFOR_BITCOIN].signed_message_header));
	l = ser_length(message_len, varint);
	hasher_Update(&hasher, varint, l);
	hasher_Update(&hasher, message, message_len);
	hasher_Final(&hasher, hash);
}

void bitcoin_message_sign(const HDNode *node, const uint8_t *message, const uint32_t message_len, uint8_t *signature)
{
	uint8_t v = 0;
	uint8_t hash[HASHER_DIGEST_LENGTH] = {0};

	bitcoin_message_hash(message, message_len, hash);

	if (ecdsa_sign_digest(&secp256k1, node->private_key, hash, signature + 1, &v, NULL) != 0) {
		printf("Error! Bitcoin signing failed\n");
		return;
	}
	// segwit-in-p2sh
	//signature[0] = 35 + v;
	// segwit
	//signature[0] = 39 + v;
	// p2pkh
	signature[0] = 31 + v;
}

int bitcoin_message_verify(const uint8_t *message, const uint32_t message_len, uint8_t *signature, uint8_t *address)
{
	uint8_t recid = 0;
	bool compressed = 0;
	uint8_t pubkey[65] = {0};
	uint8_t hash[HASHER_DIGEST_LENGTH] = {0};

	// check if the address is correct
	uint8_t addr_raw[MAX_ADDR_RAW_SIZE] = {0};
	uint8_t recovered_raw[MAX_ADDR_RAW_SIZE] = {0};

	// check for invalid signature prefix
	if (signature[0] < 27 || signature[0] > 43) {
		printf("Failed! Check if signature verifies.\n");
		return 1;
	}

#if 0 // MYSEO : hash message input
	bitcoin_message_hash(message, message_len, hash);
#else
	memcpy(hash, message, message_len);
#endif

	recid = (signature[0] - 27) % 4;
	compressed = signature[0] >= 31;

	// check if signature verifies the digest and recover the public key
	if (ecdsa_recover_pub_from_sig(&secp256k1, pubkey, signature + 1, hash, recid) != 0) {
		printf("Failed! Check if signature verifies.\n");
		return 3;
	}
	// convert public key to compressed pubkey if necessary
	if (compressed) {
		pubkey[0] = 0x02 | (pubkey[64] & 1);
	}

#if 0 // MYSEO : debug
	hex_print (hexbuf, pubkey, sizeof(pubkey));
	printf("pubkey : %s\n", hexbuf);
#endif
	// p2pkh
	if (signature[0] >= 27 && signature[0] <= 34) {
		size_t len;
		len = base58_decode_check((char *)address, coins[COIN_INFOR_TESTNET].curve->hasher_base58, addr_raw, MAX_ADDR_RAW_SIZE);
#if 0 // MYSEO : debug
		hex_print (hexbuf, addr_raw, MAX_ADDR_RAW_SIZE);
		printf("addr_raw      : %s\n", hexbuf);
#endif
		ecdsa_get_address_raw(pubkey, coins[COIN_INFOR_TESTNET].address_type, coins[COIN_INFOR_TESTNET].curve->hasher_pubkey, recovered_raw);
#if 0 // MYSEO : debug
		hex_print (hexbuf, recovered_raw, MAX_ADDR_RAW_SIZE);
		printf("recovered_raw : %s\n", hexbuf);
#endif
		if (memcmp(recovered_raw, addr_raw, len) != 0 || len != address_prefix_bytes_len(coins[COIN_INFOR_TESTNET].address_type) + 20) {
			printf("Failed! Check if signature verifies.\n");
			return 2;
		}
	}
#if 0 // MYSEO : not yet!!
	// https://github.com/sipa/bech32/blob/master/ref/c/segwit_addr.c
	else {
		// segwit-in-p2sh
		if (signature[0] >= 35 && signature[0] <= 38) {
			size_t len = base58_decode_check((char *)address, coins[COIN_INFOR_BITCOIN].curve->hasher_base58, addr_raw, MAX_ADDR_RAW_SIZE);
			ecdsa_get_address_segwit_p2sh_raw(pubkey, coins[COIN_INFOR_BITCOIN].address_type_p2sh, coins[COIN_INFOR_BITCOIN].curve->hasher_pubkey, recovered_raw);
			if (memcmp(recovered_raw, addr_raw, len) != 0
					|| len != address_prefix_bytes_len(coins[COIN_INFOR_BITCOIN].address_type_p2sh) + 20) {
				return 2;
			}
		} else {
			// segwit
			if (signature[0] >= 39 && signature[0] <= 42) {
				int witver;
				size_t len;
				if (!coins[COIN_INFOR_BITCOIN].bech32_prefix
						|| !segwit_addr_decode(&witver, recovered_raw, &len, coins[COIN_INFOR_BITCOIN].bech32_prefix, address)) {
					return 4;
				}
				ecdsa_get_pubkeyhash(pubkey, coins[COIN_INFOR_BITCOIN].curve->hasher_pubkey, addr_raw);
				if (memcmp(recovered_raw, addr_raw, len) != 0
						|| witver != 0 || len != 20) {
					return 2;
				}
			} else {
				return 4;
			}
		}
	}
#endif

	return 0;
}

void bitcoin_hash_sign(const HDNode *node, const uint8_t *hash, uint8_t *signature)
{
	uint8_t v = 0;
	if (ecdsa_sign_digest(&secp256k1, node->private_key, hash, signature + 1, &v, NULL) != 0) {
		printf("Error! Bitcoin signing failed\n");
		return;
	}
	signature[0] = 31 + v;

#if 0 // TEST
	if (ecdsa_verify_digest(&secp256k1, node->public_key, signature + 1, hash) != 0) {
		printf("### MYSEO : Bitcoin sign veryfy failed\n");
	} else {
		printf("### MYSEO : Bitcoin sign veryfy OK!\n");
	}
#endif
}


static int ethereum_is_canonic(uint8_t v, uint8_t signature[64])
{
	(void) signature;
	return (v & 2) == 0;
}

static void ethereum_message_hash(const uint8_t *message, size_t message_len, uint8_t hash[HASHER_DIGEST_LENGTH])
{
	uint8_t c;
	struct SHA3_CTX ctx;

	sha3_256_Init(&ctx);
	sha3_Update(&ctx, (const uint8_t *)"\x19" "Ethereum Signed Message:\n", 26);

	if (message_len > 1000000000) { c = '0' + message_len / 1000000000 % 10; sha3_Update(&ctx, &c, 1); }
	if (message_len > 100000000)  { c = '0' + message_len / 100000000  % 10; sha3_Update(&ctx, &c, 1); }
	if (message_len > 10000000)   { c = '0' + message_len / 10000000   % 10; sha3_Update(&ctx, &c, 1); }
	if (message_len > 1000000)    { c = '0' + message_len / 1000000    % 10; sha3_Update(&ctx, &c, 1); }
	if (message_len > 100000)     { c = '0' + message_len / 100000     % 10; sha3_Update(&ctx, &c, 1); }
	if (message_len > 10000)      { c = '0' + message_len / 10000      % 10; sha3_Update(&ctx, &c, 1); }
	if (message_len > 1000)       { c = '0' + message_len / 1000       % 10; sha3_Update(&ctx, &c, 1); }
	if (message_len > 100)        { c = '0' + message_len / 100        % 10; sha3_Update(&ctx, &c, 1); }
	if (message_len > 10)         { c = '0' + message_len / 10         % 10; sha3_Update(&ctx, &c, 1); }

	c = '0' + message_len % 10;
	sha3_Update(&ctx, &c, 1);
	sha3_Update(&ctx, message, message_len);
    sha3_Final(&ctx, hash);
}

void ethereum_message_sign(const HDNode *node, const uint8_t *message, const uint32_t message_len, uint8_t *signature, uint8_t *address)
{
	uint8_t v;
	uint8_t hash[HASHER_DIGEST_LENGTH] = {0};

	if (!hdnode_get_ethereum_pubkeyhash(node, address)) {
		printf("Error! Ethereum signing failed\n");
		return;
	}

	ethereum_message_hash(message, message_len, hash);

	if (ecdsa_sign_digest(&secp256k1, node->private_key, hash, signature, &v, ethereum_is_canonic) != 0) {
		printf("Error! Ethereum signing failed\n");
		return;
	}
	signature[64] = 27 + v;
}

int ethereum_message_verify(const uint8_t *message, const uint32_t message_len, uint8_t *signature, uint8_t *address)
{
	uint8_t pubkey[65] = {0};
	uint8_t hash[HASHER_DIGEST_LENGTH] = {0};

#if 0 // MYSEO : hash message input
	ethereum_message_hash(message, message_len, hash);
#else
	memcpy(hash, message, message_len);
#endif

	/* v should be 27, 28 but some implementations use 0,1.  We are
	 * compatible with both.
	 */
	uint8_t v = signature[64];
	if (v >= 27) {
		v -= 27;
	}
	if (v >= 2 || ecdsa_recover_pub_from_sig(&secp256k1, pubkey, signature, hash, v) != 0) {
		printf("Failed! Check if signature verifies.\n");
		return -1;
	}

#if 0 // MYSEO : debug
	hex_print (hexbuf, pubkey, sizeof(pubkey));
	printf("pubkey : %s\n", hexbuf);
#endif

	memset(hash, 0, sizeof(hash));
	struct SHA3_CTX ctx;
	sha3_256_Init(&ctx);
	sha3_Update(&ctx, pubkey + 1, 64);
	sha3_Final(&ctx, hash);

#if 0 // MYSEO : debug
	hex_print (hexbuf, address, 20);
	printf("address    : %s\n", hexbuf);
	hex_print (hexbuf, hash + 12, 20);
	printf("hashpubkey : %s\n", hexbuf);
#endif

	/* result are the least significant 160 bits */
	if (memcmp(address, hash + 12, 20) != 0) {
		printf("Failed! Check if signature verifies.\n");
		return -1;
	}

	return 0;
}

void ethereum_hash_sign(const HDNode *node, const uint8_t *hash, uint8_t *signature)
{
	uint8_t v = 0;
    uint8_t address[20] = {0};
	if (!hdnode_get_ethereum_pubkeyhash(node, address)) {
		printf("Error! Ethereum signing failed\n");
        return;
    }
	if (ecdsa_sign_digest(&secp256k1, node->private_key, hash, signature, &v, ethereum_is_canonic) != 0) {
		printf("Error! Ethereum signing failed\n");
		return;
	}
	signature[64] = 27 + v;
}


/*
 * CRC16 implementation compatible with the Stellar version
 * Ported from this implementation: http://introcs.cs.princeton.edu/java/61data/CRC16CCITT.java.html
 * Initial value changed to 0x0000 to match Stellar
 */
static uint16_t stellar_crc16(uint8_t *bytes, uint32_t length)
{
	// Calculate checksum for existing bytes
	uint16_t crc = 0x0000;
	uint16_t polynomial = 0x1021;
	uint32_t i;
	uint8_t bit;
	uint8_t byte;
	uint8_t bitidx;
	uint8_t c15;

	for (i=0; i < length; i++) {
		byte = bytes[i];
		for (bitidx=0; bitidx < 8; bitidx++) {
			bit = ((byte >> (7 - bitidx) & 1) == 1);
			c15 = ((crc >> 15 & 1) == 1);
			crc <<= 1;
			if (c15 ^ bit) crc ^= polynomial;
		}
	}

	return crc & 0xffff;
}

size_t stellar_publicAddressAsStr(const uint8_t *bytes, char *out, size_t outlen)
{
	// version + key bytes + checksum
	uint8_t keylen = 1 + 32 + 2;
	uint8_t bytes_full[keylen];
	bytes_full[0] = 6 << 3; // 'G'

	memcpy(bytes_full + 1, bytes, 32);

	// Last two bytes are the checksum
	uint16_t checksum = stellar_crc16(bytes_full, 33);
	bytes_full[keylen-2] = checksum & 0x00ff;
	bytes_full[keylen-1] = (checksum>>8) & 0x00ff;

	base32_encode(bytes_full, keylen, out, outlen, BASE32_ALPHABET_RFC4648);

	// Public key will always be 56 characters
	return 56;
}

/*
 * Stellar account string is a base32-encoded string that starts with "G"
 *
 * It decodes to the following format:
 *  Byte 0 - always 0x30 ("G" when base32 encoded), version byte indicating a public key
 *  Bytes 1-33 - 32-byte public key bytes
 *  Bytes 34-35 - 2-byte CRC16 checksum of the version byte + public key bytes (first 33 bytes)
 *
 * Note that the stellar "seed" (private key) also uses this format except the version byte
 * is 0xC0 which encodes to "S" in base32
 */
bool stellar_validateAddress(const char *str_address)
{
	bool valid = false;
	uint8_t decoded[STELLAR_ADDRESS_RAW_LENGTH] = {0};

	if (strlen(str_address) != STELLAR_ADDRESS_LENGTH) {
		return false;
	}

	// Check that it decodes correctly
	uint8_t *ret = base32_decode(str_address, STELLAR_ADDRESS_LENGTH, decoded, sizeof(decoded), BASE32_ALPHABET_RFC4648);
	valid = (ret != NULL);

	// ... and that version byte is 0x30
	if (valid && decoded[0] != 0x30) {
		valid = false;
	}

	// ... and that checksums match
	uint16_t checksum_expected = stellar_crc16(decoded, 33);
	uint16_t checksum_actual = (decoded[34] << 8) | decoded[33]; // unsigned short (little endian)
	if (valid && checksum_expected != checksum_actual) {
		valid = false;
	}

	memzero(decoded, sizeof(decoded));
	return valid;
}

bool stellar_getAddressBytes(const char* str_address, uint8_t *out_bytes)
{
	uint8_t decoded[STELLAR_ADDRESS_RAW_LENGTH] = {0};

	// Ensure address is valid
	if (!stellar_validateAddress(str_address)) return false;

	base32_decode(str_address, STELLAR_ADDRESS_LENGTH, decoded, sizeof(decoded), BASE32_ALPHABET_RFC4648);

	// The 32 bytes with offset 1-33 represent the public key
	memcpy(out_bytes, &decoded[1], 32);

	memzero(decoded, sizeof(decoded));
	return true;
}

void stellar_message_sign(const HDNode *node, const uint8_t *message, const uint32_t message_len, uint8_t *signature)
{
	ed25519_sign(message, message_len, node->private_key, node->public_key + 1, signature);
}

void stellar_hash_sign(const HDNode *node, const uint8_t *hash, uint8_t *signature)
{
	ed25519_sign(hash, SIGN_HASH_LENGTH, node->private_key, node->public_key+1, signature);
}

#if 0  // MYSEO
int stellar_message_verify(const uint8_t *message, const uint32_t message_len, uint8_t *signature, uint8_t *address)
{
	return 0;
}
#endif


/*
 * Derives the HDNode at the given index
 * m/purpose'/coin_type'/account'/change/address_index
 * Bitcoin prefix is m/44'/0'/0' and the default account is m/44'/0'/0'/0/0
 * Ethereum prefix is m/44'/60'/0' and the default account is m/44'/60'/0'/0/0
 * Stellar prefix is m/44'/148'/ and the default account is m/44'/148'/0'
 * Hardened => x | 0x80000000
 */
unsigned int coin_derive_node(HDNode *node, const uint32_t *address, const size_t length)
{
	int i = 0;
	uint32_t fingerprint = 0;

#if 0
	char private_key[BIP32_KEY_LENGTH*2] = {0};
	char public_key[BIP32_KEY_LENGTH*2] = {0};

	hdnode_fill_public_key (node);
	hdnode_serialize_private (node, fingerprint, VERSION_PRIVATE, private_key, 128);
	printf ("M : %s\n", private_key);
#endif

	for (i=0; i<(int)length; i++) {
		fingerprint = hdnode_fingerprint(node);
		if (hdnode_private_ckd(node, address[i]) == 0) {
			memzero(node, sizeof(node));
			return 0xFFFFFFFF;
		}
#if 0
		memset (private_key, 0, sizeof(private_key));
		hdnode_fill_public_key(node);
		hdnode_serialize_private (node, fingerprint, VERSION_PRIVATE, private_key, 128);
		printf ("%d(0x%x) : 0x%08x : %s\n", i, fingerprint, address[i], private_key);
#endif
	}

	if (i >= (int)length) {
		hdnode_fill_public_key((HDNode *)node);
	}

#if 0
	hdnode_serialize_public (node, fingerprint, VERSION_PUBLIC, public_key, 128);
	printf ("FP  : 0x%x\n", fingerprint);
	printf ("Pub : %s\n", public_key);
#endif

	return fingerprint;
}

/******************************************************************************
 * TrustSigner Library (BTC,ETH,XLM Keypair/Signature Maker)
 *
 * Description : JNI function
 *
 * Copyright (C) 2018-2019 NexL Corporation. All rights reserved.
 * http://www.nexl.kr (myseo@nexl.kr)
 ******************************************************************************
 * Edit History
 * When            Who         What, Where, Why
 * 2019/01/08      myseo       create.
 * 2019/01/17      myseo       coin type added.
 * 2019/01/22      myseo       AES256, SHA512 using.
 * 2019/01/23      myseo       Android <-> Shell compile define added.
 * 2019/01/31      myseo       BIP44 spec added.
 * 2019/02/02      myseo       Base64 source added.
 * 2019/02/07      myseo       Recovery data GET/SET function added.
 * 2019/02/22      myseo       BTC, ETH, XLM signature added.
 * 2019/02/28      myseo       XLM signature OK.
 * 2019/03/08      myseo       ETH signature OK.
 * 2019/03/22      myseo       BTC signature OK.
 * 2019/03/27      myseo       white-box crypto table to save a internal file.
 * 2019/04/02      myseo       Android recovery get/set modify.
 * 2019/04/08      myseo       Set recovery bug fixed.
 * 2019/04/18      myseo       iOS code modify.
 * 2019/04/29      myseo       iOS char data return code modify.
 ******************************************************************************/

#if defined(__ANDROID__)
#include <jni.h>
#endif

#include <stdio.h>
#include <stdlib.h>
#include <string>
#include <unistd.h>
#include <dlfcn.h>

#include "secp256k1.h"
#include "base32.h"
#include "base58.h"
#include "hasher.h"
#include "address.h"
#include "rand.h"
#include "memzero.h"

#include "aes.h"
#include "sha2.h"

#include "WBAES.h"
#include "WBAESGenerator.h"
#include "InputObjectBuffer.h"
#include "EncTools.h"

#include "trustsigner.h"
#include "coin.h"
#include "whitebox.h"
#include "base64.h"

#if defined(__ANDROID__)
#ifndef NDEBUG
#define DEBUG_TRUST_SIGNER 1
#endif
#define __FILES__ 1
#define __WHITEBOX__ 1
#endif

#ifdef DEBUG_TRUST_SIGNER
char hexbuf[512];

#if defined(__ANDROID__)
#include <android/log.h>
#define LOG_TAG		"### MYSEO "
#define LOGD(...)	__android_log_print(ANDROID_LOG_DEBUG, LOG_TAG, __VA_ARGS__)
#define LOGE(...)	__android_log_print(ANDROID_LOG_ERROR, LOG_TAG, __VA_ARGS__)
#else
#define LOGD(...)	printf(__VA_ARGS__)
#define LOGE(...)	printf(__VA_ARGS__)
#endif
#else
#define LOGD(...)	(__VA_ARGS__)
#define LOGE(...)	(__VA_ARGS__)
#endif

#if defined(__FILES__)
#define PREFERENCE_WB			"trustsigner.wbd"
#define RECOVERY_WB				"trustsigner.wbr"
#endif

#if defined(__ANDROID__)
static char *jbyteArry2char (JNIEnv *env, jbyteArray in)
{
	int len = env->GetArrayLength (in);
	char *ret = (char *) malloc ((size_t)len);

	if (ret != NULL) {
		jbyte *jin = env->GetByteArrayElements (in, 0);
		memcpy (ret, (const char *) jin, (size_t) len);
		env->ReleaseByteArrayElements(in, jin, 0);
	}

	return ret;
}

static jbyteArray char2JbyteArry (JNIEnv *env, char *in, int len)
{
	jbyteArray array = env->NewByteArray (len);

	if (in != NULL && array != NULL) {
		env->SetByteArrayRegion(array, 0, len, (jbyte *) in);
	} else {
		return NULL;
	}

	return array;
}

static unsigned char *jbyteArry2uchar (JNIEnv *env, jbyteArray in)
{
	int len = env->GetArrayLength (in);
	unsigned char *ret = (unsigned char *) malloc ((size_t)len);

	if (ret != NULL) {
		jbyte *jin = env->GetByteArrayElements (in, 0);
		memcpy (ret, (const char *) jin, (size_t) len);
		env->ReleaseByteArrayElements(in, jin, 0);
	}

	return ret;
}

static jbyteArray uchar2JbyteArry (JNIEnv *env, unsigned char *in, int len)
{
	jbyteArray array = env->NewByteArray (len);

	if (in != NULL && array != NULL) {
		env->SetByteArrayRegion(array, 0, len, (jbyte *) in);
	} else {
		return NULL;
	}

	return array;
}
#endif

#if defined(__FILES__) // MYSEO : Recovery
static int writeWBData (char *file_name, unsigned char *wb_data, int data_length) {
	size_t ret = 0;
	FILE *fp = NULL;

	fp = fopen (file_name, "wb");
	if (fp == NULL) {
#ifdef DEBUG_TRUST_SIGNER
		LOGE("Error! File open failed! (%s)\n", file_name);
#endif
		return -1;
	}

	ret = fwrite (&data_length, sizeof(data_length), 1, fp);
	if (ret <= 0) {
#ifdef DEBUG_TRUST_SIGNER
		LOGE("Error! Size write failed! (%d)\n", (int) ret);
#endif
		fclose (fp);
		return -1;
	}
	ret = fwrite (wb_data, (size_t) data_length, 1, fp);
	if (ret <= 0) {
#ifdef DEBUG_TRUST_SIGNER
		LOGE("Error! Data write failed! (%d)\n", (int) ret);
#endif
		fclose (fp);
		return -1;
	}

	fflush (fp);
	fclose (fp);

	return (int) ret;
}

static int readWBData (char *file_name, unsigned char *wb_data) {
	size_t ret = 0;
	int data_length = 0;
	FILE *fp = NULL;

	fp = fopen (file_name, "rb");
	if (fp == NULL) {
#ifdef DEBUG_TRUST_SIGNER
		LOGE("Error! File open failed! (%s)\n", file_name);
#endif
		return -1;
	}

	ret = fread (&data_length, sizeof(data_length), 1, fp);
	if (ret <= 0) {
#ifdef DEBUG_TRUST_SIGNER
		LOGE("Error! Size read failed! (%d)\n", (int) ret);
#endif
		fclose (fp);
		return -1;
	}

	unsigned char *buff[1024] = {0};
	ret = fread (buff, sizeof(buff), 1, fp);
	if (ret != 0) {
#ifdef DEBUG_TRUST_SIGNER
		LOGE("Error! Data read failed! (%d, %d)\n", (int) ret, data_length);
#endif
		fclose (fp);
		return -1;
	}
	memcpy (wb_data, buff, (size_t) data_length);

	fclose (fp);
	return data_length;
}

static int readRecovery (unsigned char *buffer, char *file_path) {
	int wb_buf_len = 0;
	unsigned char wb_buffer[RECOVERY_BUFFER_LENGTH] = {0};

	char file_name[256] = {0};
	sprintf (file_name, "%s/%s", file_path, PREFERENCE_WB);
	char rfile_name[256] = {0};
	sprintf (rfile_name, "%s/%s", file_path, RECOVERY_WB);

	wb_buf_len = readWBData (rfile_name, wb_buffer);
	if (wb_buf_len <= 0) {
		memzero (wb_buffer, sizeof(wb_buffer));
		return -1;
	}

#if defined(__WHITEBOX__)
	wb_buf_len = trust_signer_encrypt_fp (file_name, wb_buffer, wb_buf_len, buffer, false);
	memzero (wb_buffer, sizeof(wb_buffer));
#else
    memcpy (buffer, wb_buffer, wb_buf_len);
#endif
    
	return wb_buf_len;
}

static int writeRecovery (unsigned char *buffer, int buffer_len, char *file_path) {
	int wb_buf_len = 0;
	unsigned char wb_buffer[RECOVERY_BUFFER_LENGTH] = {0};

	char file_name[256] = {0};
	sprintf (file_name, "%s/%s", file_path, PREFERENCE_WB);
	char rfile_name[256] = {0};
	sprintf (rfile_name, "%s/%s", file_path, RECOVERY_WB);

#if defined(__WHITEBOX__)
	wb_buf_len = trust_signer_encrypt_fp (file_name, buffer, buffer_len, wb_buffer, true);
#else
    wb_buf_len = buffer_len;
    memcpy (wb_buffer, buffer, buffer_len);
#endif

	if (access (rfile_name, F_OK) != -1) {
		unlink (rfile_name);
	}
	if (writeWBData (rfile_name, wb_buffer, wb_buf_len) <= 0) {
		memzero (wb_buffer, sizeof(wb_buffer));
		return -1;
	}
	memzero (wb_buffer, sizeof(wb_buffer));

	return 0;
}
#endif

static int decryptAES256 (unsigned char *key, int key_len, unsigned char *message, int message_len, unsigned char *buffer) {
	int ret = -1;
	int enc_count = 1;

	aes_decrypt_ctx ctx_aes;
	uint8_t iv[AES_BLOCK_SIZE] ={0};
	uint8_t dec_key[SHA3_256_DIGEST_LENGTH] = {0};

	SHA512_CTX ctx_sha;
	unsigned char hashbuf[SHA3_512_DIGEST_LENGTH];

	sha512_Init (&ctx_sha);
	sha512_Update (&ctx_sha, key, (size_t) key_len);
	sha512_Final (&ctx_sha, hashbuf);
	memzero (&ctx_sha, sizeof(ctx_sha));

	memcpy (iv, hashbuf+(enc_count++), AES_BLOCK_SIZE/2);
	memcpy (dec_key, hashbuf+(enc_count++)+(AES_BLOCK_SIZE/2), SHA3_256_DIGEST_LENGTH/2);
	memcpy (iv+(AES_BLOCK_SIZE/2), hashbuf+(enc_count++)+(AES_BLOCK_SIZE/2)+(SHA3_256_DIGEST_LENGTH/2), AES_BLOCK_SIZE/2);
	memcpy (dec_key+(SHA3_256_DIGEST_LENGTH/2), hashbuf+(enc_count+1)+AES_BLOCK_SIZE+(SHA3_256_DIGEST_LENGTH/2), SHA3_256_DIGEST_LENGTH/2);
	memzero (hashbuf, sizeof(hashbuf));

#if 0 //def DEBUG_TRUST_SIGNER
	hex_print (hexbuf, iv, sizeof(iv));
	LOGD("IV : %s\n", hexbuf);
	hex_print (hexbuf, dec_key, sizeof(dec_key));
	LOGD("KEY : %s\n", hexbuf);
#endif

	if (aes_decrypt_key256 (dec_key, &ctx_aes) == EXIT_SUCCESS) {
		if (aes_cbc_decrypt (message, buffer, message_len, iv, &ctx_aes) == EXIT_SUCCESS) {
			ret = (message_len >> AES_BLOCK_SIZE_P2) * AES_BLOCK_SIZE;
		}
	}

	memzero (dec_key, sizeof(dec_key));
	memzero (iv, sizeof(iv));
	memzero (&ctx_aes, sizeof(ctx_aes));

	return ret;
}

static int encryptAES256 (unsigned char *key, int key_len, unsigned char *message, int message_len, unsigned char *buffer) {
	int ret = -1;
	int enc_count = 1;

	aes_encrypt_ctx ctx_aes;
	uint8_t iv[AES_BLOCK_SIZE] ={0};
	uint8_t enc_key[SHA3_256_DIGEST_LENGTH] = {0};

	SHA512_CTX ctx_sha;
	unsigned char hashbuf[SHA3_512_DIGEST_LENGTH];

	sha512_Init (&ctx_sha);
	sha512_Update (&ctx_sha, key, (size_t) key_len);
	sha512_Final (&ctx_sha, hashbuf);
	memzero (&ctx_sha, sizeof(ctx_sha));

	memcpy (iv, hashbuf+(enc_count++), AES_BLOCK_SIZE/2);
	memcpy (enc_key, hashbuf+(enc_count++)+(AES_BLOCK_SIZE/2), SHA3_256_DIGEST_LENGTH/2);
	memcpy (iv+(AES_BLOCK_SIZE/2), hashbuf+(enc_count++)+(AES_BLOCK_SIZE/2)+(SHA3_256_DIGEST_LENGTH/2), AES_BLOCK_SIZE/2);
	memcpy (enc_key+(SHA3_256_DIGEST_LENGTH/2), hashbuf+(enc_count+1)+AES_BLOCK_SIZE+(SHA3_256_DIGEST_LENGTH/2), SHA3_256_DIGEST_LENGTH/2);
	memzero (hashbuf, sizeof(hashbuf));

#if 0 //def DEBUG_TRUST_SIGNER
	hex_print (hexbuf, iv, sizeof(iv));
	LOGD("IV : %s\n", hexbuf);
	hex_print (hexbuf, enc_key, sizeof(enc_key));
	LOGD("KEY : %s\n", hexbuf);
#endif

	if (aes_encrypt_key256 (enc_key, &ctx_aes) == EXIT_SUCCESS) {
		if (aes_cbc_encrypt (message, buffer, message_len, iv, &ctx_aes) == EXIT_SUCCESS) {
			ret = (message_len >> AES_BLOCK_SIZE_P2) * AES_BLOCK_SIZE;
#ifdef DEBUG_TRUST_SIGNER
			LOGD("----------------------------- AES ENC --------------------------------\n");
			hex_print (hexbuf, buffer, (size_t) ret);
			LOGD("(%03d) : %s\n", ret, hexbuf);

			int tmp_len = 0;
			unsigned char tmp_buffer[TEMP_BUFFER_LENGTH] = {0};
			tmp_len = decryptAES256 (key, key_len, buffer, ret, tmp_buffer);
			LOGD("----------------------------- AES DEC --------------------------------\n");
			hex_print (hexbuf, tmp_buffer, (size_t) tmp_len);
			LOGD("(%03d) : %s\n", tmp_len, hexbuf);
#endif
		}
	}

	memzero (enc_key, sizeof(enc_key));
	memzero (iv, sizeof(iv));
	memzero (&ctx_aes, sizeof(ctx_aes));

	return ret;
}

static int getCoinType (char *coin) {
	int coinType = 0;
	if (!strncmp (coin, "BTC", 3)) {
		coinType = COIN_TYPE_BITCOIN;
	} else if (!strncmp (coin, "ETH", 3)) {
		coinType = COIN_TYPE_ETHEREUM;
	} else if (!strncmp (coin, "XLM", 3)) {
		coinType = COIN_TYPE_STELLAR;
	}
	return coinType;
}

#if defined(__ANDROID__)
extern "C"
JNIEXPORT jbyteArray JNICALL
Java_io_talken_trustsigner_TrustSigner_getWBInitializeData(JNIEnv *env, jobject instance,
		jstring appID_, jstring filePath_)
#else
#if defined(__FILES__)
unsigned char *TrustSigner_getWBInitializeData(char *app_id, char *file_path)
#else
unsigned char *TrustSigner_getWBInitializeData(char *app_id)
#endif
#endif
{
#if defined(__ANDROID__)
	jbyteArray wb_data = NULL;

    const char *app_id      = env->GetStringUTFChars (appID_, NULL);
	const char *file_path   = env->GetStringUTFChars (filePath_, NULL);
    const int  app_id_len   = env->GetStringUTFLength (appID_);
#else
	unsigned char *wb_data = NULL;
	int app_id_len = (int) strlen (app_id);
#endif

	unsigned char seed[BIP39_KEY_STRENGTH/4] = {0};
	const char *mnemonic = NULL;

	int enc_buf_len = 0;
	unsigned char enc_buffer[AES256_ENCRYPT_LENGTH] = {0};
	int wb_buf_len = 0;
	unsigned char wb_buffer[BIP39_KEY_STRENGTH*2] = {0};

#ifdef DEBUG_TRUST_SIGNER
	int dec_buf_len = 0;
	unsigned char dec_buffer[AES256_ENCRYPT_LENGTH] = {0};
#endif

#if defined(__FILES__)
	char file_name[256] = {0};
	sprintf (file_name, "%s/%s", file_path, PREFERENCE_WB);
#else
	int table_buf_len = 0;
	char *table_buffer = NULL;
#endif

#ifdef DEBUG_TRUST_SIGNER
	LOGD("\n[[[[[ %s ]]]]]\n", __FUNCTION__);
	LOGD("- appId = %s\n", app_id);
#if defined(__FILES__)
	LOGD("- filePath = %s\n", file_path);
#endif
#endif

    if (app_id == NULL) {
        LOGE("Error! Argument data is null!\n");
        return NULL;
    }

#if defined(__WHITEBOX__)
	// WB_TABLE Create /////////////////////////////////////////////////////////////////////////////
#if defined(__FILES__)
	trust_signer_create_table_fp (file_name);
#ifdef DEBUG_TRUST_SIGNER
	LOGD("----------------------------- WB_TABLE -------------------------------\n");
    LOGD("WB Table Create = %s\n", file_name);
#endif
#else
	table_buf_len = trust_signer_create_table (&table_buffer);
	if (table_buf_len <= 0) {
		LOGE("Error! WB create failed!\n");
		return NULL;
	}
#ifdef DEBUG_TRUST_SIGNER
	LOGD("----------------------------- WB_TABLE -------------------------------\n");
	LOGD("WB Table Create = %d\n", table_buf_len);
#endif
#endif
#endif

	// SEED Create /////////////////////////////////////////////////////////////////////////////////
	mnemonic = generateMnemonic (BIP39_KEY_STRENGTH);
#ifdef DEBUG_TRUST_SIGNER
	LOGD("----------------------------- MNEMONIC -------------------------------\n");
	LOGD("(%03d) : %s\n", (int) strlen(mnemonic), mnemonic);
#endif

#ifdef DEBUG_TRUST_SIGNER
	unsigned char entropy[BIP39_KEY_STRENGTH/8] = {0};
	mnemonic_to_entropy (mnemonic, entropy);
	LOGD("----------------------------- ENTROPY --------------------------------\n");
	hex_print (hexbuf, entropy, sizeof(entropy));
	LOGD("(%03ld) : %s\n", sizeof(entropy), hexbuf);
	memzero (entropy, sizeof(entropy));
#endif

	// Mnemonic AES Encrypt /////////////////////////////////////////////////////////////////////
#if defined(__FILES__) // MYSEO : Recovery
	unsigned char org_buffer_r[MNEMONIC_MAX_LENGTH] = {0}; // Fixed
	unsigned char enc_buffer_r[MNEMONIC_MAX_LENGTH] = {0}; // Fixed

	int org_buf_len = (int) (strlen((char *) mnemonic) / AES_BLOCK_SIZE) * AES_BLOCK_SIZE;
	if (strlen((char *) mnemonic) % AES_BLOCK_SIZE) {
		org_buf_len += AES_BLOCK_SIZE;
	}

	char recovery_aes_key[512] = {0};
	sprintf (recovery_aes_key, "%s|T-C-N", app_id);
	memcpy (org_buffer_r, (unsigned char *) mnemonic, strlen((char *) mnemonic));

	enc_buf_len = encryptAES256 ((unsigned char *) recovery_aes_key, (int) strlen(recovery_aes_key), org_buffer_r, org_buf_len, enc_buffer_r);
	memzero (org_buffer_r, sizeof(org_buffer_r));
	if (enc_buf_len <= 0) {
		LOGE("Error! Encrypt failed!\n");
		return NULL;
	}
	memzero (recovery_aes_key, sizeof(recovery_aes_key));

	// Recovery Mnemonic Write ///////////////////////////////////////////////////////////////////
	if (writeRecovery (enc_buffer_r, enc_buf_len, (char *) file_path) != 0) {
		memzero ((void *) mnemonic, strlen((char *) mnemonic));
		memzero (enc_buffer_r, sizeof(enc_buffer_r));
		LOGE("Error! Recovery write failed!\n");
		return NULL;
	}
	memzero (enc_buffer_r, sizeof(enc_buffer_r));
#endif

	generateBip39Seeed (mnemonic, seed, NULL);
	memzero ((void *) mnemonic, strlen((char *) mnemonic));
#ifdef DEBUG_TRUST_SIGNER
	LOGD("----------------------------- SEED -----------------------------------\n");
	hex_print (hexbuf, seed, sizeof(seed));
	LOGD("(%03ld) : %s\n", sizeof(seed), hexbuf);
#endif

#ifdef DEBUG_TRUST_SIGNER
	HDNode node;
	char private_key[BIP32_KEY_LENGTH*2] = {0};
	char public_key[BIP32_KEY_LENGTH*2] = {0};
	memset (&node, 0, sizeof(node));
	hdnode_from_seed (seed, BIP39_KEY_STRENGTH/4, SECP256K1_NAME, &node);
	LOGD("----------------------------- M BTC PRIVATE --------------------------\n");
	hdnode_serialize_private (&node, 0, VERSION_PRIVATE, private_key, sizeof(private_key));
	LOGD("(%03ld) : %s\n", strlen(private_key), private_key);
	hdnode_serialize_public (&node, 0, VERSION_PUBLIC, public_key, sizeof(public_key));
	LOGD("----------------------------- M BTC PUBLIC ---------------------------\n");
	LOGD("(%03ld) : %s\n", strlen(public_key), public_key);
#endif

	// SEED AES Encrypt ////////////////////////////////////////////////////////////////////////////
	enc_buf_len = encryptAES256 ((unsigned char *) app_id, app_id_len, seed, sizeof(seed), enc_buffer);
	memzero (seed, sizeof(seed));
	if (enc_buf_len <= 0) {
		LOGE("Error! Encrypt failed!\n");
		return NULL;
	}

#if defined(__WHITEBOX__)
	// SEED WB Encrypt /////////////////////////////////////////////////////////////////////////////
#if defined(__FILES__)
	wb_buf_len = trust_signer_encrypt_fp (file_name, enc_buffer, enc_buf_len, wb_buffer, true);
#else
	wb_buf_len = trust_signer_encrypt (table_buffer, table_buf_len, enc_buffer, enc_buf_len, wb_buffer, true);
#endif
	memzero (enc_buffer, sizeof(enc_buffer));
	if (wb_buf_len <= 0) {
		LOGE("Error! WB Encrypt failed!\n");
		return NULL;
	}
#ifdef DEBUG_TRUST_SIGNER
	LOGD("----------------------------- WB ENC ---------------------------------\n");
	hex_print (hexbuf, wb_buffer, (size_t) wb_buf_len);
	LOGD("(%03d) : %s\n", wb_buf_len, hexbuf);

#if defined(__FILES__)
	dec_buf_len = trust_signer_encrypt_fp (file_name, wb_buffer, wb_buf_len, dec_buffer, false);
#else
	dec_buf_len = trust_signer_encrypt (table_buffer, table_buf_len, wb_buffer, wb_buf_len, dec_buffer, false);
#endif
	LOGD("----------------------------- WB DEC ---------------------------------\n");
	hex_print (hexbuf, dec_buffer, (size_t) dec_buf_len);
	LOGD("(%03d) : %s\n", dec_buf_len, hexbuf);
#endif
#else
    wb_buf_len = enc_buf_len;
    memcpy (wb_buffer, enc_buffer, enc_buf_len);
#endif

	// DATA Return /////////////////////////////////////////////////////////////////////////////////
#if defined(__ANDROID__)
	wb_data = env->NewByteArray (wb_buf_len + sizeof(wb_buf_len));
	env->SetByteArrayRegion (wb_data, 0, sizeof(wb_buf_len), (jbyte *) &wb_buf_len);
	env->SetByteArrayRegion (wb_data, sizeof(wb_buf_len), wb_buf_len, (jbyte *) wb_buffer);
#else
#if defined(__FILES__)
	wb_data = (unsigned char *) malloc ((size_t) (wb_buf_len + sizeof(wb_buf_len)));
	memcpy (wb_data, &wb_buf_len, sizeof(wb_buf_len));
	memcpy (wb_data + sizeof(wb_buf_len), wb_buffer, wb_buf_len);
#else
	int wb_data_len = sizeof(wb_data_len) + sizeof(table_buf_len) + table_buf_len + wb_buf_len;
	wb_data = (unsigned char *) malloc ((size_t) wb_data_len);
	memcpy (wb_data, &wb_data_len, sizeof(wb_data_len));
	memcpy (wb_data + sizeof(wb_data_len), &table_buf_len, sizeof(table_buf_len));
	memcpy (wb_data + sizeof(wb_data_len) + sizeof(table_buf_len), table_buffer, table_buf_len);
	memcpy (wb_data + sizeof(wb_data_len) + sizeof(table_buf_len) + table_buf_len, wb_buffer, wb_buf_len);

	memzero (table_buffer, sizeof(table_buffer));

	free (table_buffer);
#endif
#endif

	memzero (wb_buffer, sizeof(wb_buffer));

	return (wb_data);
}

#if defined(__ANDROID__)
extern "C"
JNIEXPORT jbyteArray JNICALL
Java_io_talken_trustsigner_TrustSigner_getWBPublicKey(JNIEnv *env, jobject instance,
		jstring appID_, jstring filePath_, jbyteArray wbData_, jstring coinSymbol_,
        jint hdDepth, jint hdChange, jint hdIndex)
#else
#if defined(__FILES__)
char *TrustSigner_getWBPublicKey(char *app_id, char *file_path, unsigned char *wb_data, char *coin_symbol, int hd_depth, int hd_change, int hd_index)
#else
char *TrustSigner_getWBPublicKey(char *app_id, unsigned char *wb_data, char *coin_symbol, int hd_depth, int hd_change, int hd_index)
#endif
#endif
{
#if defined(__ANDROID__)
	jbyteArray public_address = NULL;

    const char *app_id      = env->GetStringUTFChars (appID_, NULL);
    const char *file_path   = env->GetStringUTFChars (filePath_, NULL);
	const char *wb_data     = jbyteArry2char (env, wbData_);
	const char *coin_symbol = env->GetStringUTFChars (coinSymbol_, NULL);
    const int  app_id_len   = env->GetStringUTFLength (appID_);
	const int  hd_depth     = (int) hdDepth;
	const int  hd_change    = (int) hdChange;
	const int  hd_index     = (int) hdIndex;
#else
	char *public_address = NULL;
	int app_id_len = strlen (app_id);
#endif

	HDNode node;
	int coin_type = 0;
	unsigned char seed[BIP39_KEY_STRENGTH/4] = {0};
    int public_key_len = 0;
	char public_key[BIP32_KEY_LENGTH*2] = {0};

	int wb_buf_len = 0;
	unsigned char wb_buffer[BIP39_KEY_STRENGTH*2] = {0};
	int enc_buf_len = 0;
	unsigned char enc_buffer[AES256_ENCRYPT_LENGTH] = {0};
	int dec_buf_len = 0;

	unsigned int finger_print = 0;
	uint32_t bip44_path[BIP44_PATH_DEPTH_MAX] = {0};

#ifdef DEBUG_TRUST_SIGNER
	LOGD("\n[[[[[ %s ]]]]]\n", __FUNCTION__);
#endif

    if (app_id == NULL || wb_data == NULL || coin_symbol == NULL) {
        LOGE("Error! Argument data is null!\n");
        return NULL;
    }
	if (hd_depth < 3) {
		LOGE("Error! Not support!\n");
		return NULL;
	}
    coin_type = getCoinType ((char *) coin_symbol);
    if (coin_type <= 0) {
        LOGE("Error! Not support coin type! (%s)\n", coin_symbol);
        memzero (seed, sizeof(seed));
        return NULL;
    }

#if defined(__WHITEBOX__)
	// SEED WB Decrypt /////////////////////////////////////////////////////////////////////////////
#if defined(__FILES__)
	char file_name[256] = {0};
	sprintf (file_name, "%s/%s", file_path, PREFERENCE_WB);

	memcpy (&wb_buf_len, wb_data, sizeof(wb_buf_len));
	memcpy (wb_buffer, wb_data + sizeof(wb_buf_len), (size_t) wb_buf_len);

	enc_buf_len = trust_signer_encrypt_fp (file_name, wb_buffer, wb_buf_len, enc_buffer, false);
#else
	int wb_data_len = 0;
	int table_buf_len = 0;
	unsigned char *table_buffer = (unsigned char *) (wb_data + sizeof(wb_data_len) + sizeof(table_buf_len));

	memcpy (&wb_data_len, wb_data, sizeof(wb_data_len));
	memcpy (&table_buf_len, wb_data + sizeof(wb_data_len), sizeof(table_buf_len));
	wb_buf_len = wb_data_len - (sizeof(wb_data_len) + sizeof(table_buf_len) + table_buf_len);
	memcpy (wb_buffer, table_buffer + table_buf_len, (size_t) wb_buf_len);

	enc_buf_len = trust_signer_encrypt ((char *) table_buffer, table_buf_len, wb_buffer, wb_buf_len, enc_buffer, false);
#endif
	memzero (wb_buffer, sizeof(wb_buffer));
	if (enc_buf_len <= 0) {
		LOGE("Error! Decrypt failed!\n");
		return NULL;
	}
#else
    memcpy (&enc_buf_len, wb_data, sizeof(enc_buf_len));
    memcpy (enc_buffer, wb_data + sizeof(enc_buf_len), (size_t) enc_buf_len);
#endif

	// SEED AES Decrypt ////////////////////////////////////////////////////////////////////////////
	dec_buf_len = decryptAES256 ((unsigned char *) app_id, app_id_len, enc_buffer, enc_buf_len, seed);
	memzero (enc_buffer, sizeof(enc_buffer));
	if (dec_buf_len <= 0) {
		LOGE("Error! Decrypt failed!\n");
		return NULL;
	}
#ifdef DEBUG_TRUST_SIGNER
	LOGD("----------------------------- SEED -----------------------------------\n");
	hex_print (hexbuf, seed, sizeof(seed));
	LOGD("(%03ld) : %s\n", sizeof(seed), hexbuf);
#endif

	// Create HD Node //////////////////////////////////////////////////////////////////////////////
	memset (&node, 0, sizeof(node));
	switch (coin_type) {
		case COIN_TYPE_BITCOIN:
			bip44_path[BIP44_PATH_PURPOSE]    = BIP44_VAL_PURPOSE | BIP44_VAL_HARDENED;
			bip44_path[BIP44_PATH_COIN_TYPE]  = BIP44_VAL_BITCOIN | BIP44_VAL_HARDENED;
			bip44_path[BIP44_PATH_ACCOUNT]    = 0 | BIP44_VAL_HARDENED;
			bip44_path[BIP44_PATH_CHANGE]     = (uint32_t ) hd_change;
			bip44_path[BIP44_PATH_ADDR_INDEX] = (uint32_t ) hd_index;
			hdnode_from_seed (seed, BIP39_KEY_STRENGTH/4, SECP256K1_NAME, &node);
			break;
		case COIN_TYPE_ETHEREUM:
			bip44_path[BIP44_PATH_PURPOSE]    = BIP44_VAL_PURPOSE | BIP44_VAL_HARDENED;
			bip44_path[BIP44_PATH_COIN_TYPE]  = BIP44_VAL_ETHEREUM | BIP44_VAL_HARDENED;
			bip44_path[BIP44_PATH_ACCOUNT]    = 0 | BIP44_VAL_HARDENED;
			bip44_path[BIP44_PATH_CHANGE]     = (uint32_t ) hd_change;
			bip44_path[BIP44_PATH_ADDR_INDEX] = (uint32_t ) hd_index;
			hdnode_from_seed (seed, BIP39_KEY_STRENGTH/4, SECP256K1_NAME, &node);
			break;
		case COIN_TYPE_STELLAR:
			bip44_path[BIP44_PATH_PURPOSE]    = BIP44_VAL_PURPOSE | BIP44_VAL_HARDENED;
			bip44_path[BIP44_PATH_COIN_TYPE]  = BIP44_VAL_STELLAR | BIP44_VAL_HARDENED;
			bip44_path[BIP44_PATH_ACCOUNT]    = (uint32_t ) hd_index | BIP44_VAL_HARDENED;
			hdnode_from_seed (seed, BIP39_KEY_STRENGTH/4, ED25519_NAME, &node);
			break;
        default:
            break;
	}
	memzero (seed, sizeof(seed));

	finger_print = coin_derive_node (&node, bip44_path, (size_t) hd_depth);
	if (finger_print == 0xFFFFFFFF) {
		LOGE("Error! Decrypt failed!\n");
		memzero (&node, sizeof(node));
		return NULL;
	}

	// Get Public Addreee //////////////////////////////////////////////////////////////////////////
	// check site : https://iancoleman.io/bip39/#english
	switch (coin_type) {
		case COIN_TYPE_BITCOIN: {
			public_key_len = hdnode_serialize_public (&node, finger_print, VERSION_PUBLIC, public_key, sizeof(public_key));
            public_key_len -= 1;
#ifdef DEBUG_TRUST_SIGNER
			LOGD("----------------------------- BTC PUBLIC -----------------------------\n");
			LOGD("(%03d) : %s\n", public_key_len, public_key);
#endif
			break;
		}
		case COIN_TYPE_ETHEREUM: {
			public_key_len = hdnode_serialize_public (&node, finger_print, VERSION_PUBLIC, public_key, sizeof(public_key));
            public_key_len -= 1;
#ifdef DEBUG_TRUST_SIGNER
			LOGD("----------------------------- ETH PUBLIC -----------------------------\n");
			LOGD("(%03d) : %s\n", public_key_len, public_key);
#endif
			break;
		}
#if 0 // ETH Address
		{
			uint32_t chain_id = 3;
			uint8_t address[ETHEREUM_ADDRESS_LENGTH] = {0};
			if (!hdnode_get_ethereum_pubkeyhash(&node, address)) {
				LOGE("Error! Address check fail!\n");
			}
			public_key[0] = '0';
			public_key[1] = 'x';
			ethereum_address_checksum (address, public_key + 2, false, chain_id);
#ifdef DEBUG_TRUST_SIGNER
			LOGD("----------------------------- ETH PUBLIC -----------------------------\n");
			LOGD("(%03d) : %s\n", strlen(public_key), public_key);
#endif
			break;
		}
#endif
		case COIN_TYPE_STELLAR: {
			public_key_len = (int) stellar_publicAddressAsStr (node.public_key + 1, public_key, sizeof(public_key));
#ifdef DEBUG_TRUST_SIGNER
			LOGD("----------------------------- XLM PUBLIC -----------------------------\n");
			LOGD("(%03d) : %s\n", public_key_len, public_key);
#endif
			break;
		}
        default:
            break;
	}
	memzero (&node, sizeof(node));

#if defined(__ANDROID__)
	public_address = char2JbyteArry (env, public_key, (int) public_key_len);
#else
	public_address = (char *) malloc ((size_t) public_key_len + 1);
    memset (public_address, 0, public_key_len + 1);
	memcpy (public_address, public_key, public_key_len);
#endif

	return (public_address);
}

#if defined(__ANDROID__)
extern "C"
JNIEXPORT jbyteArray JNICALL
Java_io_talken_trustsigner_TrustSigner_getWBSignatureData(JNIEnv *env, jobject instance,
		jstring appID_, jstring filePath_, jbyteArray wbData_, jstring coinSymbol_,
        jint hdDepth, jint hdChange, jint hdIndex,
        jbyteArray hashMessage_)
#else
#if defined(__FILES__)
extern "C"
unsigned char *TrustSigner_getWBSignatureData(char *app_id, char *file_path, unsigned char *wb_data, char *coin_symbol, int hd_depth, int hd_change, int hd_index, unsigned char *hash_message, int hash_len)
#else
extern "C"
unsigned char *TrustSigner_getWBSignatureData(char *app_id, unsigned char *wb_data, char *coin_symbol, int hd_depth, int hd_change, int hd_index, unsigned char *hash_message, int hash_len)
#endif
#endif
{
#if defined(__ANDROID__)
	jbyteArray signature = NULL;

    const char *app_id       = env->GetStringUTFChars (appID_, NULL);
    const char *file_path    = env->GetStringUTFChars (filePath_, NULL);
    const char *wb_data      = jbyteArry2char (env, wbData_);
    const char *coin_symbol  = env->GetStringUTFChars (coinSymbol_, NULL);
    const int  app_id_len    = env->GetStringUTFLength (appID_);
	const int  hd_depth      = (int) hdDepth;
	const int  hd_change     = (int) hdChange;
	const int  hd_index      = (int) hdIndex;
	const char *hash_message = jbyteArry2char (env, hashMessage_);
	const int  hash_len      = env->GetArrayLength (hashMessage_);
#else
	unsigned char *signature = NULL;
	int app_id_len = strlen (app_id);
#endif

	HDNode node;
	int coin_type = 0;
	unsigned char seed[BIP39_KEY_STRENGTH/4] = {0};
	unsigned char sign_message[SIGN_SIGNATURE_MAX_LENGTH] = {0};

	int wb_buf_len = 0;
	unsigned char wb_buffer[BIP39_KEY_STRENGTH*2] = {0};
	int enc_buf_len = 0;
	unsigned char enc_buffer[AES256_ENCRYPT_LENGTH] = {0};

	int hash_sum = 0;
	int sign_len = 0;
    unsigned int finger_print = 0;
	uint32_t bip44_path[BIP44_PATH_DEPTH_MAX] = {0};

#ifdef DEBUG_TRUST_SIGNER
	LOGD("\n[[[[[ %s ]]]]]\n", __FUNCTION__);
#endif

    if (app_id == NULL || wb_data == NULL || coin_symbol == NULL) {
        LOGE("Error! Argument data is null!\n");
        return NULL;
    }
	if (hd_depth < 3) {
		LOGE("Error! Not support!\n");
		return NULL;
	}
	coin_type = getCoinType ((char *) coin_symbol);
	if (coin_type <= 0) {
		LOGE("Error! Not support coin type! (%s)\n", coin_symbol);
		return NULL;
	}
	if (coin_type == COIN_TYPE_BITCOIN) {
		hash_sum = hash_len / SIGN_HASH_LENGTH;
		if (hash_sum > SIGN_SIGNATURE_MAX) {
			LOGE("Error! Hash length is incorrect!\n");
			return NULL;
		}
	} else if (coin_type == COIN_TYPE_ETHEREUM || coin_type == COIN_TYPE_STELLAR) {
		hash_sum = 1;
		if (hash_len > SIGN_HASH_LENGTH) {
			LOGE("Error! Hash length is incorrect!\n");
			return NULL;
		}
	}

#if defined(__WHITEBOX__)
	// SEED WB Decrypt /////////////////////////////////////////////////////////////////////////////
#if defined(__FILES__)
	char file_name[256] = {0};
	sprintf (file_name, "%s/%s", file_path, PREFERENCE_WB);
#if 1 // MYSEO : move to get public key function
	char rfile_name[256] = {0};
	sprintf (rfile_name, "%s/%s", file_path, RECOVERY_WB);
	if (access (rfile_name, F_OK) != -1) {
		//unlink (rfile_name);
		LOGE("Error! Approached by an abnormal path.\n");
		return NULL;
	}
#endif

	memcpy (&wb_buf_len, wb_data, sizeof(wb_buf_len));
	memcpy (wb_buffer, wb_data + sizeof(wb_buf_len), (size_t) wb_buf_len);;

	enc_buf_len = trust_signer_encrypt_fp (file_name, wb_buffer, wb_buf_len, enc_buffer, false);
#else
	int wb_data_len = 0;
	int table_buf_len = 0;
    unsigned char *table_buffer = (unsigned char *) (wb_data + sizeof(wb_data_len) + sizeof(table_buf_len));

    memcpy (&wb_data_len, wb_data, sizeof(wb_data_len));
    memcpy (&table_buf_len, wb_data + sizeof(wb_data_len), sizeof(table_buf_len));
    wb_buf_len = wb_data_len - (sizeof(wb_data_len) + sizeof(table_buf_len) + table_buf_len);
    memcpy (wb_buffer, table_buffer + table_buf_len, (size_t) wb_buf_len);

	enc_buf_len = trust_signer_encrypt ((char *) table_buffer, table_buf_len, wb_buffer, wb_buf_len, enc_buffer, false);
#endif
	memzero (wb_buffer, sizeof(wb_buffer));
	if (enc_buf_len <= 0) {
		LOGE("Error! Decrypt failed!\n");
		return NULL;
	}
#else
    memcpy (&enc_buf_len, wb_data, sizeof(enc_buf_len));
    memcpy (enc_buffer, wb_data + sizeof(enc_buf_len), (size_t) enc_buf_len);
#endif

	// SEED AES Decrypt ////////////////////////////////////////////////////////////////////////////
	enc_buf_len = decryptAES256 ((unsigned char *) app_id, app_id_len, enc_buffer, enc_buf_len, seed);
	memzero (enc_buffer, sizeof(enc_buffer));
	if (enc_buf_len <= 0) {
		LOGE("Error! Decrypt failed!\n");
		return NULL;
	}
#ifdef DEBUG_TRUST_SIGNER
	LOGD("- hash_sum = %d\n", hash_sum);
	LOGD("----------------------------- SEED -----------------------------------\n");
	hex_print (hexbuf, seed, sizeof(seed));
	LOGD("(%03ld) : %s\n", sizeof(seed), hexbuf);
#endif

	// Create HD Node //////////////////////////////////////////////////////////////////////////////
	memset (&node, 0, sizeof(node));
	switch (coin_type) {
		case COIN_TYPE_BITCOIN:
			bip44_path[BIP44_PATH_PURPOSE]    = BIP44_VAL_PURPOSE | BIP44_VAL_HARDENED;
			bip44_path[BIP44_PATH_COIN_TYPE]  = BIP44_VAL_BITCOIN | BIP44_VAL_HARDENED;
			bip44_path[BIP44_PATH_ACCOUNT]    = 0 | BIP44_VAL_HARDENED;
			bip44_path[BIP44_PATH_CHANGE]     = (uint32_t) hd_change;
			bip44_path[BIP44_PATH_ADDR_INDEX] = (uint32_t) hd_index;
			hdnode_from_seed (seed, BIP39_KEY_STRENGTH/4, SECP256K1_NAME, &node);
			break;
		case COIN_TYPE_ETHEREUM:
			bip44_path[BIP44_PATH_PURPOSE]    = BIP44_VAL_PURPOSE | BIP44_VAL_HARDENED;
			bip44_path[BIP44_PATH_COIN_TYPE]  = BIP44_VAL_ETHEREUM | BIP44_VAL_HARDENED;
			bip44_path[BIP44_PATH_ACCOUNT]    = 0 | BIP44_VAL_HARDENED;
			bip44_path[BIP44_PATH_CHANGE]     = (uint32_t) hd_change;
			bip44_path[BIP44_PATH_ADDR_INDEX] = (uint32_t) hd_index;
			hdnode_from_seed (seed, BIP39_KEY_STRENGTH/4, SECP256K1_NAME, &node);
			break;
		case COIN_TYPE_STELLAR:
			bip44_path[BIP44_PATH_PURPOSE]    = BIP44_VAL_PURPOSE | BIP44_VAL_HARDENED;
			bip44_path[BIP44_PATH_COIN_TYPE]  = BIP44_VAL_STELLAR | BIP44_VAL_HARDENED;
			bip44_path[BIP44_PATH_ACCOUNT]    = hd_index | BIP44_VAL_HARDENED;
			hdnode_from_seed (seed, BIP39_KEY_STRENGTH/4, ED25519_NAME, &node);
			break;
        default:
            break;
	}
	memzero (seed, sizeof(seed));

	finger_print = coin_derive_node (&node, bip44_path, (size_t) hd_depth);
	if (finger_print == 0xFFFFFFFF) {
		LOGE("Error! Decrypt failed!\n");
		memzero (&node, sizeof(node));
		return NULL;
	}

	// Create Signature ////////////////////////////////////////////////////////////////////////////
	memset (sign_message, 0, SIGN_SIGNATURE_MAX_LENGTH);
	switch (coin_type) {
		case COIN_TYPE_BITCOIN: {
			for (int i=0; i<hash_sum; i++) {
				bitcoin_hash_sign (&node, (uint8_t *) hash_message+(i*SIGN_HASH_LENGTH), sign_message+sign_len);
#ifdef DEBUG_TRUST_SIGNER
				LOGD("----------------------------- SIGNATURE BTC --------------------------\n");
				hex_print (hexbuf, (unsigned char *) hash_message+(i*SIGN_HASH_LENGTH), SIGN_HASH_LENGTH);
				LOGD("HashMessage[%d] : %s\n", i, hexbuf);
				hex_print (hexbuf, sign_message+sign_len, SIGN_SIGNATURE_LENGTH+1);
				LOGD("Signature[%d] : %s\n", i, hexbuf);
#endif
				sign_len += SIGN_SIGNATURE_LENGTH;
				sign_len += 1; // value v
			}
			break;
		}
		case COIN_TYPE_ETHEREUM: {
			ethereum_hash_sign(&node, (uint8_t *) hash_message, sign_message);
			sign_len = SIGN_SIGNATURE_LENGTH;
			sign_len += 1; // value v
#ifdef DEBUG_TRUST_SIGNER
			LOGD("----------------------------- SIGNATURE ETH --------------------------\n");
			hex_print (hexbuf, (unsigned char *) hash_message, hash_len);
			LOGD("HashMessage : %s\n", hexbuf);
			hex_print (hexbuf, sign_message, sign_len);
			LOGD("Signature : %s\n", hexbuf);
#endif
			 break;
		 }
		case COIN_TYPE_STELLAR: {
			if (hash_len < SIGN_HASH_LENGTH) {
                stellar_message_sign(&node, (uint8_t *) hash_message, (uint32_t) hash_len, sign_message);
			} else {
				stellar_hash_sign(&node, (uint8_t *) hash_message, sign_message);
			}
			sign_len = SIGN_SIGNATURE_LENGTH;
#ifdef DEBUG_TRUST_SIGNER
			LOGD("----------------------------- SIGNATURE XLM --------------------------\n");
			hex_print (hexbuf, (unsigned char *) hash_message, hash_len);
			LOGD("HashMessage : %s\n", hexbuf);
			hex_print (hexbuf, sign_message, (size_t) sign_len);
			LOGD("Signature : %s\n", hexbuf);
#endif
			break;
		}
		default:
		    break;
	}
	memzero(&node, sizeof(node));

#if defined(__ANDROID__)
	signature = uchar2JbyteArry (env, sign_message, sign_len);
#else
#if defined(__FILES__)
	signature = (unsigned char *) malloc ((size_t) (sign_len + sizeof(sign_len)));
	memcpy (signature, &sign_len, sizeof(sign_len));
	memcpy (signature + sizeof(sign_len), sign_message, sign_len);
#else
	signature = (unsigned char *) malloc (sign_len);
	memcpy (signature, sign_message, sign_len);
#endif
#endif

	return (signature);
}

// MYSEO : userKey, serverKey is sha(512) hash data need
#if defined(__ANDROID__)
extern "C"
JNIEXPORT jbyteArray JNICALL
Java_io_talken_trustsigner_TrustSigner_getWBRecoveryData(JNIEnv *env, jobject instance,
		jstring appID_, jstring filePath_, jbyteArray wbData_, jstring userKey_, jstring serverKey_)
#else
#if defined(__FILES__)
char *TrustSigner_getWBRecoveryData(char *app_id, char *file_path, char *user_key, char *server_key)
#else
char *TrustSigner_getWBRecoveryData(char *app_id, unsigned char *wb_data, char *user_key, char *server_key)
#endif
#endif
{
#if defined(__ANDROID__)
	jbyteArray recovery_data = NULL;

    const char *app_id        = env->GetStringUTFChars (appID_, NULL);
    const char *file_path     = env->GetStringUTFChars (filePath_, NULL);
    const char *wb_data      = jbyteArry2char (env, wbData_);
    const char *user_key      = env->GetStringUTFChars (userKey_, NULL);
    const char *server_key    = env->GetStringUTFChars (serverKey_, NULL);
    const int  app_id_len   = env->GetStringUTFLength (appID_);
    const int  user_key_len   = env->GetStringUTFLength (userKey_);
    const int  server_key_len = env->GetStringUTFLength (serverKey_);
#else
	char *recovery_data = NULL;

	int app_id_len = strlen (app_id);
	int user_key_len = strlen (user_key);
	int server_key_len = strlen (server_key);
#endif

	int enc_buf_len = 0;
	unsigned char enc_buffer[RECOVERY_BUFFER_LENGTH] = {0};

	int base64_buf_len = 0;
	uint8_t iv_random[AES256_IV_LENGTH] = {0};
	uint8_t nonce[RANDOM_NONCE_LENGTH] = {0};
	char base64_recovery_iv[RECOVERY_BUFFER_LENGTH] = {0};

#if defined(__FILES__)
	int dec_buf_len = 0;
	unsigned char dec_buffer[RECOVERY_BUFFER_LENGTH] = {0};

	char file_name[256] = {0};
	sprintf (file_name, "%s/%s", file_path, PREFERENCE_WB);
#else
	int wb_buf_len = 0;
	unsigned char wb_buffer[RECOVERY_BUFFER_LENGTH] = {0};

	unsigned char seed[BIP39_KEY_STRENGTH/4] = {0};
#endif

#ifdef DEBUG_TRUST_SIGNER
	LOGD("\n[[[[[ %s ]]]]]\n", __FUNCTION__);
#endif

    if (app_id == NULL || user_key == NULL || server_key == NULL) {
        LOGE("Error! Argument data is null!\n");
        return NULL;
    }

	random_buffer (iv_random, sizeof(iv_random));
	base64_encode_binary (base64_recovery_iv, iv_random, sizeof(iv_random));

#if defined(__FILES__)
	enc_buf_len = readRecovery (enc_buffer, (char *) file_path);
	if (enc_buf_len <= 0) {
		LOGE("Error! Recovery read failed!\n");
		return NULL;
	}
#if 0 // MYSEO : move to get public key function
	char rfile_name[256] = {0};
	sprintf (rfile_name, "%s/%s", file_path, RECOVERY_WB);
	if (access (rfile_name, F_OK) != -1) {
		unlink (rfile_name);
	}
#endif

	// RECOVERY AES Decrypt ////////////////////////////////////////////////////////////////////////////
	char recovery_aes_key[512] = {0};
	sprintf (recovery_aes_key, "%s|T-C-N", app_id);
	dec_buf_len = decryptAES256 ((unsigned char *) recovery_aes_key, (int) strlen(recovery_aes_key), enc_buffer, enc_buf_len, dec_buffer);
	memzero (enc_buffer, sizeof(enc_buffer));
	if (dec_buf_len <= 0) {
		LOGE("Error! Decrypt failed!\n");
		return NULL;
	}
	memzero (recovery_aes_key, sizeof(recovery_aes_key));
#ifdef DEBUG_TRUST_SIGNER
	LOGD("----------------------------- RECOVERY WB DEC ------------------------\n");
	LOGD("%s\n", dec_buffer);
#endif
#else
	int wb_data_len = 0;
	int table_buf_len = 0;
    unsigned char *table_buffer = (unsigned char *) (wb_data + sizeof(wb_data_len) + sizeof(table_buf_len));

    memcpy (&wb_data_len, wb_data, sizeof(wb_data_len));
    memcpy (&table_buf_len, wb_data + sizeof(wb_data_len), sizeof(table_buf_len));
    wb_buf_len = wb_data_len - (sizeof(wb_data_len) + sizeof(table_buf_len) + table_buf_len);
    memcpy (wb_buffer, table_buffer + table_buf_len, (size_t) wb_buf_len);

	// SEED WB Decrypt /////////////////////////////////////////////////////////////////////////////
	enc_buf_len = trust_signer_encrypt ((char *) table_buffer, table_buf_len, wb_buffer, wb_buf_len, enc_buffer, false);
	memzero (wb_buffer, sizeof(wb_buffer));
	if (enc_buf_len <= 0) {
		LOGE("Error! Decrypt failed!\n");
		return NULL;
	}

	// SEED AES Decrypt ////////////////////////////////////////////////////////////////////////////
	enc_buf_len = decryptAES256 ((unsigned char *) app_id, app_id_len, enc_buffer, enc_buf_len, seed);
	memzero (enc_buffer, sizeof(enc_buffer));
	if (enc_buf_len <= 0) {
		LOGE("Error! Decrypt failed!\n");
		return NULL;
	}
#ifdef DEBUG_TRUST_SIGNER
	LOGD("----------------------------- SEED -----------------------------------\n");
	hex_print (hexbuf, seed, sizeof(seed));
	LOGD("(%03ld) : %s\n", sizeof(seed), hexbuf);
#endif

	random_buffer (nonce, RANDOM_NONCE_LENGTH);

	unsigned char org_recovery[BIP39_KEY_STRENGTH/4+RANDOM_NONCE_LENGTH] = {0};
	memcpy (org_recovery, nonce, RANDOM_NONCE_LENGTH/2);
	memcpy (org_recovery+RANDOM_NONCE_LENGTH/2, seed, sizeof(seed));
	memcpy (org_recovery+RANDOM_NONCE_LENGTH/2+BIP39_KEY_STRENGTH/4, nonce+RANDOM_NONCE_LENGTH/2, RANDOM_NONCE_LENGTH/2);
#ifdef DEBUG_TRUST_SIGNER
	LOGD("----------------------------- ORG RECOVERY ---------------------------\n");
	hex_print (hexbuf, org_recovery, sizeof(org_recovery));
	LOGD("(%03ld) : %s\n", sizeof(org_recovery), hexbuf);
#endif

	memzero (seed, sizeof(seed));
	memzero (nonce, sizeof(nonce));
#endif

	// SEED AES User Key Encrypt ////////////////////////////////////////////////////////////////////////////
#if defined(__FILES__)
	enc_buf_len = encryptAES256 ((unsigned char *) user_key, user_key_len, dec_buffer, dec_buf_len, enc_buffer);
	memzero (dec_buffer, sizeof(dec_buffer));
#else
	enc_buf_len = encryptAES256 ((unsigned char *) user_key, user_key_len, org_recovery, sizeof(org_recovery), enc_buffer);
	memzero (org_recovery, sizeof(org_recovery));
#endif
	if (enc_buf_len <= 0) {
		LOGE("Error! Encrypt failed! 1\n");
		return NULL;
	}

	char base64_recovery[RECOVERY_BUFFER_LENGTH] = {0};
	base64_encode_binary (base64_recovery, enc_buffer, (size_t) enc_buf_len);
	memzero (enc_buffer, sizeof(enc_buffer));
#ifdef DEBUG_TRUST_SIGNER
	LOGD("----------------------------- BASE64 ENCODE --------------------------\n");
	LOGD("(%03ld) : %s\n", strlen(base64_recovery), base64_recovery);

	unsigned char base64_recovery_de[RECOVERY_BUFFER_LENGTH] = {0};
	base64_buf_len = base64_decode_binary (base64_recovery_de, base64_recovery);
	LOGD("----------------------------- BASE64 DECODE --------------------------\n");
	hex_print (hexbuf, base64_recovery_de, (size_t) base64_buf_len);
	LOGD("(%03d) : %s\n", base64_buf_len, hexbuf);
#endif

	char base64_userkey_iv[RECOVERY_BUFFER_LENGTH] = {0};
	random_buffer (iv_random, sizeof(iv_random));
	base64_encode_binary (base64_userkey_iv, iv_random, sizeof(iv_random));

#ifdef DEBUG_TRUST_SIGNER
	LOGD("----------------------------- USER KEY -------------------------------\n");
    LOGD("(%03ld) : %s\n", strlen(user_key), user_key);
#endif

    int org_userkey_len = user_key_len + RANDOM_NONCE_LENGTH;
	unsigned char org_userkey[TEMP_BUFFER_LENGTH] = {0};
	random_buffer (nonce, RANDOM_NONCE_LENGTH);
	memcpy (org_userkey, nonce, RANDOM_NONCE_LENGTH/2);
	memcpy (org_userkey+RANDOM_NONCE_LENGTH/2, (unsigned char *) user_key, (size_t) user_key_len);
	memcpy (org_userkey+RANDOM_NONCE_LENGTH/2+user_key_len, nonce+RANDOM_NONCE_LENGTH/2, RANDOM_NONCE_LENGTH/2);
	memzero (nonce, sizeof(nonce));

#ifdef DEBUG_TRUST_SIGNER
	LOGD("----------------------------- USER KEY ENC ---------------------------\n");
	hex_print (hexbuf, org_userkey, org_userkey_len);
	LOGD("(%03d) : %s\n", org_userkey_len, hexbuf);
#endif

	// User Key AES Server Key Encrypt ////////////////////////////////////////////////////////////////////////////
    unsigned char key_buffer[TEMP_BUFFER_LENGTH] = {0};
    int key_buf_len = (int) (org_userkey_len / AES_BLOCK_SIZE) * AES_BLOCK_SIZE;
    if (org_userkey_len % AES_BLOCK_SIZE) {
        key_buf_len += AES_BLOCK_SIZE;
    }
    memcpy (key_buffer, org_userkey, org_userkey_len);
    
	enc_buf_len = encryptAES256 ((unsigned char *) server_key, server_key_len, key_buffer, key_buf_len, enc_buffer);
	memzero (org_userkey, sizeof(org_userkey));
	if (enc_buf_len <= 0) {
		LOGE("Error! Encrypt failed! 2\n");
		return NULL;
	}

	char base64_userkey[RECOVERY_BUFFER_LENGTH] = {0};
	base64_encode_binary (base64_userkey, enc_buffer, (size_t) enc_buf_len);
	memzero (enc_buffer, sizeof(enc_buffer));

#ifdef DEBUG_TRUST_SIGNER
	LOGD("----------------------------- BASE64 ENCODE --------------------------\n");
	LOGD("(%03ld) : %s\n", strlen(base64_userkey), base64_userkey);

	unsigned char base64_userkey_de[RECOVERY_BUFFER_LENGTH] = {0};
	base64_buf_len = base64_decode_binary (base64_userkey_de, base64_userkey);
	LOGD("----------------------------- BASE64 DECODE --------------------------\n");
	hex_print (hexbuf, base64_userkey_de, (size_t) base64_buf_len);
	LOGD("(%03d) : %s\n", base64_buf_len, hexbuf);

	enc_buf_len = decryptAES256 ((unsigned char *) server_key, server_key_len, base64_userkey_de, base64_buf_len, enc_buffer);
	LOGD("----------------------------- DEC USER KEY ---------------------------\n");
	memset (org_userkey, 0, sizeof(org_userkey));
	memcpy (org_userkey, enc_buffer + (RANDOM_NONCE_LENGTH/2), user_key_len);
    LOGD("(%03ld) : %s\n", strlen((char *) org_userkey), (char *) org_userkey);
#endif

	char recovery_buffer[RECOVERY_BUFFER_LENGTH] = {0};
	sprintf (recovery_buffer, "[{\"iv\":\"%s\",\"v\":1,\"iter\":1,\"ks\":256,\"ts\":64,\"mode\":\"ccm\",\"adata\":\"\",\"cipher\":\"aes\",\"ct\":\"%s\"},{\"iv\":\"%s\",\"v\":1,\"iter\":1,\"ks\":256,\"ts\":64,\"mode\":\"ccm\",\"adata\":\"\",\"cipher\":\"aes\",\"ct\":\"%s\"}]", base64_recovery_iv, base64_recovery, base64_userkey_iv, base64_userkey);
#ifdef DEBUG_TRUST_SIGNER
	LOGD("----------------------------- RECOVERY DATA --------------------------\n");
	LOGD("(%03ld) : %s\n", strlen(recovery_buffer), recovery_buffer);
#endif

	memzero (base64_recovery, sizeof(base64_recovery));
	memzero (base64_recovery_iv, sizeof(base64_recovery_iv));

	memzero (base64_userkey, sizeof(base64_userkey));
	memzero (base64_userkey_iv, sizeof(base64_userkey_iv));

#if defined(__ANDROID__)
	recovery_data = char2JbyteArry (env, recovery_buffer, (int) strlen (recovery_buffer));
#else
	recovery_data = (char *) malloc ((size_t) strlen (recovery_buffer) + 1);
    memset (recovery_data, 0, strlen (recovery_buffer) + 1);
	memcpy (recovery_data, recovery_buffer, strlen (recovery_buffer));
#endif

	memzero (recovery_buffer, sizeof(recovery_buffer));

    return (recovery_data);
}

#if defined(__FILES__)
#if defined(__ANDROID__)
extern "C"
JNIEXPORT jboolean JNICALL
Java_io_talken_trustsigner_TrustSigner_finishWBRecoveryData(JNIEnv *env, jobject instance,
                                                            jstring appID_, jstring filePath_)
#else
bool TrustSigner_finishWBRecoveryData(char *app_id, char *file_path)
#endif
{
#if defined(__ANDROID__)
	const char *app_id    = env->GetStringUTFChars (appID_, NULL);
	const char *file_path = env->GetStringUTFChars (filePath_, NULL);
#endif

#ifdef DEBUG_TRUST_SIGNER
	LOGD("\n[[[[[ %s ]]]]]\n", __FUNCTION__);
#endif

	if (app_id == NULL) {
		LOGE("Error! Argument data is null!\n");
		return false;
	}

	char rfile_name[256] = {0};
	sprintf (rfile_name, "%s/%s", file_path, RECOVERY_WB);
	if (access (rfile_name, F_OK) != -1) {
		unlink (rfile_name);
		LOGD("Recovery finish is TRUE!\n");
		return true;
	}

	LOGE("Recovery finish is FALSE!\n");
	return false;
}
#endif

#if defined(__ANDROID__)
extern "C"
JNIEXPORT jbyteArray JNICALL
Java_io_talken_trustsigner_TrustSigner_setWBRecoveryData(JNIEnv *env, jobject instance,
		jstring appID_, jstring filePath_, jstring userKey_, jstring recoveryData_)
#else
#if defined(__FILES__)
unsigned char *TrustSigner_setWBRecoveryData(char *app_id, char *file_path, char *user_key, char *recovery_data)
#else
unsigned char *TrustSigner_setWBRecoveryData(char *app_id, char *user_key, char *recovery_data)
#endif
#endif
{
#if defined(__ANDROID__)
	jbyteArray wb_data = NULL;

    const char *app_id           = env->GetStringUTFChars (appID_, NULL);
	const char *file_path        = env->GetStringUTFChars (filePath_, NULL);
    const char *user_key         = env->GetStringUTFChars (userKey_, NULL);
    const char *recovery_data    = env->GetStringUTFChars (recoveryData_, NULL);
    const int  app_id_len        = env->GetStringUTFLength (appID_);
    const int  user_key_len      = env->GetStringUTFLength (userKey_);
#else
	unsigned char *wb_data = NULL;

	int app_id_len = strlen (app_id);
	int user_key_len = strlen (user_key);
#endif

	int wb_buf_len = 0;
	unsigned char wb_buffer[RECOVERY_BUFFER_LENGTH] = {0};
	int enc_buf_len = 0;
	unsigned char enc_buffer[RECOVERY_BUFFER_LENGTH] = {0};
	int dec_buf_len = 0;
	unsigned char dec_buffer[RECOVERY_BUFFER_LENGTH] = {0};

	unsigned char seed[BIP39_KEY_STRENGTH/4] = {0};

	int base64_buf_len = 0;
	char base64_recovery[RECOVERY_BUFFER_LENGTH] = {0};
	unsigned char base64_recovery_de[RECOVERY_BUFFER_LENGTH] = {0};

    int recovery_length = 0;
	char *recovery_start = NULL;
	char *recovery_end = NULL;

#if defined(__FILES__)
	char file_name[256] = {0};
	sprintf (file_name, "%s/%s", file_path, PREFERENCE_WB);
#else
	int table_buf_len = 0;
	char *table_buffer = NULL;
#endif

#ifdef DEBUG_TRUST_SIGNER
	LOGD("\n[[[[[ %s ]]]]]\n", __FUNCTION__);
	LOGD("- appId = %s\n", app_id);
#if defined(__FILES__)
	LOGD("- filePath = %s\n", file_path);
#endif
#endif

    if (app_id == NULL || user_key == NULL || recovery_data == NULL) {
        LOGE("Error! Argument data is null!\n");
        return NULL;
    }

    recovery_start = (char *) strstr (recovery_data, "ct\":\"");
	recovery_start += 5;
    recovery_end = (char *) strstr (recovery_start, "\"");
	recovery_length = (int) (recovery_end - recovery_start);
	strncpy (base64_recovery, recovery_start, (size_t) recovery_length);
#ifdef DEBUG_TRUST_SIGNER
	LOGD("----------------------------- BASE64 ENCODE --------------------------\n");
	LOGD("(%03ld) : %s\n", strlen(base64_recovery), base64_recovery);
#endif

	base64_buf_len = base64_decode_binary (base64_recovery_de, base64_recovery);
	memzero (base64_recovery, sizeof(base64_recovery));
#ifdef DEBUG_TRUST_SIGNER
	LOGD("----------------------------- BASE64 DECODE --------------------------\n");
	hex_print (hexbuf, base64_recovery_de, (size_t) base64_buf_len);
	LOGD("(%03d) : %s\n", base64_buf_len, hexbuf);
#endif

	dec_buf_len = decryptAES256 ((unsigned char *) user_key, user_key_len, base64_recovery_de, base64_buf_len, dec_buffer);
	memzero (base64_recovery_de, sizeof(base64_recovery_de));
	if (dec_buf_len <= 0) {
		LOGE("Error! Decrypt failed!\n");
		return NULL;
	}
#ifdef DEBUG_TRUST_SIGNER
	LOGD("----------------------------- AES DEC --------------------------------\n");
#if defined(__FILES__)
	LOGD("(%03d) : %s\n", dec_buf_len, dec_buffer);
#else
	hex_print (hexbuf, dec_buffer, (size_t) dec_buf_len);
	LOGD("(%03d) : %s\n", dec_buf_len, hexbuf);
#endif
#endif

#if defined(__FILES__)
    for (int i=0; i<(int) strlen((char *) dec_buffer); i++) {
        if (!(dec_buffer[i] == ' ' || (dec_buffer[i] >= 'a' && dec_buffer[i] <= 'z'))) {
			memzero (dec_buffer, sizeof(dec_buffer));
			LOGE("Error! Decrypt failed! (%d, %c, %d)\n", i, dec_buffer[i], dec_buffer[i]);
			return NULL;
        }
    }
#endif

#if defined(__WHITEBOX__)
	// WB_TABLE Create /////////////////////////////////////////////////////////////////////////////
#if defined(__FILES__)
	trust_signer_create_table_fp (file_name);
#ifdef DEBUG_TRUST_SIGNER
	LOGD("----------------------------- WB_TABLE -------------------------------\n");
	LOGD("WB Table Create = %s\n", file_name);
#endif
#else
	table_buf_len = trust_signer_create_table (&table_buffer);
	if (table_buf_len <= 0) {
		LOGE("Error! WB create failed!\n");
		return NULL;
	}
#ifdef DEBUG_TRUST_SIGNER
	LOGD("----------------------------- WB_TABLE -------------------------------\n");
	LOGD("WB Table Create = %d\n", table_buf_len);
#endif
#endif
#endif

#if defined(__FILES__)
	generateBip39Seeed ((char *) dec_buffer, seed, NULL);
#else
	memcpy (seed, dec_buffer+RANDOM_NONCE_LENGTH/2, sizeof(seed));
#endif
	memzero (dec_buffer, sizeof(dec_buffer));
#ifdef DEBUG_TRUST_SIGNER
	LOGD("----------------------------- SEED -----------------------------------\n");
	hex_print (hexbuf, seed, sizeof(seed));
	LOGD("(%03ld) : %s\n", sizeof(seed), hexbuf);
#endif

	// SEED AES Encrypt ////////////////////////////////////////////////////////////////////////////
	enc_buf_len = encryptAES256 ((unsigned char *) app_id, app_id_len, seed, sizeof(seed), enc_buffer);
	memzero (seed, sizeof(seed));
	if (enc_buf_len <= 0) {
		LOGE("Error! Encrypt failed!\n");
		return NULL;
	}

#if defined(__WHITEBOX__)
	// SEED WB Encrypt /////////////////////////////////////////////////////////////////////////////
#if defined(__FILES__)
	wb_buf_len = trust_signer_encrypt_fp (file_name, enc_buffer, enc_buf_len, wb_buffer, true);
#else
	wb_buf_len = trust_signer_encrypt (table_buffer, table_buf_len, enc_buffer, enc_buf_len, wb_buffer, true);
#endif
	memzero (enc_buffer, sizeof(enc_buffer));
	if (wb_buf_len <= 0) {
		LOGE("Error! WB Encrypt failed!\n");
		return NULL;
	}
#ifdef DEBUG_TRUST_SIGNER
	LOGD("----------------------------- WB ENC ---------------------------------\n");
	hex_print (hexbuf, wb_buffer, (size_t) wb_buf_len);
	LOGD("(%03d) : %s\n", wb_buf_len, hexbuf);

#if defined(__FILES__)
	dec_buf_len = trust_signer_encrypt_fp (file_name, wb_buffer, wb_buf_len, dec_buffer, false);
#else
	dec_buf_len = trust_signer_encrypt (table_buffer, table_buf_len, wb_buffer, wb_buf_len, dec_buffer, false);
#endif
	LOGD("----------------------------- WB DEC ---------------------------------\n");
	hex_print (hexbuf, dec_buffer, (size_t) dec_buf_len);
	LOGD("(%03d) : %s\n", dec_buf_len, hexbuf);
#endif
#else
    wb_buf_len = enc_buf_len;
    memcpy (wb_buffer, enc_buffer, enc_buf_len);
#endif

	// DATA Return /////////////////////////////////////////////////////////////////////////////////
#if defined(__ANDROID__)
	wb_data = env->NewByteArray (wb_buf_len + sizeof(wb_buf_len));
	env->SetByteArrayRegion (wb_data, 0, sizeof(wb_buf_len), (jbyte *) &wb_buf_len);
	env->SetByteArrayRegion (wb_data, sizeof(wb_buf_len), wb_buf_len, (jbyte *) wb_buffer);
#else
#if defined(__FILES__)
	wb_data = (unsigned char *) malloc ((size_t) (wb_buf_len + sizeof(wb_buf_len)));
	memcpy (wb_data, &wb_buf_len, sizeof(wb_buf_len));
	memcpy (wb_data + sizeof(wb_buf_len), wb_buffer, wb_buf_len);
#else
	int wb_data_len = sizeof(wb_data_len) + sizeof(table_buf_len) + table_buf_len + wb_buf_len;
	wb_data = (unsigned char *) malloc ((size_t) wb_data_len);
	memcpy (wb_data, &wb_data_len, sizeof(wb_data_len));
	memcpy (wb_data + sizeof(wb_data_len), &table_buf_len, sizeof(table_buf_len));
	memcpy (wb_data + sizeof(wb_data_len) + sizeof(table_buf_len), table_buffer, table_buf_len);
	memcpy (wb_data + sizeof(wb_data_len) + sizeof(table_buf_len) + table_buf_len, wb_buffer, wb_buf_len);

	memzero (table_buffer, sizeof(table_buffer));

	free (table_buffer);
#endif
#endif

	memzero (wb_buffer, sizeof(wb_buffer));

	return (wb_data);
}


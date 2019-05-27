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
 * 2019/03/26      myseo       create.
 ******************************************************************************/

#ifndef TRUST_SINER_H
#define TRUST_SINER_H

#include <stdio.h>

#if defined(__cplusplus)
extern "C" {
#endif

unsigned char *TrustSigner_getWBInitializeData(char *app_id, char *file_path);
char *TrustSigner_getWBPublicKey(char *app_id, char *file_path, unsigned char *wb_data, char *coin_symbol, int hd_depth, int hd_change, int hd_index);
unsigned char *TrustSigner_getWBSignatureData(char *app_id, char *file_path, unsigned char *wb_data, char *coin_symbol, int hd_depth, int hd_change, int hd_index, unsigned char *hash_message, int hash_len);
char *TrustSigner_getWBRecoveryData(char *app_id, char *file_path, char *user_key, char *server_key);
bool TrustSigner_finishWBRecoveryData(char *app_id, char *file_path);
unsigned char *TrustSigner_setWBRecoveryData(char *app_id, char *file_path, char *user_key, char *recovery_data);

#if defined(__cplusplus)
}
#endif

#endif

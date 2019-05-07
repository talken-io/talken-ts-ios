/******************************************************************************
 * TrustSigner Library (BTC,ETH,XLM Keypair/Signature Maker)
 *
 * Description : White-box encryption header
 *
 * Copyright (C) 2018-2019 NexL Corporation. All rights reserved.
 * http://www.nexl.kr (myseo@nexl.kr)
 ******************************************************************************
 * Edit History
 * When            Who         What, Where, Why
 * 2018/12/20      myseo       create.
 * 2019/03/27      myseo       table file save.
 ******************************************************************************/

#ifndef TRUST_SINER_WHITEBOC_H
#define TRUST_SINER_WHITEBOC_H

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdbool.h>

#if defined(__cplusplus)
extern "C" {
#endif

int trust_signer_create_table(char **table);
int trust_signer_encrypt(char *table, int table_length, unsigned char *input, int in_length, unsigned char *output, bool encrypt);

int trust_signer_create_table_fp(char *filename);
int trust_signer_encrypt_fp(char *filename, unsigned char *input, int in_length, unsigned char *output, bool encrypt);

#if defined(__cplusplus)
}
#endif

#endif

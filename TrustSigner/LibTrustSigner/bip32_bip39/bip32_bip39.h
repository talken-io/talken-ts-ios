//
// Created by Adebayo Olabode on 11/2/18.
//

#ifndef LIB_BIP32_BIP39_H
#define LIB_BIP32_BIP39_H

#include <stdio.h>
#include <string.h>
#include "curves.h"
#include "bip39.h"
#include "bip32.h"

#if defined(__cplusplus)
extern "C" {
#endif

#define VERSION_PRIVATE 0x0488ade4
#if 1 // MYSEO
#define VERSION_PUBLIC  0x0488b21e
#endif

#define FROMHEX_MAXLEN 1024 // MYSEO : 512 -> 1024

const char *generateMnemonic(int strength);
void  generateBip39Seeed(const char *mnemonic,uint8_t seed[64],const char *passphrase);

const uint8_t *fromhex(const char *str);

#if 1 // MYSEO
unsigned char *str2hex(char *string, int length);
#endif

#if 1 // DEBUG
void  print_hex(uint8_t *s);
void  hex_print(char *h, const unsigned char *bin, size_t len);
void  hex_dump(uint8_t *data, uint32_t len);
#endif

#if defined(__cplusplus)
}
#endif

#endif //LIB_BIP32_BIP39_H

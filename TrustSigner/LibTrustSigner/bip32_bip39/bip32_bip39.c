//
// Created by Adebayo Olabode on 11/2/18.
//

#include "bip32_bip39.h"

const char *generateMnemonic(int strength)
{
	const char *mnemonic = mnemonic_generate(strength);
	return mnemonic  ;
}

void  generateBip39Seeed(const char *mnemonic,uint8_t seed[64],const char *passphrase)
{
	mnemonic_to_seed(mnemonic, passphrase, seed,0);
}

const uint8_t *fromhex(const char *str)
{
	static uint8_t buf[FROMHEX_MAXLEN];
	size_t len = strlen(str) / 2;
	if (len > FROMHEX_MAXLEN) len = FROMHEX_MAXLEN;
	for (size_t i = 0; i < len; i++) {
		uint8_t c = 0;
		if (str[i * 2] >= '0' && str[i*2] <= '9') c += (str[i * 2] - '0') << 4;
		if ((str[i * 2] & ~0x20) >= 'A' && (str[i*2] & ~0x20) <= 'F') c += (10 + (str[i * 2] & ~0x20) - 'A') << 4;
		if (str[i * 2 + 1] >= '0' && str[i * 2 + 1] <= '9') c += (str[i * 2 + 1] - '0');
		if ((str[i * 2 + 1] & ~0x20) >= 'A' && (str[i * 2 + 1] & ~0x20) <= 'F') c += (10 + (str[i * 2 + 1] & ~0x20) - 'A');
		buf[i] = c;
	}
	return buf;
}

#if 1 // DEBUG
unsigned char *str2hex(char *string, int length)
{
	static unsigned char buf[FROMHEX_MAXLEN];
	size_t len = length / 2;
	if (len > FROMHEX_MAXLEN) len = FROMHEX_MAXLEN;
	for (size_t i = 0; i < len; i++) {
		unsigned char c = 0;
		if  (string[i * 2]     >= '0'          &&  string[i * 2]      <= '9')         c += (string[i * 2] - '0') << 4;
		if ((string[i * 2]     & ~0x20) >= 'A' && (string[i * 2]     & ~0x20) <= 'F') c += (10 + (string[i * 2] & ~0x20) - 'A') << 4;
		if  (string[i * 2 + 1] >= '0'          &&  string[i * 2 + 1]  <= '9')         c += (string[i * 2 + 1] - '0');
		if ((string[i * 2 + 1] & ~0x20) >= 'A' && (string[i * 2 + 1] & ~0x20) <= 'F') c += (10 + (string[i * 2 + 1] & ~0x20) - 'A');
		buf[i] = c;
	}
	return buf;
}

void print_hex(uint8_t *s)
{
	size_t len = strlen((char*)s);
	for(size_t i = 0; i < len; i++) {
		printf("%02x", s[i]);
	}
	printf("\n");
}

void hex_print(char *h, const unsigned char *bin, size_t len)
{
	const char hex[16] = "0123456789abcdef";

	while (len > 0) {
		*h++ = hex[*bin >> 4];
		*h++ = hex[*bin & 0xf];
		++bin, --len;
	}
	*h = '\0';
 }

void hex_dump(uint8_t *data, uint32_t len)
{
	char ascii[17];
	size_t i, j;
	ascii[16] = '\0';
	for (i=0; i<len; ++i) {
		printf("%02X ", ((unsigned char*)data)[i]);
		if (((unsigned char*)data)[i] >= ' ' && ((unsigned char*)data)[i] <= '~') {
			ascii[i % 16] = ((unsigned char*)data)[i];
		} else {
			ascii[i % 16] = '.';
		}
		if ((i+1) % 8 == 0 || i+1 == len) {
			printf(" ");
			if ((i+1) % 16 == 0) {
				printf("|  %s \n", ascii);
			} else if (i+1 == len) {
				ascii[(i+1) % 16] = '\0';
				if ((i+1) % 16 <= 8) {
					printf(" ");
				}
				for (j = (i+1) % 16; j < 16; ++j) {
					printf("   ");
				}
				printf("|  %s \n", ascii);
			}
		}
	}
}
#endif

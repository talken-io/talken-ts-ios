/******************************************************************************
 * TrustSigner Library (BTC,ETH,XLM Keypair/Signature Maker)
 *
 * Description : White-box encryption function
 *
 * Copyright (C) 2018-2019 NexL Corporation. All rights reserved.
 * http://www.nexl.kr (myseo@nexl.kr)
 ******************************************************************************
 * Edit History
 * When            Who         What, Where, Why
 * 2018/12/20      myseo       create.
 * 2019/03/27      myseo       table file save.
 ******************************************************************************/

#include "string.h"

#include "whitebox.h"

#include "WBAES.h"
#include "WBAESGenerator.h"
#include "InputObjectBuffer.h"
#include "EncTools.h"

using namespace std;

int trust_signer_create_table(char **table)
{
	std::string outTable;
	char *phrase;
	unsigned char keyFromString[AES_BYTES] = {0};

	GenericAES defAES;
	defAES.init(0x11B, 0x03);

	WBAESGenerator generator;
	WBAES *genAES = new WBAES;

	ExtEncoding coding;
	generator.generateExtEncoding(&coding, WBAESGEN_EXTGEN_ID);

	for(int i=0; i<AES_BYTES; i++){
		keyFromString[i] = (unsigned char)(phrand() % 0x100);
	}

	generator.generateTables(keyFromString, KEY_SIZE_16, genAES, &coding, true);
	generator.generateTables(keyFromString, KEY_SIZE_16, genAES, &coding, false);

	for(int i=0; i<AES_BYTES; i++){
		keyFromString[i] = (unsigned char) 0xFF;
		keyFromString[i] = (unsigned char) 0x55;
		keyFromString[i] = (unsigned char) 0x00;
	}

	outTable = genAES->save();
	delete genAES;

	int length = outTable.length();
	phrase = (char *) malloc (length + 1);
	memset (phrase, 0, length + 1);
	memcpy (phrase, outTable.c_str(), length);

	outTable.clear();

	*table = phrase;

	return length;
}

int trust_signer_encrypt(char *table, int table_length, unsigned char *input, int in_length, unsigned char *output, bool encrypt)
{
	bool cbc = true;
	bool pkcs5Padding = true;
	time_t cacc = 0;
	clock_t pacc = 0;
	unsigned char ivFromString[N_BYTES] = {0};

	GenericAES defAES;
	defAES.init(0x11B, 0x03);

	WBAESGenerator generator;
	WBAES *genAES = new WBAES;

	ExtEncoding coding;
	generator.generateExtEncoding(&coding, WBAESGEN_EXTGEN_ID);

	std::string inTable(table, table_length);

	genAES->loadString(inTable);

	InputObjectBuffer<BYTE> ioib(in_length);
	ioib.write(input, in_length);
	InputObjectBuffer<BYTE> ioob(in_length*N_BYTES);

	EncTools::processData(!encrypt, genAES, &generator, &ioib, &ioob, &coding, pkcs5Padding, cbc, ivFromString, &cacc, &pacc);
	delete genAES;

	int length = ioob.getPos();
	ioob.read(output, length);

	ioib.clear();
	ioob.clear();

	return length;
}

int trust_signer_create_table_fp(char *filename)
{
	int ret = 0;
	unsigned char keyFromString[AES_BYTES] = {0};

	if (filename == NULL || strlen(filename) < 1)
		return -1;

	GenericAES defAES;
	defAES.init(0x11B, 0x09);

	WBAESGenerator generator;
	WBAES *genAES = new WBAES;

	ExtEncoding coding;
	generator.generateExtEncoding(&coding, WBAESGEN_EXTGEN_ID);

	for(int i=0; i<AES_BYTES; i++){
		keyFromString[i] = (unsigned char)(phrand() % 0x100);
	}

	generator.generateTables(keyFromString, KEY_SIZE_16, genAES, &coding, true);
	generator.generateTables(keyFromString, KEY_SIZE_16, genAES, &coding, false);

	for(int i=0; i<AES_BYTES; i++){
		keyFromString[i] = (unsigned char) 0xFF;
		keyFromString[i] = (unsigned char) 0x55;
		keyFromString[i] = (unsigned char) 0x00;
	}

	ret = genAES->save(filename);
	delete genAES;

	return ret;
}

int trust_signer_encrypt_fp(char *filename, unsigned char *input, int in_length, unsigned char *output, bool encrypt)
{
	bool cbc = true;
	bool pkcs5Padding = true;
	time_t cacc = 0;
	clock_t pacc = 0;
	unsigned char ivFromString[N_BYTES] = {0};

	if (filename == NULL || strlen(filename) < 1)
		return -1;

	GenericAES defAES;
	defAES.init(0x11B, 0x09);

	WBAESGenerator generator;
	WBAES *genAES = new WBAES;
	genAES->load(filename);

	ExtEncoding coding;
	generator.generateExtEncoding(&coding, WBAESGEN_EXTGEN_ID);

	InputObjectBuffer<BYTE> ioib(in_length);
	ioib.write(input, in_length);
	InputObjectBuffer<BYTE> ioob(in_length*N_BYTES);

	EncTools::processData(!encrypt, genAES, &generator, &ioib, &ioob, &coding, pkcs5Padding, cbc, ivFromString, &cacc, &pacc);
	delete genAES;

	int length = ioob.getPos();
	ioob.read(output, length);

	ioib.clear();
	ioob.clear();

	return length;
}

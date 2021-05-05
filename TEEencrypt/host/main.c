/*
 * Copyright (c) 2016, Linaro Limited
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 *
 * 1. Redistributions of source code must retain the above copyright notice,
 * this list of conditions and the following disclaimer.
 *
 * 2. Redistributions in binary form must reproduce the above copyright notice,
 * this list of conditions and the following disclaimer in the documentation
 * and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
 * AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE
 * LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
 * CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
 * SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
 * INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
 * CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
 * POSSIBILITY OF SUCH DAMAGE.
 */

#include <err.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>

/* OP-TEE TEE client API (built by optee_client) */
#include <tee_client_api.h>

/* To the the UUID (found the the TA's h-file(s)) */
#include <TEEencrypt_ta.h>

int main(int argc, char* argv[])
{
	TEEC_Result res;
	TEEC_Context ctx;
	TEEC_Session sess;
	TEEC_Operation op;
	TEEC_UUID uuid = TA_TEEencrypt_UUID;
	uint32_t err_origin;
	char plaintext[64] = {0,};
	char ciphertext[64] = {0,};
	char enc_random_key[64] = {0,};
	int len=64;

	res = TEEC_InitializeContext(NULL, &ctx);
	if (res != TEEC_SUCCESS)
		errx(1, "TEEC_InitializeContext failed with code 0x%x", res);

	res = TEEC_OpenSession(&ctx, &sess, &uuid,
			       TEEC_LOGIN_PUBLIC, NULL, NULL, &err_origin);
	if (res != TEEC_SUCCESS)
		errx(1, "TEEC_Opensession failed with code 0x%x origin 0x%x",
			res, err_origin);

	memset(&op, 0, sizeof(op));
	op.paramTypes = TEEC_PARAM_TYPES(TEEC_MEMREF_TEMP_OUTPUT, TEEC_MEMREF_TEMP_OUTPUT,
					 TEEC_MEMREF_TEMP_OUTPUT, TEEC_NONE);
	op.params[0].tmpref.buffer = plaintext;
	op.params[0].tmpref.size = len;
	op.params[1].tmpref.buffer = ciphertext;
	op.params[1].tmpref.size = len;
	op.params[2].tmpref.buffer = enc_random_key;
	op.params[2].tmpref.size = len;


	int flag = 0;
	int c;
	while((c=getopt(argc, argv, "ed")) != -1){
		switch(c){
			case 'e':printf("Option e\n");flag=1;break;
			case 'd':printf("Option d\n");flag=2;break;
			default:printf("Unknown Option\n");break;
		}
	}
	
	if(flag == 1){
		FILE *f1 = fopen(argv[2], "r+");
		if(f1 == NULL){
			printf("File does not exist\n");
			exit(1);
		}
		fgets(plaintext, len, f1);
		printf("Input File: %s", plaintext);
		memcpy(op.params[0].tmpref.buffer, plaintext, len);
		fclose(f1);

		res = TEEC_InvokeCommand(&sess, TA_TEEencrypt_CMD_GEN_RANDOM_VALUE, &op,
				 &err_origin);
		if (res != TEEC_SUCCESS)
			errx(1, "TEEC_InvokeCommand failed with code 0x%x origin 0x%x",
				res, err_origin);
		printf("Generate Random Key\n");

		res = TEEC_InvokeCommand(&sess, TA_TEEencrypt_CMD_ENC_VALUE, &op,
				&err_origin);
		if (res != TEEC_SUCCESS)
			errx(1, "TEEC_InvokeCommand failed with code 0x%x origin 0x%x",
				res, err_origin);
		printf("Encrypt Text\n");
		memcpy(ciphertext, op.params[0].tmpref.buffer, len);
		printf("Encrypted Text: %s", ciphertext);
		FILE *f2 = fopen("ciphertext.txt", "w");
		if(f2 == NULL){
			printf("Can't make file\n");
			exit(1);
		}
		fputs(ciphertext, f2);
		printf("Maked: ciphertext.txt\n");
		fclose(f2);

		res = TEEC_InvokeCommand(&sess, TA_TEEencrypt_CMD_ENC_RANDOM_VALUE, &op,
				&err_origin);
		if (res != TEEC_SUCCESS)
			errx(1, "TEEC_InvokeCommand failed with code 0x%x origin 0x%x",
				res, err_origin);
		printf("Encrypt Random Key\n");
		memcpy(enc_random_key, op.params[0].tmpref.buffer, len);
		printf("Encrypted Random Key: %c\n", enc_random_key[0]);

		FILE *f3 = fopen("enc_random_key.txt", "w");
		if(f3 == NULL){
			printf("Can't make file\n");
			exit(1);
		}
		fputc(enc_random_key[0], f3);
		printf("Maked: enc_random_key.txt\n");
		fclose(f3);
	}
	else if(flag == 2){
		FILE *f1 = fopen(argv[2], "r+");
		if(f1 == NULL){
			printf("FILE does not exist\n");
			exit(1);
		}
		fgets(plaintext, len, f1);
		printf("Input File: %s", plaintext);
		memcpy(op.params[0].tmpref.buffer, plaintext, len);
		fclose(f1);

		FILE *f2 = fopen(argv[3], "r+");
		if(f2 == NULL){
			printf("FILE does not exist\n");
			exit(1);
		}
		enc_random_key[0] = (char)fgetc(f2);
		printf("Encrypted Random Key: %c\n", enc_random_key[0]);
		memcpy(op.params[1].tmpref.buffer, enc_random_key, len);
		fclose(f2);

		res = TEEC_InvokeCommand(&sess, TA_TEEencrypt_CMD_DEC_VALUE, &op,
				&err_origin);
		if (res != TEEC_SUCCESS)
			errx(1, "TEEC_InvokeCommand failed with code 0x%x origin 0x%x",
				res, err_origin);
		printf("DECRYPT RANDOM KEY & DECRYPT TXT\n");
		memcpy(ciphertext, op.params[0].tmpref.buffer, len);
		printf("Decrypted Text : %s", ciphertext);

		FILE *f3 = fopen("decryptedtext.txt", "w");
		if(f3 == NULL){
			printf("Can't make file\n");
			exit(1);
		}
		fputs(ciphertext, f3);
		printf("Maked: decryptedtext.txt\n");
		fclose(f3);
	}

	TEEC_CloseSession(&sess);
	TEEC_FinalizeContext(&ctx);

	return 0;
}

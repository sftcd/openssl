/*
 * Copyright 2018 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the OpenSSL license (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

/*
 * This is a temporary library and main file to start in on esni
 * in OpenSSL style, as per https://tools.ietf.org/html/draft-ietf-tls-esni-02
 * Author: stephen.farrell@cs.tcd.ie
 * Date: 20181103
 */

#include <stdio.h>
#include <ssl_locl.h>
#include <../ssl/packet_locl.h>
#include <../apps/apps.h>
#include <openssl/kdf.h>
#include <openssl/esni.h>
#include <openssl/esnierr.h>


/*
 * For local testing
 */
#define TESTMAIN

#ifdef TESTMAIN
// code within here need not be openssl-style, but we'll migrate there:-)
int main(int argc, char **argv)
{
	int rv;
	// s_client gets stuff otherwise but for now...
	// usage: esni frontname esniname
	if (argc!=3 && argc!=4) {
		printf("usage: esni frontname esniname [esnikeys]\n");
		exit(1);
	}
	if (!ERR_load_ESNI_strings()) {
		printf("Can't init error strings - exiting\n");
		exit(1);
	}
	// init ciphers
	if (!ssl_load_ciphers()) {
		printf("Can't init ciphers - exiting\n");
		exit(1);
	}
	if (!RAND_set_rand_method(NULL)) {
		printf("Can't init (P)RNG - exiting\n");
		exit(1);
	}
	char *encservername=OPENSSL_strdup(argv[1]);
	char *frontname=OPENSSL_strdup(argv[2]);
	char *esnikeys_b64=NULL;
	char *deffront="cloudflare.net";
	FILE *fp=NULL;
	BIO *out=NULL;
	SSL_ESNI *esnikeys=NULL;
	CLIENT_ESNI *the_esni=NULL;
	/* 
	 * fake client random
	 */
	size_t cr_len=SSL3_RANDOM_SIZE;
	unsigned char client_random[SSL3_RANDOM_SIZE];
	RAND_bytes(client_random,cr_len);

	/*
	 * fake client keyshare
	 */
	size_t ckl=32;
	unsigned char ck[32];
	//RAND_bytes(ck,32);
	memset(ck,0xA5,32);


	if (argc==4) 
		esnikeys_b64=OPENSSL_strdup(argv[3]);
	else
		esnikeys_b64=deffront;

	if (!(rv=esni_checknames(encservername,frontname))) {
		printf("Bad names! %d\n",rv);
		goto end;
	}

	esnikeys=SSL_ESNI_new_from_base64(esnikeys_b64);
	if (esnikeys == NULL) {
		printf("Can't create SSL_ESNI from b64!\n");
		goto end;
	}

	fp=fopen("/dev/stdout","w");
	if (fp==NULL)
		goto end;

	out=BIO_new_fp(fp,BIO_CLOSE|BIO_FP_TEXT);
	if (out == NULL)
		goto end;

	if (!SSL_ESNI_enc(esnikeys,encservername,frontname,cr_len,client_random,ckl,ck,&the_esni)) {
		printf("Can't encrypt SSL_ESNI!\n");
		goto end;
	}

	if (!SSL_ESNI_print(out,esnikeys)) {
		printf("Can't print SSL_ESNI!\n");
		goto end;
	}

end:
	BIO_free_all(out);
	OPENSSL_free(encservername);
	OPENSSL_free(frontname);
	if (argc==4) 
		OPENSSL_free(esnikeys_b64);
	if (esnikeys!=NULL) {
		SSL_ESNI_free(esnikeys);
		OPENSSL_free(esnikeys);
	}
	return(0);
}
#endif





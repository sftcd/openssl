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

#ifndef OPENSSL_NO_ESNI
/*
 * code within here should be openssl-style
 */

/*
 * define'd constants to go in various places
 */ 

/* destintion: include/openssl/tls1.h: */
# define TLSEXT_TYPE_esni_type           0xffce

/*
 * From the I-D:
       struct {
           uint16 version;
           uint8 checksum[4];
           KeyShareEntry keys<4..2^16-1>;
           CipherSuite cipher_suites<2..2^16-2>;
           uint16 padded_length;
           uint64 not_before;
           uint64 not_after;
           Extension extensions<0..2^16-1>;
       } ESNIKeys;
 * 
 * Note that I don't like the above, but it's what we have to
 * work with at the moment.
 * TODO: figure out openssl style types for the above
 */
typedef struct esni_record_st {
	uint16_t version;
	const char checksum[4];
	unsigned int nkeys;
	unsigned int *curve_ids;
	EVP_PKEY *keys;
	unsigned int nsuites;
	SSL_CIPHER *suites;
	unsigned int padded_length;
	uint64_t not_before;
	uint64_t not_after;
	unsigned int nexts;
	unsigned int *exttypes;
	void *exts[];
} ESNI_RECORD;

/*
 * Per connection ESNI state (inspired by include/internal/dane.h) 
 */
typedef struct ssl_esni_st {
	int nerecs; /* number of DNS RRs in RRset */
    ESNI_RECORD *erecs; /* array of these */
    ESNI_RECORD *mesni;      /* Matching esni record */
	const char *encservername;
	const char *frontname;
	uint64_t ttl;
	uint64_t lastread;
} SSL_ESNI;

int esni_checknames(const char *encservername, const char *frontname)
{
	/*
	 * Check names for length 
	 * TODO: other sanity checks, as becomes apparent
	 */
	if (OPENSSL_strnlen(encservername,TLSEXT_MAXLEN_host_name)>TLSEXT_MAXLEN_host_name) return(0);
	if (OPENSSL_strnlen(frontname,TLSEXT_MAXLEN_host_name)>TLSEXT_MAXLEN_host_name) return(0);
	return(1);
}

/*
 * Decode from TXT RR to binary buffer, this is the
 * exact same as ct_base64_decode from crypto/ct/ct_b64.c
 * which function is declared static but could otherwise
 * be re-used. Returns -1 for error or length of decoded
 * buffer length otherwise (wasn't clear to me at first
 * glance).
 *
 * Decodes the base64 string |in| into |out|.
 * A new string will be malloc'd and assigned to |out|. This will be owned by
 * the caller. Do not provide a pre-allocated string in |out|.
 */
static int esni_base64_decode(char *in, unsigned char **out)
{
    size_t inlen = strlen(in);
    int outlen, i;
    unsigned char *outbuf = NULL;

    if (inlen == 0) {
        *out = NULL;
        return 0;
    }

    outlen = (inlen / 4) * 3;
    outbuf = OPENSSL_malloc(outlen);
    if (outbuf == NULL) {
        CTerr(CT_F_CT_BASE64_DECODE, ERR_R_MALLOC_FAILURE);
        goto err;
    }

    outlen = EVP_DecodeBlock(outbuf, (unsigned char *)in, inlen);
    if (outlen < 0) {
        CTerr(CT_F_CT_BASE64_DECODE, CT_R_BASE64_DECODE_ERROR);
        goto err;
    }

    /* Subtract padding bytes from |outlen|.  Any more than 2 is malformed. */
    i = 0;
    while (in[--inlen] == '=') {
        --outlen;
        if (++i > 2)
            goto err;
    }

    *out = outbuf;
    return outlen;
err:
    OPENSSL_free(outbuf);
    return -1;
}

/*
 * Decode from TXT RR to SSL_ESNI
 * This time inspired but, but not the same as
 * SCT_new_from_base64 from crypto/ct/ct_b64.c
 */
SSL_ESNI* SSL_ESNI_new_from_base64(char *esnikeys)
{
	/* 
	 * TODO: fix up error handling when we know what errors
	 */
	if (esnikeys==NULL)
		return(NULL);

    int declen;
    unsigned char *outbuf = NULL;
    declen = esni_base64_decode(esnikeys, &outbuf);
	SSL_ESNI *newesni=NULL;
    if (declen < 0) {
        CTerr(CT_F_SCT_NEW_FROM_BASE64, X509_R_BASE64_DECODE_ERROR);
        goto err;
    }
	newesni=OPENSSL_malloc(sizeof(SSL_ESNI));
	if (newesni==NULL)
		goto err;
	/* version */
	if (declen < 2) {
        CTerr(CT_F_SCT_NEW_FROM_BASE64, X509_R_BASE64_DECODE_ERROR);
		goto err;
	}
	/*
	 * TODO: handle >1 RR in RRset here (somehow:-)
	 */
	newesni->nerecs=1;
	newesni->erecs=NULL;
	newesni->erecs=OPENSSL_malloc(sizeof(SSL_ESNI));
	if (newesni->erecs==NULL) { 
        CTerr(CT_F_SCT_NEW_FROM_BASE64, X509_R_BASE64_DECODE_ERROR);
		goto err;
	}
	newesni->erecs->version=(outbuf[0] << 8 | outbuf [1]);
	return(newesni);
err:
	if (newesni->erecs!=NULL)
		OPENSSL_free(newesni->erecs);
	if (newesni!=NULL)
		OPENSSL_free(newesni);
	if (outbuf!=NULL)
		OPENSSL_free(outbuf);
	return(NULL);
}

/*
 * TODO: This should output to a BIO*
 */
int SSL_ESNI_print(SSL_ESNI *esni)
{
	if (esni==NULL) {
        CTerr(CT_F_SCT_NEW_FROM_BASE64, X509_R_BASE64_DECODE_ERROR);
		return(1);
	}
	if (esni->erecs==NULL) {
        CTerr(CT_F_SCT_NEW_FROM_BASE64, X509_R_BASE64_DECODE_ERROR);
		return(1);
	}
	printf("ESNI version: %x\n",esni->erecs->version);
	return(1);
}

#endif

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
	char *encservername=OPENSSL_strdup(argv[1]);
	char *frontname=OPENSSL_strdup(argv[2]);
	char *esnikeys_b64=NULL;
	char *deffront="cloudflare.net";
	if (argc==4) 
		esnikeys_b64=OPENSSL_strdup(argv[3]);
	else
		esnikeys_b64=deffront;
	printf("Trying to do bits of esni to %s via %s using %s\n",encservername,frontname,esnikeys_b64);
	if (!(rv=esni_checknames(encservername,frontname)))
		printf("Bad names! %d\n",rv);
	SSL_ESNI *esnikeys=SSL_ESNI_new_from_base64(esnikeys_b64);
	if (esnikeys==NULL) {
		printf("Can't create SSL_ESNI from b64!\n");
		goto out;
	}
	if (!SSL_ESNI_print(esnikeys)) {
		printf("Can't print SSL_ESNI!\n");
		goto out;
	}
		
out:
	OPENSSL_free(encservername);
	OPENSSL_free(frontname);
	if (argc==4) 
		OPENSSL_free(esnikeys_b64);
	if (esnikeys->erecs!=NULL)
		OPENSSL_free(esnikeys->erecs);
	if (esnikeys!=NULL)
		OPENSSL_free(esnikeys);
	return(0);
}
#endif





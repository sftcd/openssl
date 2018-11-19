/*
 * Copyright 2018 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the OpenSSL license (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#include <stdio.h>
#include <ssl_locl.h>
#include <../ssl/packet_locl.h>
#include <../apps/apps.h>
#include <openssl/kdf.h>

/*
 * code within here should be openssl-style
 */
#ifndef OPENSSL_NO_ESNI

/*
 * define'd constants to go in various places
 */ 

/* destintion: include/openssl/tls1.h: */
#define TLSEXT_TYPE_esni_type           0xffce

/* destination: include/openssl/ssl.h: */
#define SSL_MAX_SSL_RECORD_DIGEST_LENGTH 255 
#define SSL_MAX_SSL_ENCRYPTED_SNI_LENGTH 1024

/* destination: unknown */
#define SSL_F_TLS_CONSTRUCT_CTOS_ENCRYPTED_SERVER_NAME 401

/*
 * Wrap error handler for now
 */
#ifndef TESTMAIN
/* destination: include/openssl/err.h: */
#define ESNIerr(f,r) ERR_PUT_error(ERR_LIB_CT,(f),(r),OPENSSL_FILE,OPENSSL_LINE)
#else
#define ESNIerr(f,r) fprintf(stderr,"Error in %d,%d, File: %s,Line: %d\n",(f),(r),OPENSSL_FILE,OPENSSL_LINE)
#endif

/* destination: new include/openssl/esni_err.h and/or include/openssl.err.h */

/* 
 * Currently 53 is last one, but lest not be presumptious (yet:-)
 */
#define ERR_LIB_ESNI 									 99

/* 
 * ESNI function codes for ESNIerr
 * These may need to be >100 (or might be convention)
 */
#define ESNI_F_BASE64_DECODE							101
#define ESNI_F_NEW_FROM_BASE64							102
#define ESNI_F_ENC										103
#define ESNI_F_CHECKSUM_CHECK							104

/*
 * ESNI reason codes for ESNIerr
 * These should be >100
 */
#define ESNI_R_BASE64_DECODE_ERROR						110
#define ESNI_R_RR_DECODE_ERROR							111
#define ESNI_R_NOT_IMPL									112


/* 
 * ESNI error strings - inspired by crypto/ct/cterr.c
 */
static const ERR_STRING_DATA ESNI_str_functs[] = {
    {ERR_PACK(ERR_LIB_ESNI, ESNI_F_BASE64_DECODE, 0), "base64 decode"},
    {ERR_PACK(ERR_LIB_ESNI, ESNI_F_NEW_FROM_BASE64, 0), "read from RR"},
    {ERR_PACK(ERR_LIB_ESNI, ESNI_F_ENC, 0), "encrypt SNI details"},
    {0, NULL}
};

static const ERR_STRING_DATA ESNI_str_reasons[] = {
    {ERR_PACK(ERR_LIB_ESNI, 0, ESNI_R_BASE64_DECODE_ERROR), "base64 decode error"},
    {ERR_PACK(ERR_LIB_ESNI, 0, ESNI_R_RR_DECODE_ERROR), "DNS resources record decode error"},
    {ERR_PACK(ERR_LIB_ESNI, 0, ESNI_R_NOT_IMPL), "feature not implemented"},
    {0, NULL}
};

int ERR_load_ESNI_strings(void)
{
#ifndef OPENSSL_NO_ESNI
    if (ERR_func_error_string(ESNI_str_functs[0].error) == NULL) {
        ERR_load_strings_const(ESNI_str_functs);
        ERR_load_strings_const(ESNI_str_reasons);
    }
#endif
    return 1;
}

/* 
 * From the -02 I-D, what we find in DNS:
 *     struct {
 *         uint16 version;
 *         uint8 checksum[4];
 *         KeyShareEntry keys<4..2^16-1>;
 *         CipherSuite cipher_suites<2..2^16-2>;
 *         uint16 padded_length;
 *         uint64 not_before;
 *         uint64 not_after;
 *         Extension extensions<0..2^16-1>;
 *     } ESNIKeys;
 * 
 * Note that I don't like the above, but it's what we have to
 * work with at the moment.
 */
typedef struct esni_record_st {
	unsigned int version;
	unsigned char checksum[4];
	unsigned int nkeys;
	unsigned int *group_ids;
	EVP_PKEY **keys;
	STACK_OF(SSL_CIPHER) *ciphersuites;
	unsigned int padded_length;
	uint64_t not_before;
	uint64_t not_after;
	unsigned int nexts;
	unsigned int *exttypes;
	void **exts;
	/*
	 * The Encoded (binary, after b64-decode) form of the RR
	 */
	size_t encoded_len;
	unsigned char *encoded;
} ESNI_RECORD;

/*
 * The plaintext form of SNI that we encrypt
 *
 *    struct {
 *        ServerNameList sni;
 *        opaque zeros[ESNIKeys.padded_length - length(sni)];
 *    } PaddedServerNameList;
 *
 *    struct {
 *        uint8 nonce[16];
 *        PaddedServerNameList realSNI;
 *    } ClientESNIInner;
 */
typedef struct client_esni_inner_st {
	size_t nonce_len;
	unsigned char *nonce;
	size_t realSNI_len;
	unsigned char *realSNI;
} CLIENT_ESNI_INNER; 

/* 
 * a struct used in key derivation
 * from the I-D:
 *    struct {
 *        opaque record_digest<0..2^16-1>;
 *        KeyShareEntry esni_key_share;
 *        Random client_hello_random;
 *     } ESNIContents;
 *
 */
typedef struct esni_contents_st {
	size_t rd_len;
	unsigned char *rd;
	size_t kse_len;
	unsigned char *kse;
	size_t cr_len;
	unsigned char *cr;
} ESNIContents;

/*
 * Place to keep crypto vars for when we try interop.
 * This should probably (mostly) disappear when/if we end up with
 * a final working version that maps to an RFC.
 *
 * Fields below:
 * keyshare: is the client's ephemeral public value
 * shared: is the D-H shared secret
 * hi: encoded ESNIContents hash input 
 * hash: hash output from above
 * Zx: derived from D-H shared secret
 * key: derived from Zx as per I-D
 * iv: derived from Zx as per I-D
 * aad: the AAD for the AEAD
 * plain: encoded plaintext
 * cipher: ciphertext
 * tag: AEAD tag (exposed by OpenSSL api?)
 */
typedef struct esni_crypto_vars_st {
	EVP_PKEY *keyshare;
	size_t shared_len;
	unsigned char *shared; /* shared secret */
	size_t hi_len;
	unsigned char *hi;
	size_t hash_len;
	unsigned char *hash;
	size_t Zx_len;
	unsigned char *Zx;
	size_t key_len;
	unsigned char *key;
	size_t iv_len;
	unsigned char *iv;
	size_t aad_len;
	unsigned char *aad;
	size_t plain_len;
	unsigned char *plain;
	size_t cipher_len;
	unsigned char *cipher;
	size_t tag_len;
	unsigned char *tag;
} ESNI_CRYPTO_VARS;

/*
 * What we send in the esni CH extension:
 *
 *    struct {
 *        CipherSuite suite;
 *        KeyShareEntry key_share;
 *        opaque record_digest<0..2^16-1>;
 *        opaque encrypted_sni<0..2^16-1>;
 *    } ClientEncryptedSNI;
 *
 * We include some related non-transmitted 
 * e.g. key structures too
 *
 */
typedef struct client_esni_st {
	/*
	 * Fields encoded in extension
	 */
	const SSL_CIPHER *ciphersuite;
	size_t encoded_keyshare_len; /* my encoded key share */
	unsigned char *encoded_keyshare;
	size_t record_digest_len;
	unsigned char record_digest[SSL_MAX_SSL_RECORD_DIGEST_LENGTH];
	size_t encrypted_sni_len;
	unsigned char encrypted_sni[SSL_MAX_SSL_ENCRYPTED_SNI_LENGTH];
	/*
	 * Various intermediate/crypto vars
	 */
	ESNIContents econt;
	CLIENT_ESNI_INNER inner;
	ESNI_CRYPTO_VARS cvars;
} CLIENT_ESNI;

/*
 * Per connection ESNI state (inspired by include/internal/dane.h) 
 * Has DNS RR values and some more
 */
typedef struct ssl_esni_st {
	int nerecs; /* number of DNS RRs in RRset */
    ESNI_RECORD *erecs; /* array of these */
    ESNI_RECORD *mesni;      /* Matching esni record */
	CLIENT_ESNI *client;
	const char *encservername;
	const char *frontname;
	uint64_t ttl;
	uint64_t lastread;
} SSL_ESNI;

/*
 * Prototypes
 */

void CLIENT_ESNI_free(CLIENT_ESNI *c);
void SSL_ESNI_free(SSL_ESNI *esnikeys);
SSL_ESNI* SSL_ESNI_new_from_base64(char *esnikeys);
int SSL_ESNI_print(BIO* out, SSL_ESNI *esni);
int SSL_ESNI_enc(SSL_ESNI *esnikeys, 
				char *protectedserver, 
				char *frontname, 
				size_t  cr_len,
				unsigned char *client_random,
				CLIENT_ESNI **the_esni);

#endif

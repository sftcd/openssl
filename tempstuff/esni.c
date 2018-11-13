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

/*
 * For local testing
 */
#define TESTMAIN

/*
 * code within here should be openssl-style
 */
#ifndef OPENSSL_NO_ESNI

/*
 * define'd constants to go in various places
 */ 

/* destintion: include/openssl/tls1.h: */
#define TLSEXT_TYPE_esni_type           0xffce

/* destinatin: include/openssl/ssl.h: */
#define SSL_MAX_SSL_RECORD_DIGEST_LENGTH 255 
#define SSL_MAX_SSL_ENCRYPTED_SNI_LENGTH 255

/*
 * Wrap error handler for now
 */
#ifndef TESTMAIN
/* destination: include/openssl/err.h: */
#define ESNIerr(f,r) ERR_PUT_error(ERR_LIB_CT,(f),(r),OPENSSL_FILE,OPENSSL_LINE)
#else
#define ESNIerr(f,r) fprintf(stderr,"Error in %d,%d, File: %s,Line: %d\n",(f),(r),OPENSSL_FILE,OPENSSL_LINE)
#endif

/* destination: new include/openssl/esni_err.h: */

/* 
 * ESNI function codes for ESNIerr
 * TODO: check uniqueness rules
 */
#define ESNI_F_BASE64_DECODE							101
#define ESNI_F_NEW_FROM_BASE64							102
#define ESNI_F_ENC										103

/*
 * ESNI reason codes for ESNIerr
 * TODO: check uniqueness rules
 */
#define ESNI_R_BASE64_DECODE_ERROR						110
#define ESNI_R_RR_DECODE_ERROR							111
#define ESNI_R_NOT_IMPL									112
#define ESNI_R_MALLOC_FAILURE							113
#define ESNI_R_INTERNAL_ERROR							114

/*
 * destination: new file include/openssl/esni.h
 * Basic structs for ESNI
 */

/*
 * TODO: simplify these structs once we have the full client-side story done
 */

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
	void *exts[];
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
	size_t hash_len;
	unsigned char hash[EVP_MAX_MD_SIZE];
} ESNIContents;

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
 * TODO: make shared secret hidden below crypto API
 *
 */
typedef struct client_esni_st {
	/*
	 * Fields encoded in extension
	 */
	const SSL_CIPHER *ciphersuite;
	EVP_PKEY *keyshare;
	size_t record_digest_len;
	unsigned char record_digest[SSL_MAX_SSL_RECORD_DIGEST_LENGTH];
	size_t encrypted_sni_len;
	unsigned char encrypted_sni[SSL_MAX_SSL_ENCRYPTED_SNI_LENGTH];
	/*
	 * Locally handled fields
	 */
	size_t shared_len;
	unsigned char *shared; /* shared secret */
	size_t encoded_keyshare_len; /* my encoded key share */
	unsigned char *encoded_keyshare;
	CLIENT_ESNI_INNER inner;
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
 * TODO: Include function prototypes in esni.h
 * We'll do that later, with one file for now, no
 * need yet.
 */

/*
 * Utility functions
 */

/*
* Check names for length 
* TODO: other sanity checks, as becomes apparent
*/
static int esni_checknames(const char *encservername, const char *frontname)
{
	if (OPENSSL_strnlen(encservername,TLSEXT_MAXLEN_host_name)>TLSEXT_MAXLEN_host_name) 
		return(0);
	if (OPENSSL_strnlen(frontname,TLSEXT_MAXLEN_host_name)>TLSEXT_MAXLEN_host_name) 
		return(0);
	return(1);
}

/*
 * map 8 bytes in n/w byte order from PACKET to a 64-bit time value
 * TODO: there must be code for this somewhere - find it
 */
static uint64_t uint64_from_bytes(unsigned char *buf)
{
	uint64_t rv=0;
	rv = ((uint64_t)(*buf)) << 56;
	rv |= ((uint64_t)(*(buf + 1))) << 48;
	rv |= ((uint64_t)(*(buf + 2))) << 40;
	rv |= ((uint64_t)(*(buf + 3))) << 32;
	rv |= ((uint64_t)(*(buf + 4))) << 24;
	rv |= ((uint64_t)(*(buf + 5))) << 16;
	rv |= ((uint64_t)(*(buf + 6))) << 8;
	rv |= *(buf + 7);
	return(rv);
}

/*
 * TODO: Decode from TXT RR to binary buffer, this is the
 * exact same as ct_base64_decode from crypto/ct/ct_b64.c
 * which function is declared static but could otherwise
 * be re-used. Returns -1 for error or length of decoded
 * buffer length otherwise (wasn't clear to me at first
 * glance). The TODO thing is to re-use the ct code by
 * exporting it.
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
        ESNIerr(ESNI_F_BASE64_DECODE, ESNI_R_MALLOC_FAILURE);
        goto err;
    }

    outlen = EVP_DecodeBlock(outbuf, (unsigned char *)in, inlen);
    if (outlen < 0) {
        ESNIerr(ESNI_F_BASE64_DECODE, ESNI_R_BASE64_DECODE_ERROR);
        goto err;
    }

    /* Subtract padding bytes from |outlen|.  Any more than 2 is malformed. */
    i = 0;
    while (in[--inlen] == '=') {
        --outlen;
        if (++i > 2) {
        	ESNIerr(ESNI_F_BASE64_DECODE, ESNI_R_BASE64_DECODE_ERROR);
            goto err;
		}
    }

    *out = outbuf;
    return outlen;
err:
    OPENSSL_free(outbuf);
	ESNIerr(ESNI_F_BASE64_DECODE, ESNI_R_BASE64_DECODE_ERROR);
    return -1;
}

/*
 * Free up a CLIENT_ESNI structure
 * We don't free the top level
 */
void CLIENT_ESNI_free(CLIENT_ESNI *c)
{
	if (c == NULL) return;
    if (c->keyshare != NULL) EVP_PKEY_free(c->keyshare);
	if (c->encoded_keyshare != NULL) OPENSSL_free(c->encoded_keyshare);
	if (c->shared != NULL) OPENSSL_free(c->shared);
	if (c->inner.nonce != NULL ) OPENSSL_free(c->inner.nonce);
	if (c->inner.realSNI != NULL ) OPENSSL_free(c->inner.realSNI);
	return;
}

/*
 * Free up an SSL_ESNI structure - note that we don't
 * free the top level
 */
void SSL_ESNI_free(SSL_ESNI *esnikeys)
{
	if (esnikeys==NULL) 
		return;
	if (esnikeys->erecs != NULL) {
		for (int i=0;i!=esnikeys->nerecs;i++) {
			/*
	 		* ciphersuites
	 		*/
			if (esnikeys->erecs[i].ciphersuites!=NULL) {
				STACK_OF(SSL_CIPHER) *sk=esnikeys->erecs->ciphersuites;
				sk_SSL_CIPHER_free(sk);
			}
			/*
	 		* keys
	 		*/
			if (esnikeys->erecs[i].nkeys!=0) {
				for (int j=0;j!=esnikeys->erecs[i].nkeys;j++) {
					EVP_PKEY *pk=esnikeys->erecs[i].keys[j];
					EVP_PKEY_free(pk);
				}
				OPENSSL_free(esnikeys->erecs[i].group_ids);
				OPENSSL_free(esnikeys->erecs[i].keys);
			}
		}
	}
	if (esnikeys->erecs!=NULL)
		OPENSSL_free(esnikeys->erecs);
	if (esnikeys->client!=NULL) {
		CLIENT_ESNI_free(esnikeys->client);
		OPENSSL_free(esnikeys->client);
	}
	return;
}

/*
 * Decode from TXT RR to SSL_ESNI
 * This time inspired by, but not the same as,
 * SCT_new_from_base64 from crypto/ct/ct_b64.c
 * TODO: handle >1 RRset (maybe at a higher layer)
 */
SSL_ESNI* SSL_ESNI_new_from_base64(char *esnikeys)
{
	if (esnikeys==NULL)
		return(NULL);

    unsigned char *outbuf = NULL; /* binary representation of ESNIKeys */
    int declen; /* length of binary representation of ESNIKeys */
	SSL_ESNI *newesni=NULL; /* decoded ESNIKeys */

    declen = esni_base64_decode(esnikeys, &outbuf);
    if (declen < 0) {
        ESNIerr(ESNI_F_NEW_FROM_BASE64, ESNI_R_BASE64_DECODE_ERROR);
        goto err;
    }

	PACKET pkt={outbuf,declen};

	newesni=OPENSSL_malloc(sizeof(SSL_ESNI));
	if (newesni==NULL) {
        ESNIerr(ESNI_F_NEW_FROM_BASE64, ESNI_R_MALLOC_FAILURE);
		goto err;
	}

	/* sanity check: version + checksum + KeyShareEntry have to be there - min len >= 10 */
	if (declen < 10) {
        ESNIerr(ESNI_F_NEW_FROM_BASE64, ESNI_R_BASE64_DECODE_ERROR);
		goto err;
	}

	newesni->nerecs=1;
	newesni->erecs=NULL;
	newesni->erecs=OPENSSL_malloc(sizeof(ESNI_RECORD));
	if (newesni->erecs==NULL) { 
        ESNIerr(ESNI_F_NEW_FROM_BASE64, ESNI_R_MALLOC_FAILURE);
		goto err;
	}
	ESNI_RECORD *crec=newesni->erecs;

	/* version */
	if (!PACKET_get_net_2(&pkt,&crec->version)) {
        ESNIerr(ESNI_F_NEW_FROM_BASE64, ESNI_R_RR_DECODE_ERROR);
		goto err;
	}

	/* checksum */
	if (!PACKET_copy_bytes(&pkt,crec->checksum,4)) {
        ESNIerr(ESNI_F_NEW_FROM_BASE64, ESNI_R_RR_DECODE_ERROR);
		goto err;
	}
	/* 
	 * list of KeyShareEntry elements - 
	 * inspiration: ssl/statem/extensions_srvr.c:tls_parse_ctos_key_share 
	 */
	PACKET key_share_list;
	if (!PACKET_get_length_prefixed_2(&pkt, &key_share_list)) {
        ESNIerr(ESNI_F_NEW_FROM_BASE64, ESNI_R_RR_DECODE_ERROR);
		goto err;
    }

	unsigned int group_id;
	PACKET encoded_pt;
	int nkeys=0;
	unsigned int *group_ids=NULL;
	EVP_PKEY **keys=NULL;

    while (PACKET_remaining(&key_share_list) > 0) {
        if (!PACKET_get_net_2(&key_share_list, &group_id)
                || !PACKET_get_length_prefixed_2(&key_share_list, &encoded_pt)
                || PACKET_remaining(&encoded_pt) == 0) {
        	ESNIerr(ESNI_F_NEW_FROM_BASE64, ESNI_R_RR_DECODE_ERROR);
            goto err;
        }
		/* 
		 * TODO: ensure that we can call this - likely this calling code will need to be
		 * in libssl.so as that seems to hide this symbol, for now, we hack the build
		 * by copying the .a files locally and linking statically
		 */
		EVP_PKEY *kn=ssl_generate_param_group(group_id);
		if (kn==NULL) {
			//printf("inside: Exit2\n");
        	ESNIerr(ESNI_F_NEW_FROM_BASE64, ESNI_R_RR_DECODE_ERROR);
            goto err;
		}
        if (!EVP_PKEY_set1_tls_encodedpoint(kn,
                PACKET_data(&encoded_pt),
                PACKET_remaining(&encoded_pt))) {
        	ESNIerr(ESNI_F_NEW_FROM_BASE64, ESNI_R_RR_DECODE_ERROR);
            goto err;
        }
		nkeys++;
		EVP_PKEY** tkeys=(EVP_PKEY**)OPENSSL_realloc(keys,nkeys*sizeof(EVP_PKEY*));
		if (tkeys == NULL ) {
        	ESNIerr(ESNI_F_NEW_FROM_BASE64, ESNI_R_RR_DECODE_ERROR);
            goto err;
		}
		keys=tkeys;
		keys[nkeys-1]=kn;
		group_ids=(unsigned int*)OPENSSL_realloc(group_ids,nkeys*sizeof(unsigned int));
		if (keys == NULL ) {
        	ESNIerr(ESNI_F_NEW_FROM_BASE64, ESNI_R_RR_DECODE_ERROR);
            goto err;
		}
    }
	crec->nkeys=nkeys;
	crec->keys=keys;
	crec->group_ids=group_ids;

	/*
	 * List of ciphersuites - 2 byte len + 2 bytes per ciphersuite
	 * Code here inspired by ssl/ssl_lib.c:bytes_to_cipher_list
	 */
	PACKET cipher_suites;
	if (!PACKET_get_length_prefixed_2(&pkt, &cipher_suites)) {
		ESNIerr(ESNI_F_NEW_FROM_BASE64, ESNI_R_RR_DECODE_ERROR);
		goto err;
	}
	int nsuites=PACKET_remaining(&cipher_suites);
	if (!nsuites || (nsuites % 1)) {
		ESNIerr(ESNI_F_NEW_FROM_BASE64, ESNI_R_RR_DECODE_ERROR);
		goto err;
	}
    const SSL_CIPHER *c;
    STACK_OF(SSL_CIPHER) *sk = NULL;
    int n;
    unsigned char cipher[TLS_CIPHER_LEN];
    n = TLS_CIPHER_LEN;
    sk = sk_SSL_CIPHER_new_null();
    if (sk == NULL) {
		ESNIerr(ESNI_F_NEW_FROM_BASE64, ESNI_R_RR_DECODE_ERROR);
        goto err;
    }
    while (PACKET_copy_bytes(&cipher_suites, cipher, n)) {
        c = ssl3_get_cipher_by_char(cipher);
        if (c != NULL) {
            if (c->valid && !sk_SSL_CIPHER_push(sk, c)) {
				ESNIerr(ESNI_F_NEW_FROM_BASE64, ESNI_R_RR_DECODE_ERROR);
                goto err;
            }
        }
    }
    if (PACKET_remaining(&cipher_suites) > 0) {
		ESNIerr(ESNI_F_NEW_FROM_BASE64, ESNI_R_RR_DECODE_ERROR);
        goto err;
    }
    newesni->erecs->ciphersuites=sk;

	if (!PACKET_get_net_2(&pkt,&crec->padded_length)) {
		ESNIerr(ESNI_F_NEW_FROM_BASE64, ESNI_R_RR_DECODE_ERROR);
		goto err;
	}
	unsigned char nbs[8];
	if (!PACKET_copy_bytes(&pkt,nbs,8)) {
		ESNIerr(ESNI_F_NEW_FROM_BASE64, ESNI_R_RR_DECODE_ERROR);
		goto err;
	}
	crec->not_before=uint64_from_bytes(nbs);
	if (!PACKET_copy_bytes(&pkt,nbs,8)) {
		ESNIerr(ESNI_F_NEW_FROM_BASE64, ESNI_R_RR_DECODE_ERROR);
		goto err;
	}
	crec->not_after=uint64_from_bytes(nbs);
	/*
	 * Extensions: we don't yet support any (does anyone?)
	 * TODO: add extensions support at some level 
	 */
	if (!PACKET_get_net_2(&pkt,&crec->nexts)) {
		ESNIerr(ESNI_F_NEW_FROM_BASE64, ESNI_R_RR_DECODE_ERROR);
		goto err;
	}
	if (crec->nexts != 0 ) {
		ESNIerr(ESNI_F_NEW_FROM_BASE64, ESNI_R_RR_DECODE_ERROR);
		goto err;

	}
	int leftover=PACKET_remaining(&pkt);
	if (leftover!=0) {
		ESNIerr(ESNI_F_NEW_FROM_BASE64, ESNI_R_RR_DECODE_ERROR);
		goto err;
	}
	newesni->client=NULL;
	newesni->mesni=&newesni->erecs[0];
	/*
	 * TODO: check bleedin checksum and not_before/not_after as if that's gonna help;-)
	 */

	OPENSSL_free(outbuf);
	return(newesni);
err:
	if (newesni!=NULL) {
		SSL_ESNI_free(newesni);
		OPENSSL_free(newesni);
	}
	if (outbuf!=NULL)
		OPENSSL_free(outbuf);
	return(NULL);
}

/*
 * Print out the DNS RR value(s)
 */
int SSL_ESNI_print(BIO* out, SSL_ESNI *esni)
{
	int indent=0;
	int rv=0;
	if (esni==NULL) {
		BIO_printf(out,"ESNI is NULL!\n");
		return(1);
	}
	BIO_printf(out,"ESNI has %d RRsets\n",esni->nerecs);
	if (esni->erecs==NULL) {
		BIO_printf(out,"ESNI has no keys!\n");
		return(1);
	}
	for (int e=0;e!=esni->nerecs;e++) {
		BIO_printf(out,"ESNI version: 0x%x\n",esni->erecs[e].version);
		BIO_printf(out,"ESNI checksum: 0x");
		for (int i=0;i!=4;i++) {
			BIO_printf(out,"%02x",esni->erecs[e].checksum[i]);
		}
		BIO_printf(out,"\n");
		BIO_printf(out,"Keys: %d\n",esni->erecs[e].nkeys);
		for (int i=0;i!=esni->erecs[e].nkeys;i++) {
			BIO_printf(out,"ESNI Key[%d]: ",i);
			if (esni->erecs->keys && esni->erecs[e].keys[i]) {
				rv=EVP_PKEY_print_public(out, esni->erecs[e].keys[i], indent, NULL); 
				if (!rv) {
					BIO_printf(out,"Oops: %d\n",rv);
				}
			} else {
				BIO_printf(out,"Key %d is NULL!\n",i);
			}
		}
    	STACK_OF(SSL_CIPHER) *sk = esni->erecs[e].ciphersuites;
		if (sk==NULL) {
			BIO_printf(out,"No ciphersuites!\n");
		} else {
			for (int i = 0; i < sk_SSL_CIPHER_num(sk); i++) {
				const SSL_CIPHER *c = sk_SSL_CIPHER_value(sk, i);
				if (c!=NULL) {
					BIO_printf(out,"Ciphersuite %d is %s\n",i,c->name);
				} else {
					BIO_printf(out,"Ciphersuite %d is NULL\n",i);
				}
			}
	
		}
		BIO_printf(out,"ESNI padded_length: %d\n",esni->erecs[e].padded_length);
		BIO_printf(out,"ESNI not_before: %lu\n",esni->erecs[e].not_before);
		BIO_printf(out,"ESNI not_after: %lu\n",esni->erecs[e].not_after);
		BIO_printf(out,"ESNI number of extensions: %d\n",esni->erecs[e].nexts);
	}
	CLIENT_ESNI *c=esni->client;
	if (c == NULL) {
		BIO_printf(out,"ESNI client not done yet.\n");
	} else {
		if (c->ciphersuite!=NULL) {
			BIO_printf(out,"ESNI Client Ciphersuite is %s\n",c->ciphersuite->name);
		} else {
			BIO_printf(out,"ESNI Client Ciphersuite is NULL\n");
		}
		if (c->keyshare != NULL) {
			BIO_printf(out,"ESNI Client Keyshare:\n");
			rv=EVP_PKEY_print_public(out, c->keyshare, indent, NULL); 
			if (!rv) {
				BIO_printf(out,"Oops: %d\n",rv);
			}
		} else {
			BIO_printf(out,"ESNI Client Keyshare is NULL!\n");
		}

		if (c->shared != NULL) {
			BIO_printf(out,"ESNI Client shared: 0x");
			for (int i=0;i!=c->shared_len;i++) {
				BIO_printf(out,"%02x",c->shared[i]);
			}
			BIO_printf(out,"\n");
		} else {
			BIO_printf(out,"ESNI Client shared is NULL!\n");
		}

		if (c->encoded_keyshare != NULL) {
			BIO_printf(out,"ESNI Client encoded_keyshare: 0x");
			for (int i=0;i!=c->encoded_keyshare_len;i++) {
				BIO_printf(out,"%02x",c->encoded_keyshare[i]);
			}
			BIO_printf(out,"\n");
		} else {
			BIO_printf(out,"ESNI Client encoded_keyshare is NULL!\n");
		}
		CLIENT_ESNI_INNER *ci=&c->inner;
		if (ci->nonce != NULL) {
			BIO_printf(out,"ESNI Client inner nonce: 0x");
			for (int i=0;i!=ci->nonce_len;i++) {
				BIO_printf(out,"%02x",ci->nonce[i]);
			}
			BIO_printf(out,"\n");
		} else {
			BIO_printf(out,"ESNI Client inner nonce is NULL!\n");
		}
		if (ci->realSNI != NULL) {
			BIO_printf(out,"ESNI Client inner realSNI (padded: %d): 0x",esni->mesni->padded_length);
			for (int i=0;i!=esni->mesni->padded_length;i++) {
				BIO_printf(out,"%02x",ci->realSNI[i]);
			}
			BIO_printf(out,"\n");
		} else {
			BIO_printf(out,"ESNI Client inner realSNI is NULL!\n");
		}

		/*

	size_t record_digest_len;
	unsigned char record_digest[SSL_MAX_SSL_RECORD_DIGEST_LENGTH];
	size_t encrypted_sni_len;
	unsigned char encrypted_sni[SSL_MAX_SSL_ENCRYPTED_SNI_LENGTH];
		*/
	}
	return(1);
}

/*
 * Make a 16 octet nonce for ESNI
 */
static unsigned char *esni_nonce(size_t nl)
{
	unsigned char *ln=OPENSSL_malloc(nl);
	RAND_bytes(ln,nl);
	return ln;
}

/*
 * Pad an SNI before encryption
 */
static unsigned char *esni_pad(char *name, unsigned int padded_len)
{
	/*
	 * usual function is statem/extensions_clnt.c:tls_construct_ctos_server_name
	 * encoding is 2 byte overall length, 0x00 for hostname, 2 byte length of name, name
	 */
	size_t nl=OPENSSL_strnlen(name,padded_len);
	size_t oh=5; /* encoding overhead */
	if ((nl+oh)>=padded_len) return(NULL);
	unsigned char *buf=OPENSSL_malloc(padded_len);
	memset(buf,0,padded_len);
	buf[0]=((nl+oh)/256);
	buf[1]=((nl+oh)%256);
	buf[2]=0x00;
	buf[3]=(nl/256);
	buf[4]=(nl%256);
	memcpy(buf+oh,name,nl);
	return buf;
}

/*
 * Produce the encrypted SNI value for the CH
 * TODO: handle >1 of things
 * TODO: handle checksums/digests
 */
int SSL_ESNI_enc(SSL_ESNI *esnikeys, char *protectedserver, char *frontname, PACKET *the_esni, unsigned char *client_random)
{
	/*
	 * - make my private key
	 * - generate shared secret
	 * - encrypt protectedserver
	 * - encode packet and return
	 */
	if (esnikeys->client != NULL ) {
		ESNIerr(ESNI_F_ENC, ESNI_R_INTERNAL_ERROR);
		goto err;
	}
	CLIENT_ESNI *cesni=OPENSSL_zalloc(sizeof(CLIENT_ESNI));
	if (cesni==NULL) {
		ESNIerr(ESNI_F_ENC, ESNI_R_MALLOC_FAILURE);
		goto err;
	}
	CLIENT_ESNI_INNER *inner=&cesni->inner;

	/*
	 * D-H stuff inspired by openssl/statem/statem_clnt.c:tls_construct_cke_ecdhe
	 */
    EVP_PKEY *skey = NULL;
    int ret = 0;

	if (esnikeys->erecs==NULL) {
		ESNIerr(ESNI_F_ENC, ESNI_R_INTERNAL_ERROR);
		goto err;
	}

	if (esnikeys->erecs->nkeys==0) {
		ESNIerr(ESNI_F_ENC, ESNI_R_INTERNAL_ERROR);
		goto err;
	}

	/*
	 * TODO: handle cases of >1 thing, for now we just pick 1st and hope...
	 */
	if (esnikeys->nerecs>1) {
		ESNIerr(ESNI_F_ENC, ESNI_R_NOT_IMPL);
	}
	if (esnikeys->erecs[0].nkeys>1) {
		ESNIerr(ESNI_F_ENC, ESNI_R_NOT_IMPL);
	}
	if (sk_SSL_CIPHER_num(esnikeys->erecs[0].ciphersuites)>1) {
		ESNIerr(ESNI_F_ENC, ESNI_R_NOT_IMPL);
	}

	cesni->ciphersuite=sk_SSL_CIPHER_value(esnikeys->erecs[0].ciphersuites,0);

    skey = esnikeys->erecs[0].keys[0];
    if (skey == NULL) {
		ESNIerr(ESNI_F_ENC, ESNI_R_INTERNAL_ERROR);
        goto err;
    }

    cesni->keyshare = ssl_generate_pkey(skey);
    if (cesni->keyshare == NULL) {
		ESNIerr(ESNI_F_ENC, ESNI_R_INTERNAL_ERROR);
        goto err;
    }

	/*
	 * code from ssl/s3_lib.c:ssl_derive
	 */
    EVP_PKEY_CTX *pctx;
	pctx = EVP_PKEY_CTX_new(cesni->keyshare, NULL);
    if (EVP_PKEY_derive_init(pctx) <= 0
        || EVP_PKEY_derive_set_peer(pctx, skey) <= 0
        || EVP_PKEY_derive(pctx, NULL, &cesni->shared_len) <= 0) {
		ESNIerr(ESNI_F_ENC, ESNI_R_INTERNAL_ERROR);
        goto err;
    }
    cesni->shared = OPENSSL_malloc(cesni->shared_len);
    if (cesni->shared == NULL) {
		ESNIerr(ESNI_F_ENC, ESNI_R_INTERNAL_ERROR);
        goto err;
    }
    if (EVP_PKEY_derive(pctx, cesni->shared, &cesni->shared_len) <= 0) {
		ESNIerr(ESNI_F_ENC, ESNI_R_INTERNAL_ERROR);
        goto err;
    }

    /* Generate encoding of client key */
    cesni->encoded_keyshare_len = EVP_PKEY_get1_tls_encodedpoint(cesni->keyshare, &cesni->encoded_keyshare);
    if (cesni->encoded_keyshare_len == 0) {
		ESNIerr(ESNI_F_ENC, ESNI_R_INTERNAL_ERROR);
        goto err;
    }

	/*
	 * Form up the inner SNI stuff
	 */
	inner->realSNI=esni_pad(protectedserver,esnikeys->mesni->padded_length);
	if (inner->realSNI==NULL) {
		ESNIerr(ESNI_F_ENC, ESNI_R_INTERNAL_ERROR);
        goto err;
	}
	inner->nonce_len=16;
	inner->nonce=esni_nonce(inner->nonce_len);
	if (!inner->nonce) {
		ESNIerr(ESNI_F_ENC, ESNI_R_INTERNAL_ERROR);
        goto err;
	}

	/* 
	 * encrypt the actual SNI based on shared key, Z - the I-D says:
	 *    Zx = HKDF-Extract(0, Z)
     *    key = HKDF-Expand-Label(Zx, "esni key", Hash(ESNIContents), key_length)
     *    iv = HKDF-Expand-Label(Zx, "esni iv", Hash(ESNIContents), iv_length)
	 *
     *    struct {
     *        opaque record_digest<0..2^16-1>;
     *        KeyShareEntry esni_key_share;
	 *        Random client_hello_random;
     *    } ESNIContents;
	 *
	 * The above implies we need the CH random as an input (or
	 * the SSL context, but not yet for that)
	 *
	 * client_random is unsigned char client_random[SSL3_RANDOM_SIZE];
	 * from ssl/ssl_locl.h
	 */
	ESNIContents esnicontents;
	esnicontents.rd_len=32;
	/* 
	 * TODO: figure out digesting, just fill randomly for now 
	 */
	esnicontents.rd=OPENSSL_zalloc(esnicontents.rd_len); 
	if (!esnicontents.rd) {
		ESNIerr(ESNI_F_ENC, ESNI_R_MALLOC_FAILURE);
        goto err;
	}
	RAND_bytes(esnicontents.rd,esnicontents.rd_len);
	esnicontents.kse_len=cesni->encoded_keyshare_len;
	esnicontents.kse=cesni->encoded_keyshare;
	esnicontents.cr_len=SSL3_RANDOM_SIZE;
	esnicontents.cr=client_random;

	/*
	 * Form up input for hashing
	 * TODO: Check encoding is right - and use some better fnc
	 */
	size_t oh=2+2+2;
	size_t hi_len=oh+esnicontents.rd_len+esnicontents.kse_len+esnicontents.cr_len;
	unsigned char *hi=OPENSSL_zalloc(hi_len);
	if (hi==NULL) {
		ESNIerr(ESNI_F_ENC, ESNI_R_MALLOC_FAILURE);
        goto err;
	}
	unsigned char *hip=hi;
	*hip++=esnicontents.rd_len/256;
	*hip++=esnicontents.rd_len%256;
	memcpy(hip,esnicontents.rd,esnicontents.rd_len); 
	hip+=esnicontents.rd_len;
	*hip++=esnicontents.kse_len/256;
	*hip++=esnicontents.kse_len%256;
	memcpy(hip,esnicontents.kse,esnicontents.kse_len); 
	hip+=esnicontents.kse_len;
	*hip++=esnicontents.cr_len/256;
	*hip++=esnicontents.cr_len%256;
	memcpy(hip,esnicontents.cr,esnicontents.cr_len); 
	hip+=esnicontents.cr_len;
	hi_len=hip-hi;

	/*
	 * Hash that hi buffer
	 */
	const EVP_MD *md=ssl_md(cesni->ciphersuite->algorithm2);
	EVP_MD_CTX *mctx = NULL;
	mctx = EVP_MD_CTX_new();
	esnicontents.hash_len = EVP_MD_size(md);

    if (mctx == NULL
            || EVP_DigestInit_ex(mctx, md, NULL) <= 0
			|| EVP_DigestUpdate(mctx, hi, hi_len) <= 0
            || EVP_DigestFinal_ex(mctx, esnicontents.hash, NULL) <= 0) {
		ESNIerr(ESNI_F_ENC, ESNI_R_INTERNAL_ERROR);
        goto err;
	}

	/*
	 * Print hash temporarily
	 */
	printf("ESNIContents hash: ");
	for (int i=0;i!=esnicontents.hash_len;i++) {
		printf("%02x",esnicontents.hash[i]);
	}
	printf("\n");

	/*
	 * free up stuff needed just for encryption
	 */
	if (esnicontents.rd!=NULL) OPENSSL_free(esnicontents.rd);
	if (hi!=NULL) OPENSSL_free(hi);

	/* 
	 * finish up
	 */
	esnikeys->client=cesni;
	EVP_PKEY_CTX_free(pctx);
	EVP_MD_CTX_free(mctx);
	OPENSSL_free(hi);

    ret = 1;
	return(ret);
 err:
	if (pctx!=NULL) EVP_PKEY_CTX_free(pctx);
	if (mctx!=NULL) EVP_MD_CTX_free(mctx);
	if (hi!=NULL) OPENSSL_free(hi);
	if (cesni!=NULL) {
		CLIENT_ESNI_free(cesni);
		OPENSSL_free(cesni);
	}
	if (esnicontents.rd!=NULL) OPENSSL_free(esnicontents.rd);
    return ret;
}

#endif

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
	PACKET the_esni={NULL,0};
	/* 
	 * fake client random
	 */
	unsigned char client_random[SSL3_RANDOM_SIZE];
	RAND_bytes(client_random,SSL3_RANDOM_SIZE);


	if (argc==4) 
		esnikeys_b64=OPENSSL_strdup(argv[3]);
	else
		esnikeys_b64=deffront;

	printf("Trying r %s %s %s\n",encservername,frontname,esnikeys_b64);
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

	if (!SSL_ESNI_enc(esnikeys,encservername,frontname,&the_esni,client_random)) {
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
	if (the_esni.curr!=NULL) {
		OPENSSL_free((char*)the_esni.curr);
	}
	return(0);
}
#endif





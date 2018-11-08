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
	unsigned int version;
	unsigned char checksum[4];
	unsigned int nkeys;
	unsigned int *group_ids;
	EVP_PKEY **keys;
	//unsigned int nsuites;
	//SSL_CIPHER *suites;
	STACK_OF(SSL_CIPHER) *ciphersuites;
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

    unsigned char *outbuf = NULL; /* binary representation of ESNIKeys */
    int declen; /* length of binary representation of ESNIKeys */
	SSL_ESNI *newesni=NULL; /* decoded ESNIKeys */

    declen = esni_base64_decode(esnikeys, &outbuf);
    if (declen < 0) {
        CTerr(CT_F_SCT_NEW_FROM_BASE64, X509_R_BASE64_DECODE_ERROR);
        goto err;
    }

	PACKET pkt={outbuf,declen};

	size_t rm=PACKET_remaining(&pkt);
	printf("inside: rm=%ld\n",rm);

	newesni=OPENSSL_malloc(sizeof(SSL_ESNI));
	if (newesni==NULL)
		goto err;

	/* sanity check: version + checksum + KeyShareEntry have to be there - min len >= 10 */
	if (declen < 10) {
        CTerr(CT_F_SCT_NEW_FROM_BASE64, X509_R_BASE64_DECODE_ERROR);
		goto err;
	}

	/*
	 * TODO: handle >1 RR in RRset here (later:-)
	 */
	newesni->nerecs=1;
	newesni->erecs=NULL;
	newesni->erecs=OPENSSL_malloc(sizeof(SSL_ESNI));
	if (newesni->erecs==NULL) { 
        CTerr(CT_F_SCT_NEW_FROM_BASE64, X509_R_BASE64_DECODE_ERROR);
		goto err;
	}
	ESNI_RECORD *crec=newesni->erecs;

	/* version */
	if (!PACKET_get_net_2(&pkt,&crec->version))
		goto err;
	printf("inside: version=%x\n",crec->version);

	/* checksum */
	if (!PACKET_copy_bytes(&pkt,crec->checksum,4))
		goto err;
	printf("inside: checksum: %02x%02x%02x%02x\n",
					crec->checksum[0],
					crec->checksum[1],
					crec->checksum[2],
					crec->checksum[3]);

	/* list of KeyShareEntry elements - inspiration: ssl/statem/extensions_srvr.c:tls_parse_ctos_key_share */
	PACKET key_share_list;
	if (!PACKET_get_length_prefixed_2(&pkt, &key_share_list)) {
        CTerr(CT_F_SCT_NEW_FROM_BASE64, X509_R_BASE64_DECODE_ERROR);
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
        	CTerr(CT_F_SCT_NEW_FROM_BASE64, X509_R_BASE64_DECODE_ERROR);
			printf("inside: Exit1\n");
            goto err;
        }
		printf("inside: group_id: %u\n",group_id);
		rm=PACKET_remaining(&encoded_pt);
		printf("inside: rm=%ld\n",rm);
		/* 
		 * TODO: ensure that we can call this - likely this calling code will need to be
		 * in libssl.so as that seems to hide this symbol
		 */
		EVP_PKEY *kn=ssl_generate_param_group(group_id);
		if (kn==NULL) {
			printf("inside: Exit2\n");
        	CTerr(CT_F_SCT_NEW_FROM_BASE64, X509_R_BASE64_DECODE_ERROR);
            goto err;
		}
		size_t csize=EVP_PKEY_size(kn);
		printf("inside: csize: %ld\n",csize);
        if (!EVP_PKEY_set1_tls_encodedpoint(kn,
                PACKET_data(&encoded_pt),
                PACKET_remaining(&encoded_pt))) {
			printf("inside: Exit3\n");
        	CTerr(CT_F_SCT_NEW_FROM_BASE64, X509_R_BASE64_DECODE_ERROR);
            goto err;
        }
		csize=EVP_PKEY_size(kn);
		printf("inside: csize2: %ld\n",csize);
		nkeys++;
		EVP_PKEY** tkeys=(EVP_PKEY**)OPENSSL_realloc(keys,nkeys*sizeof(EVP_PKEY*));
		if (tkeys == NULL ) {
        	CTerr(CT_F_SCT_NEW_FROM_BASE64, X509_R_BASE64_DECODE_ERROR);
			printf("inside: Exit4\n");
            goto err;
		}
		keys=tkeys;
		keys[nkeys-1]=kn;
		group_ids=(unsigned int*)OPENSSL_realloc(group_ids,nkeys*sizeof(unsigned int));
		if (keys == NULL ) {
        	CTerr(CT_F_SCT_NEW_FROM_BASE64, X509_R_BASE64_DECODE_ERROR);
			printf("inside: Exit5\n");
            goto err;
		}
    }
	printf("inside: found %d keys\n",nkeys);
	crec->nkeys=nkeys;
	crec->keys=keys;
	crec->group_ids=group_ids;

	/*
	 * List of ciphersuites - 2 byte len + 2 bytes per ciphersuite
	 * Code here inspired by ssl/ssl_lib.c:bytes_to_cipher_list
	 */
	PACKET cipher_suites;
	if (!PACKET_get_length_prefixed_2(&pkt, &cipher_suites)) {
       	CTerr(CT_F_SCT_NEW_FROM_BASE64, X509_R_BASE64_DECODE_ERROR);
		printf("inside: Exit6\n");
		goto err;
	}
	int nsuites=PACKET_remaining(&cipher_suites);
	printf("inside: found %d suites\n",nsuites);
	if (!nsuites || (nsuites % 1)) {
       	CTerr(CT_F_SCT_NEW_FROM_BASE64, X509_R_BASE64_DECODE_ERROR);
		printf("inside: Exit7\n");
		goto err;
	}
    const SSL_CIPHER *c;
    STACK_OF(SSL_CIPHER) *sk = newesni->erecs->ciphersuites;
    int n;
    unsigned char cipher[TLS_CIPHER_LEN];
    n = TLS_CIPHER_LEN;
    sk = sk_SSL_CIPHER_new_null();
    if (sk == NULL) {
       	CTerr(CT_F_SCT_NEW_FROM_BASE64, X509_R_BASE64_DECODE_ERROR);
		printf("inside: Exit8\n");
        goto err;
    }
    while (PACKET_copy_bytes(&cipher_suites, cipher, n)) {
        c = ssl3_get_cipher_by_char(cipher);
        if (c != NULL) {
            if (c->valid && !sk_SSL_CIPHER_push(sk, c)) {
				CTerr(CT_F_SCT_NEW_FROM_BASE64, X509_R_BASE64_DECODE_ERROR);
				printf("inside: Exit9\n");
                goto err;
            }
        }
    }
    if (PACKET_remaining(&cipher_suites) > 0) {
       	CTerr(CT_F_SCT_NEW_FROM_BASE64, X509_R_BASE64_DECODE_ERROR);
		printf("inside: Exit10\n");
        goto err;
    }

	return(newesni);
err:
	if (newesni->erecs!=NULL) {
		if (newesni->erecs->nkeys!=0) {
			for (int i=0;i!=newesni->erecs->nkeys;i++) {
				EVP_PKEY_free(newesni->erecs->keys[i]);
			}
			OPENSSL_free(newesni->erecs->group_ids);
			OPENSSL_free(newesni->erecs->keys);
		}
		/*
		if (newesni->erecs->nsuites!=0) {
			for (int i=0;i!=newesni->erecs->nsuites;i++) {
				SSL_CIPHER_free(newesni->erecs->suites[i]);
			}
			OPENSSL_free(newesni->erecs->suites);
		}
		*/
	}
	if (newesni->erecs!=NULL)
		OPENSSL_free(newesni->erecs);
	if (newesni!=NULL)
		OPENSSL_free(newesni);
	if (outbuf!=NULL)
		OPENSSL_free(outbuf);
	return(NULL);
}

void SSL_ESNI_free(SSL_ESNI *esnikeys)
{
	if (esnikeys==NULL) 
		return;
	if (esnikeys!=NULL && esnikeys->erecs!=NULL)
		OPENSSL_free(esnikeys->erecs);
	if (esnikeys!=NULL)
		OPENSSL_free(esnikeys);
	return;
}

/*
 * TODO: This should output to a BIO*
 */
int SSL_ESNI_print(BIO* out, SSL_ESNI *esni)
{
	int indent=0;
	int rv=0;
	if (esni==NULL) {
		BIO_printf(out,"ESNI is NULL!\n");
		return(1);
	}
	if (esni->erecs==NULL) {
		BIO_printf(out,"ESNI has no keys!\n");
		return(1);
	}
	BIO_printf(out,"ESNI version: %x\n",esni->erecs->version);
	BIO_printf(out,"ESNI checksum: ");
	for (int i=0;i!=4;i++) {
		BIO_printf(out,"%0x",esni->erecs->checksum[i]);
	}
	BIO_printf(out,"\n");
	BIO_printf(out,"Keys: %d\n",esni->erecs->nkeys);
	for (int i=0;i!=esni->erecs->nkeys;i++) {
		BIO_printf(out,"ESNI Key[%d]: ",i);
		if (esni->erecs->keys && esni->erecs->keys[i]) {
			rv=EVP_PKEY_print_public(out, esni->erecs->keys[i], indent, NULL); // ASN1_PCTX *pctx);
			if (!rv) {
				BIO_printf(out,"Oops: %d\n",rv);
			}
		} else {
			BIO_printf(out,"NULL!\n");
		}
	}

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
	FILE *fp=NULL;
	BIO *out=NULL;
	SSL_ESNI *esnikeys=NULL;

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
	if (esnikeys!=NULL)
		SSL_ESNI_free(esnikeys);
	return(0);
}
#endif





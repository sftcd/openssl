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

#include "ssl_locl.h"
#include <openssl/ssl.h>
#include <openssl/rand.h>
#include <openssl/kdf.h>
#include <openssl/evp.h>
#include <openssl/esni.h>
#include <openssl/esnierr.h>


/*
 * code within here should be openssl-style
 */
#ifndef OPENSSL_NO_ESNI

/*
 * Purely debug
 */
#ifdef CRYPT_INTEROP
unsigned char *lg_nonce=NULL;
size_t lg_nonce_len=0;
#endif

/*
 * Utility functions
 */

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
 * Decode from TXT RR to binary buffer, this is the
 * exact same as ct_base64_decode from crypto/ct/ct_b64.c
 * which function is declared static but could otherwise
 * be re-used. Returns -1 for error or length of decoded
 * buffer length otherwise (wasn't clear to me at first
 * glance). Possible future change: re-use the ct code by
 * exporting it.
 *
 * Decodes the base64 string |in| into |out|.
 * A new string will be malloc'd and assigned to |out|. This will be owned by
 * the caller. Do not provide a pre-allocated string in |out|.
 */
static int esni_base64_decode(const char *in, unsigned char **out)
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
        ESNIerr(ESNI_F_BASE64_DECODE, ERR_R_MALLOC_FAILURE);
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
    if (c->encoded_keyshare != NULL) OPENSSL_free(c->encoded_keyshare);
    if (c->inner.nonce != NULL ) OPENSSL_free(c->inner.nonce);
    if (c->inner.realSNI != NULL ) OPENSSL_free(c->inner.realSNI);
    if (c->econt.rd != NULL) OPENSSL_free(c->econt.rd);
    if (c->cvars.keyshare != NULL) EVP_PKEY_free(c->cvars.keyshare);
    if (c->cvars.shared != NULL) OPENSSL_free(c->cvars.shared);
    if (c->cvars.hi != NULL) OPENSSL_free(c->cvars.hi);
    if (c->cvars.hash != NULL) OPENSSL_free(c->cvars.hash);
    if (c->cvars.Zx != NULL) OPENSSL_free(c->cvars.Zx);
    if (c->cvars.key != NULL) OPENSSL_free(c->cvars.key);
    if (c->cvars.iv != NULL) OPENSSL_free(c->cvars.iv);
    if (c->cvars.aad != NULL) OPENSSL_free(c->cvars.aad);
    if (c->cvars.cr != NULL) OPENSSL_free(c->cvars.cr);
    if (c->cvars.plain != NULL) OPENSSL_free(c->cvars.plain);
    if (c->cvars.cipher != NULL) OPENSSL_free(c->cvars.cipher);
    if (c->cvars.tag != NULL) OPENSSL_free(c->cvars.tag);
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
            if (esnikeys->erecs[i].encoded!=NULL) OPENSSL_free(esnikeys->erecs[i].encoded);
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

static int esni_checksum_check(unsigned char *buf, size_t buf_len)
{
    /* 
     * copy input with zero'd checksum, do SHA256 hash, compare with checksum, tedious but easy enough
     */
    unsigned char *buf_zeros=OPENSSL_malloc(buf_len);
    if (buf_zeros==NULL) {
        ESNIerr(ESNI_F_NEW_FROM_BASE64, ERR_R_MALLOC_FAILURE);
        goto err;
    }
    memcpy(buf_zeros,buf,buf_len);
    memset(buf_zeros+2,0,4);

    unsigned char md[EVP_MAX_MD_SIZE];

    SHA256_CTX context;
    if(!SHA256_Init(&context)) {
        ESNIerr(ESNI_F_CHECKSUM_CHECK, ERR_R_INTERNAL_ERROR);
        goto err;
    }

    if(!SHA256_Update(&context, buf_zeros, buf_len)) {
        ESNIerr(ESNI_F_CHECKSUM_CHECK, ERR_R_INTERNAL_ERROR);
        goto err;
    }

    if(!SHA256_Final(md, &context)) {
        ESNIerr(ESNI_F_CHECKSUM_CHECK, ERR_R_INTERNAL_ERROR);
        goto err;
    }

    OPENSSL_free(buf_zeros);

    if (memcmp(buf+2,md,4)) {
        /* non match - bummer */
        return 0;
    } else {
        return 1;
    }
err:
    if (buf_zeros!=NULL) OPENSSL_free(buf_zeros);
    return 0;
}

/*
 * Decode from TXT RR to SSL_ESNI
 * This time inspired by, but not the same as,
 * SCT_new_from_base64 from crypto/ct/ct_b64.c
 * TODO: handle >1 of the many things that can 
 * have >1 instance (maybe at a higher layer)
 */
SSL_ESNI* SSL_ESNI_new_from_base64(const char *esnikeys)
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

    int cksum_ok=esni_checksum_check(outbuf,declen);
    if (cksum_ok!=1) {
        ESNIerr(ESNI_F_NEW_FROM_BASE64, ERR_R_INTERNAL_ERROR);
        goto err;
    }

    PACKET pkt={outbuf,declen};

    newesni=OPENSSL_malloc(sizeof(SSL_ESNI));
    if (newesni==NULL) {
        ESNIerr(ESNI_F_NEW_FROM_BASE64, ERR_R_MALLOC_FAILURE);
        goto err;
    }
    memset(newesni,0,sizeof(SSL_ESNI));

    /* sanity check: version + checksum + KeyShareEntry have to be there - min len >= 10 */
    if (declen < 10) {
        ESNIerr(ESNI_F_NEW_FROM_BASE64, ESNI_R_BASE64_DECODE_ERROR);
        goto err;
    }

    newesni->nerecs=1;
    newesni->erecs=NULL;
    newesni->erecs=OPENSSL_malloc(sizeof(ESNI_RECORD));
    if (newesni->erecs==NULL) { 
        ESNIerr(ESNI_F_NEW_FROM_BASE64, ERR_R_MALLOC_FAILURE);
        goto err;
    }
    ESNI_RECORD *crec=newesni->erecs;
    crec->encoded_len=declen;
    crec->encoded=outbuf;

    /* version */
    if (!PACKET_get_net_2(&pkt,&crec->version)) {
        ESNIerr(ESNI_F_NEW_FROM_BASE64, ESNI_R_RR_DECODE_ERROR);
        goto err;
    }

    /* checksum decode */
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

        EVP_PKEY *kn=ssl_generate_param_group(group_id);
        if (kn==NULL) {
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
     * TODO: check bleedin not_before/not_after as if that's gonna help;-)
     */
    return(newesni);
err:
    if (newesni!=NULL) {
        SSL_ESNI_free(newesni);
        OPENSSL_free(newesni);
    }
    return(NULL);
}

/*
 * print a buffer nicely
 */
static void esni_pbuf(BIO *out,char *msg,unsigned char *buf,size_t blen,int indent)
{
    if (buf==NULL) {
        BIO_printf(out,"OPENSSL: %s is NULL",msg);
        return;
    }
    BIO_printf(out,"OPENSSL: %s (%zd):\n    ",msg,blen);
    int i;
    for (i=0;i!=blen;i++) {
        if ((i!=0) && (i%16==0))
            BIO_printf(out,"\n    ");
        BIO_printf(out,"%02x:",buf[i]);
    }
    BIO_printf(out,"\n");
    return;
}

#ifdef CRYPT_INTEROP
/*
 * stdout version of the above - just for odd/occasional debugging
 */
static void so_esni_pbuf(char *msg,unsigned char *buf,size_t blen,int indent)
{
    if (buf==NULL) {
        printf("OPENSSL: %s is NULL",msg);
        return;
    }
    printf("OPENSSL: %s (%zd):\n    ",msg,blen);
    int i;
    for (i=0;i!=blen;i++) {
        if ((i!=0) && (i%16==0))
            printf("\n    ");
        printf("%02x:",buf[i]);
    }
    printf("\n");
    return;
}
#endif

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
        BIO_printf(out,"ESNI Server version: 0x%x\n",esni->erecs[e].version);
        BIO_printf(out,"ESNI Server checksum: 0x");
        for (int i=0;i!=4;i++) {
            BIO_printf(out,"%02x",esni->erecs[e].checksum[i]);
        }
        BIO_printf(out,"\n");
        BIO_printf(out,"ESNI Server Keys: %d\n",esni->erecs[e].nkeys);
        for (int i=0;i!=esni->erecs[e].nkeys;i++) {
            BIO_printf(out,"ESNI Server Key[%d]: ",i);
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
            BIO_printf(out,"ESNI Server, No ciphersuites!\n");
        } else {
            for (int i = 0; i < sk_SSL_CIPHER_num(sk); i++) {
                const SSL_CIPHER *c = sk_SSL_CIPHER_value(sk, i);
                if (c!=NULL) {
                    BIO_printf(out,"ESNI Server Ciphersuite %d is %s\n",i,c->name);
                } else {
                    BIO_printf(out,"ENSI Server Ciphersuite %d is NULL\n",i);
                }
            }
    
        }
        BIO_printf(out,"ESNI Server padded_length: %d\n",esni->erecs[e].padded_length);
        BIO_printf(out,"ESNI Server not_before: %ju\n",esni->erecs[e].not_before);
        BIO_printf(out,"ESNI Server not_after: %ju\n",esni->erecs[e].not_after);
        BIO_printf(out,"ESNI Server number of extensions: %d\n",esni->erecs[e].nexts);
    }
    CLIENT_ESNI *c=esni->client;
    if (c == NULL) {
        BIO_printf(out,"ESNI client not done yet.\n");
    } else {
        BIO_printf(out,"ESNI client:\n");
        if (c->ciphersuite!=NULL) {
            BIO_printf(out,"ESNI Client Ciphersuite is %s\n",c->ciphersuite->name);
        } else {
            BIO_printf(out,"ESNI Client Ciphersuite is NULL\n");
        }

        CLIENT_ESNI_INNER *ci=&c->inner;


        esni_pbuf(out,"ESNI Client keyshare",
                            c->encoded_keyshare,c->encoded_keyshare_len,indent);
        esni_pbuf(out,"ESNI CLient record_digest",
                            c->record_digest,c->record_digest_len,indent);
        esni_pbuf(out,"ESNI CLient encrypted_sni",
                            c->encrypted_sni,c->encrypted_sni_len,indent);
        esni_pbuf(out,"ESNI CLient inner nonce",ci->nonce,ci->nonce_len,indent);
        esni_pbuf(out,"ESNI CLient inner realSNI",ci->realSNI,
                            esni->mesni->padded_length,
                            indent);
        esni_pbuf(out,"ESNI CLient ESNIContents client_random",
                            c->econt.cr,c->econt.cr_len,indent);

        esni_pbuf(out,"ESNI Cryptovars Encoded ESNIContents (hash input)",c->cvars.hi,c->cvars.hi_len,indent);
        esni_pbuf(out,"ESNI Cryptovars hash(ESNIContents)",
                            c->cvars.hash,c->cvars.hash_len,indent);
        esni_pbuf(out,"ESNI Cryptovars Z",c->cvars.shared,c->cvars.shared_len,indent);
        esni_pbuf(out,"ESNI Cryptovars Zx",c->cvars.Zx,c->cvars.Zx_len,indent);
        esni_pbuf(out,"ESNI Cryptovars key",c->cvars.key,c->cvars.key_len,indent);
        esni_pbuf(out,"ESNI Cryptovars iv",c->cvars.iv,c->cvars.iv_len,indent);
        esni_pbuf(out,"ESNI Cryptovars aad",c->cvars.aad,c->cvars.aad_len,indent);
        esni_pbuf(out,"ESNI Cryptovars plain",c->cvars.plain,c->cvars.plain_len,indent);
        esni_pbuf(out,"ESNI Cryptovars cipher",c->cvars.cipher,c->cvars.cipher_len,indent);
        esni_pbuf(out,"ESNI Cryptovars tag",c->cvars.tag,c->cvars.tag_len,indent);
    }
    return(1);
}

/*
 * Make a 16 octet nonce for ESNI
 */
static unsigned char *esni_nonce(size_t nl)
{
#ifdef CRYPT_INTEROP
    if (lg_nonce_len==0) {
        unsigned char *ln=OPENSSL_malloc(nl);
        RAND_bytes(ln,nl);
        return ln;
    } else {
        // hope nl <= lg_nonce_len :-)
        unsigned char *ln=OPENSSL_malloc(nl);
        memset(ln,0,nl);
        memcpy(ln,lg_nonce,lg_nonce_len);
        return ln;
    }
#else
    unsigned char *ln=OPENSSL_malloc(nl);
    RAND_bytes(ln,nl);
    return ln;
#endif
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
    size_t oh=3; /* encoding overhead */
    if ((nl+oh)>=padded_len) return(NULL);
    unsigned char *buf=OPENSSL_malloc(padded_len);
    memset(buf,0,padded_len);
    buf[0]=((nl+oh)/256);
    buf[1]=((nl+oh)%256);
    buf[2]=0x00;
    buf[3]=(nl/256);
    buf[4]=(nl%256);
    memcpy(buf+5,name,nl);
    return buf;
}

/*
 * Hash up ESNIContents as per I-D
 */
static int esni_contentshash(ESNIContents *e, ESNI_CRYPTO_VARS *cv, const EVP_MD *md)
{
    EVP_MD_CTX *mctx = NULL;
    size_t oh=2;
    cv->hi_len=oh+e->rd_len+e->kse_len+e->cr_len;
    cv->hi=OPENSSL_zalloc(cv->hi_len);
    if (cv->hi==NULL) {
        ESNIerr(ESNI_F_ENC, ERR_R_MALLOC_FAILURE);
        goto err;
    }
    unsigned char *hip=cv->hi;
    *hip++=e->rd_len/256;
    *hip++=e->rd_len%256;
    memcpy(hip,e->rd,e->rd_len); 
    hip+=e->rd_len;
    memcpy(hip,e->kse,e->kse_len); 
    hip+=e->kse_len;
    memcpy(hip,e->cr,e->cr_len); 
    hip+=e->cr_len;
    cv->hi_len=hip-cv->hi;
    mctx = EVP_MD_CTX_new();
    cv->hash_len = EVP_MD_size(md);
    cv->hash=OPENSSL_malloc(cv->hash_len);
    if (cv->hash==NULL) {
        goto err;
    }
    if (mctx == NULL
            || EVP_DigestInit_ex(mctx, md, NULL) <= 0
            || EVP_DigestUpdate(mctx, cv->hi, cv->hi_len) <= 0
            || EVP_DigestFinal_ex(mctx, cv->hash, NULL) <= 0) {
        ESNIerr(ESNI_F_ENC, ERR_R_INTERNAL_ERROR);
        goto err;
    }
    EVP_MD_CTX_free(mctx);
    return 1;
err:
    if (mctx!=NULL) EVP_MD_CTX_free(mctx);
    if (cv->hash!=NULL) OPENSSL_free(cv->hash);
    return 0;
}

/*
 * Local wrapper for HKDF-Extract(salt,IVM)=HMAC-Hash(salt,IKM) according
 * to RFC5689
 */
static unsigned char *esni_hkdf_extract(unsigned char *secret,size_t slen,size_t *olen, const EVP_MD *md)
{
    int ret=1;
    unsigned char *outsecret=NULL;
    EVP_PKEY_CTX *pctx = EVP_PKEY_CTX_new_id(EVP_PKEY_HKDF, NULL);
    if (pctx==NULL) {
        return NULL;
    }

    outsecret=OPENSSL_zalloc(EVP_MAX_MD_SIZE);
    if (outsecret==NULL) {
        EVP_PKEY_CTX_free(pctx);
        return NULL;
    }

    /* 
     * based on ssl/tls13_enc.c:tls13_generate_secret
     */

    ret = EVP_PKEY_derive_init(pctx) <= 0
            || EVP_PKEY_CTX_hkdf_mode(pctx, EVP_PKEY_HKDEF_MODE_EXTRACT_ONLY) <= 0
            || EVP_PKEY_CTX_set_hkdf_md(pctx, md) <= 0
            || EVP_PKEY_CTX_set1_hkdf_key(pctx, secret, slen) <= 0
            || EVP_PKEY_CTX_set1_hkdf_salt(pctx, NULL, 0) <= 0
            || EVP_PKEY_derive(pctx, outsecret, olen) <= 0;

    EVP_PKEY_CTX_free(pctx);

    if (ret!=0) {
        OPENSSL_free(outsecret);
        return NULL;
    }
    return outsecret;
}


static unsigned char *esni_hkdf_expand_label(
            unsigned char *Zx, size_t Zx_len,
            const char *label,
            unsigned char *hash, size_t hash_len,
            size_t *expanded_len,
            const EVP_MD *md)
{

#ifndef NOTDEF
    SSL s;
    unsigned char *out=OPENSSL_malloc(32);
    int rv=tls13_hkdf_expand(&s, md, Zx, 
                            (const unsigned char*)label, strlen(label),
                            hash, hash_len,
                            out, *expanded_len);
    if (rv!=1) {
        return NULL;
    }
    return out;
#else
    int ret=1;
    EVP_PKEY_CTX *pctx = EVP_PKEY_CTX_new_id(EVP_PKEY_HKDF, NULL);
    if (pctx==NULL) {
        return NULL;
    }

    unsigned char *out=OPENSSL_zalloc(EVP_MAX_MD_SIZE);
    if (out==NULL) {
        EVP_PKEY_CTX_free(pctx);
        return NULL;
    }

    ret = EVP_PKEY_derive_init(pctx) <= 0
            || EVP_PKEY_CTX_hkdf_mode(pctx, EVP_PKEY_HKDEF_MODE_EXPAND_ONLY) <= 0
            || EVP_PKEY_CTX_set_hkdf_md(pctx, md) <= 0
            || EVP_PKEY_CTX_set1_hkdf_key(pctx, Zx, Zx_len) <= 0
            || EVP_PKEY_CTX_add1_hkdf_info(pctx, label, strlen(label)) <= 0
            || EVP_PKEY_derive(pctx, out, expanded_len) <= 0;

    EVP_PKEY_CTX_free(pctx);
    if (ret!=0) {
        OPENSSL_free(out);
        return NULL;
    }
    return out;
#endif
}

static unsigned char *esni_aead_enc(
            unsigned char *key, size_t key_len,
            unsigned char *iv, size_t iv_len,
            unsigned char *aad, size_t aad_len,
            unsigned char *plain, size_t plain_len,
            unsigned char *tag, size_t tag_len, 
            size_t *cipher_len,
            const SSL_CIPHER *ciph)
{
    /*
     * From https://wiki.openssl.org/index.php/EVP_Authenticated_Encryption_and_Decryption
     */

    EVP_CIPHER_CTX *ctx=NULL;
    int len;
    size_t ciphertext_len;
    unsigned char *ciphertext=NULL;

    /*
     * TODO: figure out correct expansion based on ciphersuite
     */
    ciphertext=OPENSSL_malloc(plain_len+16);
    if (ciphertext==NULL) {
        ESNIerr(ESNI_F_ENC, ERR_R_INTERNAL_ERROR);
        goto err;
    }

    /* Create and initialise the context */
    if(!(ctx = EVP_CIPHER_CTX_new())) {
        ESNIerr(ESNI_F_ENC, ERR_R_INTERNAL_ERROR);
        goto err;
    }

    /* Initialise the encryption operation. */
    const EVP_CIPHER *enc=EVP_get_cipherbynid(SSL_CIPHER_get_cipher_nid(ciph));
    if (enc == NULL) {
        ESNIerr(ESNI_F_ENC, ERR_R_INTERNAL_ERROR);
        goto err;
    }

    if(1 != EVP_EncryptInit_ex(ctx, enc, NULL, NULL, NULL)) {
        ESNIerr(ESNI_F_ENC, ERR_R_INTERNAL_ERROR);
        goto err;
    }

    /* Set IV length if default 12 bytes (96 bits) is not appropriate */
    if(1 != EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, iv_len, NULL)) {
        ESNIerr(ESNI_F_ENC, ERR_R_INTERNAL_ERROR);
        goto err;
    }

    /* Initialise key and IV */
    if(1 != EVP_EncryptInit_ex(ctx, NULL, NULL, key, iv))  {
        ESNIerr(ESNI_F_ENC, ERR_R_INTERNAL_ERROR);
        goto err;
    }

    /* Provide any AAD data. This can be called zero or more times as
     * required
     */
    if(1 != EVP_EncryptUpdate(ctx, NULL, &len, aad, aad_len)) {
        ESNIerr(ESNI_F_ENC, ERR_R_INTERNAL_ERROR);
        goto err;
    }

    /* Provide the message to be encrypted, and obtain the encrypted output.
     * EVP_EncryptUpdate can be called multiple times if necessary
     */
    if(1 != EVP_EncryptUpdate(ctx, ciphertext, &len, plain, plain_len)) {
        ESNIerr(ESNI_F_ENC, ERR_R_INTERNAL_ERROR);
        goto err;
    }

    ciphertext_len = len;

    /* Finalise the encryption. Normally ciphertext bytes may be written at
     * this stage, but this does not occur in GCM mode
     */
    if(1 != EVP_EncryptFinal_ex(ctx, ciphertext + len, &len))  {
        ESNIerr(ESNI_F_ENC, ERR_R_INTERNAL_ERROR);
        goto err;
    }

    ciphertext_len += len;

    /* Get the tag */
    /*
     * This isn't a duplicate so needs to be added to the ciphertext
     */
    if(1 != EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_GET_TAG, tag_len, tag)) {
        ESNIerr(ESNI_F_ENC, ERR_R_INTERNAL_ERROR);
        goto err;
    }
    memcpy(ciphertext+ciphertext_len,tag,tag_len);
    ciphertext_len += tag_len;

    /* Clean up */
    EVP_CIPHER_CTX_free(ctx);

    *cipher_len=ciphertext_len;

    return ciphertext;

err:
    EVP_CIPHER_CTX_free(ctx);
    if (ciphertext!=NULL) OPENSSL_free(ciphertext);
    return NULL;
}

static int esni_make_rd(ESNI_RECORD *er,ESNIContents *ec)
{
    const SSL_CIPHER *sc=sk_SSL_CIPHER_value(er->ciphersuites,0);
    const EVP_MD *md=ssl_md(sc->algorithm2);

    if (er->encoded_len<=2) {
        ESNIerr(ESNI_F_ENC, ERR_R_INTERNAL_ERROR);
        goto err;
    }
    /*
     * It seems that NSS uses the entire buffer, incl. the version, let's try
     * that. (Opened issue: https://github.com/tlswg/draft-ietf-tls-esni/issues/119)
     * Oddly - the ISSUE119YES branch seems to work worse!
     * That may be because CF handle the errors differently I guess.
     * TODO: find answer!
     */
#define ISSUE119YES
#ifdef ISSUE119NO
    unsigned char *hip=er->encoded+2;
    size_t hi_len=er->encoded_len-2;
#endif
#ifdef ISSUE119YES
    unsigned char *hip=er->encoded;
    size_t hi_len=er->encoded_len;
#endif

    EVP_MD_CTX *mctx = NULL;
    mctx = EVP_MD_CTX_new();
    ec->rd_len=EVP_MD_size(md);
    ec->rd=OPENSSL_malloc(ec->rd_len);
    if (ec->rd==NULL) {
        goto err;
    }
    if (mctx == NULL
            || EVP_DigestInit_ex(mctx, md, NULL) <= 0
            || EVP_DigestUpdate(mctx, hip, hi_len) <= 0
            || EVP_DigestFinal_ex(mctx, ec->rd, NULL) <= 0) {
        ESNIerr(ESNI_F_ENC, ERR_R_INTERNAL_ERROR);
        goto err;
    }
    EVP_MD_CTX_free(mctx);

    return 1;
err:
    return 0;
}

/*
 * Produce the encrypted SNI value for the CH
 */
int SSL_ESNI_enc(SSL_ESNI *esnikeys, 
                char *protectedserver, 
                char *frontname, 
                size_t  client_random_len,
                unsigned char *client_random,
                size_t  client_keyshare_len,
                unsigned char *client_keyshare,
                CLIENT_ESNI **the_esni)
{

    EVP_PKEY *skey = NULL; /* server public key */
    int ret = 0;
    EVP_PKEY_CTX *pctx=NULL;
    CLIENT_ESNI *cesni=NULL;
    /*
     * - make my private key
     * - generate shared secret
     * - encrypt protectedserver
     * - encode packet and return
     */
    if (esnikeys->client != NULL ) {
        ESNIerr(ESNI_F_ENC, ERR_R_INTERNAL_ERROR);
        goto err;
    }
    cesni=OPENSSL_zalloc(sizeof(CLIENT_ESNI));
    if (cesni==NULL) {
        ESNIerr(ESNI_F_ENC, ERR_R_MALLOC_FAILURE);
        goto err;
    }
    ESNI_CRYPTO_VARS *cv=&cesni->cvars;
    memset(cv,0,sizeof(ESNI_CRYPTO_VARS));
    CLIENT_ESNI_INNER *inner=&cesni->inner;

    /*
     * Copy into crypto var
     */
    cv->cr_len=client_random_len;
    cv->cr=OPENSSL_malloc(cv->cr_len);
    if (cv->cr == NULL ) {
        ESNIerr(ESNI_F_ENC, ERR_R_MALLOC_FAILURE);
        goto err;
    }
    memcpy(cv->cr,client_random,cv->cr_len);

    /*
     * D-H stuff inspired by openssl/statem/statem_clnt.c:tls_construct_cke_ecdhe
     */

    if (esnikeys->erecs==NULL) {
        ESNIerr(ESNI_F_ENC, ERR_R_INTERNAL_ERROR);
        goto err;
    }

    if (esnikeys->erecs->nkeys==0) {
        ESNIerr(ESNI_F_ENC, ERR_R_INTERNAL_ERROR);
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
        ESNIerr(ESNI_F_ENC, ERR_R_INTERNAL_ERROR);
        goto err;
    }

#ifdef CRYPT_INTEROP

    if (esnikeys->private_str==NULL) {
        cesni->cvars.keyshare = ssl_generate_pkey(skey);
        if (cesni->cvars.keyshare == NULL) {
            ESNIerr(ESNI_F_ENC, ERR_R_INTERNAL_ERROR);
            goto err;
        }
    } else {
        unsigned char binpriv[64];
        size_t bp_len=32;
        for (int i=0;i!=32;i++) {
            binpriv[i]=AH2B(esnikeys->private_str[2*i])*16+AH2B(esnikeys->private_str[(2*i)+1]);
        }
        so_esni_pbuf("CRYPTO_INTEROP  private",binpriv,bp_len,0);
    
        // const SSL_CIPHER *tsc=cesni->ciphersuite;
        int foo=EVP_PKEY_X25519;
        cesni->cvars.keyshare=EVP_PKEY_new_raw_private_key(foo,NULL,binpriv,bp_len);
        if (cesni->cvars.keyshare == NULL) {
            ESNIerr(ESNI_F_ENC, ERR_R_INTERNAL_ERROR);
            goto err;
        }
    }
#else
    // random new private
    cesni->cvars.keyshare = ssl_generate_pkey(skey);
    if (cesni->cvars.keyshare == NULL) {
        ESNIerr(ESNI_F_ENC, ERR_R_INTERNAL_ERROR);
        goto err;
    }
#endif

    /*
     * code from ssl/s3_lib.c:ssl_derive
     */
    pctx = EVP_PKEY_CTX_new(cesni->cvars.keyshare,NULL);
    if (EVP_PKEY_derive_init(pctx) <= 0 ) {
        ESNIerr(ESNI_F_ENC, ERR_R_INTERNAL_ERROR);
        goto err;
    }
    if (EVP_PKEY_derive_set_peer(pctx, skey) <= 0 ) {
        ESNIerr(ESNI_F_ENC, ERR_R_INTERNAL_ERROR);
        goto err;
    }
    int rv;
    if ((rv=EVP_PKEY_derive(pctx, NULL, &cesni->cvars.shared_len)) <= 0) {
        ESNIerr(ESNI_F_ENC, ERR_R_INTERNAL_ERROR);
        goto err;
    }
    cesni->cvars.shared = OPENSSL_malloc(cesni->cvars.shared_len);
    if (cesni->cvars.shared == NULL) {
        ESNIerr(ESNI_F_ENC, ERR_R_INTERNAL_ERROR);
        goto err;
    }
    if (EVP_PKEY_derive(pctx, cesni->cvars.shared, &cesni->cvars.shared_len) <= 0) {
        ESNIerr(ESNI_F_ENC, ERR_R_INTERNAL_ERROR);
        goto err;
    }

    /* 
     * Generate encoding of client key 
     * Gotta prepend the NamedGroup and overall length to that
     * TODO: find a better API that does that for me.
     */
    unsigned char *tmp=NULL;
    size_t tlen=0;
    tlen = EVP_PKEY_get1_tls_encodedpoint(cesni->cvars.keyshare,&tmp); 
    if (tlen == 0) {
        ESNIerr(ESNI_F_ENC, ERR_R_INTERNAL_ERROR);
        goto err;
    }
    cesni->encoded_keyshare_len = tlen+4;
    cesni->encoded_keyshare=OPENSSL_malloc(cesni->encoded_keyshare_len);
    cesni->encoded_keyshare[0]=0x00;
    cesni->encoded_keyshare[1]=0x1d;
    cesni->encoded_keyshare[2]=0x00;
    cesni->encoded_keyshare[3]=0x20;
    memcpy(cesni->encoded_keyshare+4,tmp,tlen);
    OPENSSL_free(tmp);

    /*
     * Form up the inner SNI stuff
     */
    inner->realSNI_len=esnikeys->mesni->padded_length;
    inner->realSNI=esni_pad(protectedserver,inner->realSNI_len);
    if (inner->realSNI==NULL) {
        ESNIerr(ESNI_F_ENC, ERR_R_INTERNAL_ERROR);
        goto err;
    }
    inner->nonce_len=16;
    inner->nonce=esni_nonce(inner->nonce_len);
    if (!inner->nonce) {
        ESNIerr(ESNI_F_ENC, ERR_R_INTERNAL_ERROR);
        goto err;
    }

    /*
     * encode into our plaintext
     */
    int oh=0; // TODO: check if it works - try remove these two bytes
    cv->plain_len=oh+inner->nonce_len+inner->realSNI_len;
    cv->plain=OPENSSL_malloc(cv->plain_len);
    if (cv->plain == NULL) {
        ESNIerr(ESNI_F_ENC, ERR_R_INTERNAL_ERROR);
        goto err;
    }
    unsigned char *pip=cv->plain;
    memcpy(pip,inner->nonce,inner->nonce_len); pip+=inner->nonce_len;
    // *pip++=inner->realSNI_len/256;
    // *pip++=inner->realSNI_len%256;
    memcpy(pip,inner->realSNI,inner->realSNI_len); pip+=inner->realSNI_len;

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
    ESNIContents *esnicontents=&cesni->econt;

    /*
     * Calculate digest of input RR as per I-D
     */
    esnicontents->kse_len=cesni->encoded_keyshare_len;
    esnicontents->kse=cesni->encoded_keyshare;
    esnicontents->cr_len=client_random_len;
    esnicontents->cr=client_random;
    if (!esni_make_rd(esnikeys->mesni,esnicontents)) {
        ESNIerr(ESNI_F_ENC, ERR_R_MALLOC_FAILURE);
        goto err;
    }

    if (esnicontents->rd_len>SSL_MAX_SSL_RECORD_DIGEST_LENGTH) {
        ESNIerr(ESNI_F_ENC, ERR_R_INTERNAL_ERROR);
        goto err;
    }
    cesni->record_digest_len=esnicontents->rd_len;
    memcpy(cesni->record_digest,esnicontents->rd,esnicontents->rd_len);

    /*
     * Form up input for hashing, and hash it
     */

    const SSL_CIPHER *sc=sk_SSL_CIPHER_value(esnikeys->mesni->ciphersuites,0);
    const EVP_MD *md=ssl_md(sc->algorithm2);
    if (!esni_contentshash(esnicontents,cv,md)) {
        ESNIerr(ESNI_F_ENC, ERR_R_INTERNAL_ERROR);
        goto err;
    }

    /*
     * Derive key and encrypt
     * encrypt the actual SNI based on shared key, Z - the I-D says:
     *    Zx = HKDF-Extract(0, Z)
     *    key = HKDF-Expand-Label(Zx, "esni key", Hash(ESNIContents), key_length)
     *    iv = HKDF-Expand-Label(Zx, "esni iv", Hash(ESNIContents), iv_length)
     */
    cv->Zx_len=0;
    cv->Zx=esni_hkdf_extract(cv->shared,cv->shared_len,&cv->Zx_len,md);
    if (cv->Zx==NULL) {
        ESNIerr(ESNI_F_ENC, ERR_R_INTERNAL_ERROR);
        goto err;
    }

    /* 
     * TODO: use proper API to derive key and IV lengths from suite
     */
    cv->key_len=16;
    cv->key=esni_hkdf_expand_label(cv->Zx,cv->Zx_len,"esni key",
                    cv->hash,cv->hash_len,&cv->key_len,md);
    if (cv->key==NULL) {
        ESNIerr(ESNI_F_ENC, ERR_R_INTERNAL_ERROR);
        goto err;
    }
    cv->iv_len=12;
    cv->iv=esni_hkdf_expand_label(cv->Zx,cv->Zx_len,"esni iv",
                    cv->hash,cv->hash_len,&cv->iv_len,md);
    if (cv->iv==NULL) {
        ESNIerr(ESNI_F_ENC, ERR_R_INTERNAL_ERROR);
        goto err;
    }

    /*
     * The actual encryption... from the I-D:
     *     encrypted_sni = AEAD-Encrypt(key, iv, ClientHello.KeyShareClientHello, ClientESNIInner)
     */

    /*
     * Copy the ClientHello.KeyShareClientHello in here as aad. 
     * TODO: find a better API that does that for me.
     */
    cv->aad_len=client_keyshare_len+6;
    cv->aad=OPENSSL_zalloc(cv->aad_len); 
    if (!cv->aad) {
        ESNIerr(ESNI_F_ENC, ERR_R_MALLOC_FAILURE);
        goto err;
    }
    cv->aad[0]=0x00;
    cv->aad[1]=0x24;
    cv->aad[2]=0x00;
    cv->aad[3]=0x1d;
    cv->aad[4]=0x00;
    cv->aad[5]=0x20;
    memcpy(cv->aad+6,client_keyshare,client_keyshare_len);

    /*
     * Tag is in ciphertext anyway, but sure may as well keep it
     */
    cv->tag_len=16;
    cv->tag=OPENSSL_malloc(cv->tag_len);
    if (cv->tag == NULL) {
        ESNIerr(ESNI_F_ENC, ERR_R_MALLOC_FAILURE);
        goto err;
    }

    cv->cipher=esni_aead_enc(cv->key, cv->key_len,
            cv->iv, cv->iv_len,
            cv->aad, cv->aad_len,
            cv->plain, cv->plain_len,
            cv->tag, cv->tag_len,
            &cv->cipher_len,
            cesni->ciphersuite);
    if (cv->cipher==NULL) {
        ESNIerr(ESNI_F_ENC, ERR_R_INTERNAL_ERROR);
        goto err;
    }

    if (cv->cipher_len>SSL_MAX_SSL_ENCRYPTED_SNI_LENGTH) {
        ESNIerr(ESNI_F_ENC, ERR_R_INTERNAL_ERROR);
        goto err;
    }
    cesni->encrypted_sni_len=cv->cipher_len;
    memcpy(cesni->encrypted_sni,cv->cipher,cv->cipher_len);

    /* 
     * finish up
     */
    esnikeys->client=cesni;
    EVP_PKEY_CTX_free(pctx);
    *the_esni=cesni;

    ret = 1;
    return(ret);
 err:
    OPENSSL_free(tmp);
    if (pctx!=NULL) EVP_PKEY_CTX_free(pctx);
    if (cesni!=NULL) {
        CLIENT_ESNI_free(cesni);
        OPENSSL_free(cesni);
    }
    return ret;
}

/*
* Check names for length, maybe add more checks later before starting...
*/
int esni_checknames(const char *encservername, const char *frontname)
{
    if (encservername != NULL && OPENSSL_strnlen(encservername,TLSEXT_MAXLEN_host_name)>TLSEXT_MAXLEN_host_name) 
        return(0);
    if (frontname != NULL && OPENSSL_strnlen(frontname,TLSEXT_MAXLEN_host_name)>TLSEXT_MAXLEN_host_name) 
        return(0);
    /*
     * Possible checks:
     * - If no covername, then send no (clear) SNI, so allow that
     * - Check same A/AAAA exists for both names, if we have both
     *       - could be a privacy leak though
     *       - even if using DoT/DoH (but how'd we know for sure?)
     * - check/retrive RR's from DNS if not already in-hand and
     *   if (sufficiently) privacy preserving
     */
    return(1);
}

/*
 * API so application (e.g. s_client) can deposit stuff it got from CLI
 */
int SSL_esni_enable(SSL *s, const char *hidden, const char *cover, SSL_ESNI *esni)
{
    if (s==NULL) {
        return 0;
    }
    if (s->ext.enchostname!=NULL) {
        OPENSSL_free(s->ext.enchostname);
    }
    if (hidden!=NULL ) {
        s->ext.enchostname=OPENSSL_strndup(hidden,TLSEXT_MAXLEN_host_name);
    }
    if (s->ext.hostname!=NULL) {
        OPENSSL_free(s->ext.hostname);
    }
    if (cover != NULL) {
        s->ext.hostname=OPENSSL_strndup(cover,TLSEXT_MAXLEN_host_name);
    }
    if (s->esni!=NULL) {
        SSL_ESNI_free(s->esni);
    }
    if (esni!=NULL) {
        s->esni=esni;
    }
    return 1;
}

/*
 * API for e.g. allowing s_client to print ESNI stuff
 */
void SSL_set_esni_callback(SSL *s, SSL_esni_client_cb_func f)
{
    s->esni_cb=f;
}

/*
 * API for access to esnistuff
 */
int SSL_ESNI_get_esni(SSL *s, SSL_ESNI **esni)
{
    if (s==NULL || esni==NULL) {
        return 0;
    }
    *esni=s->esni;
    return 1;
}

int SSL_ESNI_set_private(SSL_ESNI *esni, char *private)
{
#ifdef CRYPT_INTEROP
    esni->private_str=private;
#endif
    return 1;
}

int SSL_ESNI_set_nonce(SSL_ESNI *esni, unsigned char *nonce, size_t nlen)
{
#ifdef CRYPT_INTEROP
    lg_nonce=nonce;
    lg_nonce_len=nlen;
#endif
    return 1;
}

#endif


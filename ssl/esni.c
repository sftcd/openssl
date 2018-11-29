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
#ifdef ESNI_CRYPT_INTEROP
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
 * Free up an ENSI_RECORD
 */
void ESNI_RECORD_free(ESNI_RECORD *er)
{
    /* 
     * Don't free ciphersuites- they're copied over to SSL_ESNI and freed there
     */
    if (er==NULL) return;
    if (er->group_ids!=NULL) OPENSSL_free(er->group_ids);
    for (int i=0;i!=er->nkeys;i++) {
        EVP_PKEY *pk=er->keys[i];
        EVP_PKEY_free(pk);
        if (er->encoded_keys[i]!=NULL) OPENSSL_free(er->encoded_keys[i]);
    }
    if (er->keys!=NULL) OPENSSL_free(er->keys);
    for (int i=0;i!=er->nexts;i++) {
        if (er->exts[i]!=NULL) OPENSSL_free(er->exts[i]);
    }
    if (er->encoded_lens!=NULL) OPENSSL_free(er->encoded_lens);
    if (er->encoded_keys!=NULL) OPENSSL_free(er->encoded_keys);
    if (er->exts!=NULL) OPENSSL_free(er->exts);
    return;
}


/*
 * Free up an SSL_ESNI structure - note that we don't
 * free the top level
 */
void SSL_ESNI_free(SSL_ESNI *esni)
{
    if (esni==NULL) return;
    if (esni->encservername!=NULL) OPENSSL_free(esni->encservername);
    if (esni->covername!=NULL) OPENSSL_free(esni->covername);
    if (esni->encoded_rr!=NULL) OPENSSL_free(esni->encoded_rr);
    if (esni->rd!=NULL) OPENSSL_free(esni->rd);
    if (esni->ciphersuite!=NULL) {
        /*
         * Weirdly, I know how to free a stack of these, but not just one
         * So, we copied the stack from ESNI_RECORD
         */
        STACK_OF(SSL_CIPHER) *sk=esni->ciphersuites;
        sk_SSL_CIPHER_free(sk);
        esni->ciphersuite=NULL;
        esni->ciphersuites=NULL;
    }
    if (esni->esni_server_keyshare!=NULL) OPENSSL_free(esni->esni_server_keyshare);
    if (esni->esni_server_pkey!=NULL) EVP_PKEY_free(esni->esni_server_pkey);
    if (esni->nonce!=NULL) OPENSSL_free(esni->nonce);
    if (esni->hs_cr!=NULL) OPENSSL_free(esni->hs_cr);
    if (esni->hs_kse!=NULL) OPENSSL_free(esni->hs_kse);
    if (esni->keyshare) EVP_PKEY_free(esni->keyshare);
    if (esni->encoded_keyshare) OPENSSL_free(esni->encoded_keyshare);
    if (esni->hi!=NULL) OPENSSL_free(esni->hi);
    if (esni->hash!=NULL) OPENSSL_free(esni->hash);
    if (esni->Z!=NULL) OPENSSL_free(esni->Z);
    if (esni->Zx!=NULL) OPENSSL_free(esni->Zx);
    if (esni->key!=NULL) OPENSSL_free(esni->key);
    if (esni->iv!=NULL) OPENSSL_free(esni->iv);
    if (esni->aad!=NULL) OPENSSL_free(esni->aad);
    if (esni->plain!=NULL) OPENSSL_free(esni->plain);
    if (esni->cipher!=NULL) OPENSSL_free(esni->cipher);
    if (esni->tag!=NULL) OPENSSL_free(esni->tag);
    if (esni->realSNI!=NULL) OPENSSL_free(esni->realSNI);
#ifdef ESNI_CRYPT_INTEROP
    if (esni->private_str!=NULL) OPENSSL_free(esni->private_str);
#endif
    if (esni->the_esni!=NULL) OPENSSL_free(esni->the_esni); 
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
 * Hash the DNS RR as per the ciphersuite specified therein
 */
static unsigned char *esni_make_rd(const unsigned char *buf,const size_t blen, const EVP_MD *md, size_t *rd_len)
{
    /*
     * It seems that NSS uses the entire buffer, incl. the version, let's try
     * that. (Opened issue: https://github.com/tlswg/draft-ietf-tls-esni/issues/119)
     */
    EVP_MD_CTX *mctx = NULL;
    mctx = EVP_MD_CTX_new();
    size_t lc_rd_len=EVP_MD_size(md);
    unsigned char *rd=OPENSSL_malloc(lc_rd_len);
    if (rd==NULL) {
        goto err;
    }
    if (mctx == NULL
            || EVP_DigestInit_ex(mctx, md, NULL) <= 0
            || EVP_DigestUpdate(mctx, buf, blen) <= 0
            || EVP_DigestFinal_ex(mctx, rd, NULL) <= 0) {
        ESNIerr(ESNI_F_ENC, ERR_R_INTERNAL_ERROR);
        goto err;
    }
    EVP_MD_CTX_free(mctx);
    *rd_len=lc_rd_len;
    return rd;
err:
    return NULL;
}

/*
 * Put the outer length and curve ID around a key share.
 * This just exists because we do it twice: for the ESNI
 * client keyshare and for handshake client keyshare.
 * The input keyshare is the e.g. 32 octets of a point
 * on curve 25519 as used in X25519.
 */
static unsigned char *wrap_keyshare(
                const unsigned char *keyshare,
                const size_t keyshare_len,
                const uint16_t curve_id,
                size_t *outlen)
{
    if (outlen==NULL) {
        ESNIerr(ESNI_F_ENC, ERR_R_MALLOC_FAILURE);
        return NULL;
    }
    unsigned char *dest=NULL;
    size_t destlen=keyshare_len+6;
    dest=OPENSSL_zalloc(destlen);
    if (dest==NULL) {
        ESNIerr(ESNI_F_ENC, ERR_R_MALLOC_FAILURE);
        return NULL;
    }
    dest[0]=(keyshare_len+4)/256;;
    dest[1]=(keyshare_len+4)%256;;
    dest[2]=curve_id/256;
    dest[3]=curve_id%256;
    dest[4]=keyshare_len/256;;
    dest[5]=keyshare_len%256;;
    memcpy(dest+6,keyshare,keyshare_len);
    *outlen=destlen;
    return dest;
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
    if (esnikeys==NULL) {
        return(NULL);
    }
    ESNI_RECORD er;
    unsigned char *outbuf = NULL; /* binary representation of ESNIKeys */
    int declen; /* length of binary representation of ESNIKeys */
    SSL_ESNI *newesni=NULL; 
    memset(&er,0,sizeof(ESNI_RECORD));

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

    newesni->encoded_rr_len=declen;
    newesni->encoded_rr=outbuf;

    /* version */
    if (!PACKET_get_net_2(&pkt,&er.version)) {
        ESNIerr(ESNI_F_NEW_FROM_BASE64, ESNI_R_RR_DECODE_ERROR);
        goto err;
    }

    /* checksum decode */
    if (!PACKET_copy_bytes(&pkt,er.checksum,4)) {
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

    uint16_t group_id;
    PACKET encoded_pt;
    int nkeys=0;
    uint16_t *group_ids=NULL;
    EVP_PKEY **keys=NULL;
    unsigned char **encoded_keys=NULL;
    size_t *encoded_lens=NULL;

    while (PACKET_remaining(&key_share_list) > 0) {
        unsigned int tmp;
        if (!PACKET_get_net_2(&key_share_list, &tmp)
                || !PACKET_get_length_prefixed_2(&key_share_list, &encoded_pt)
                || PACKET_remaining(&encoded_pt) == 0) {
            ESNIerr(ESNI_F_NEW_FROM_BASE64, ESNI_R_RR_DECODE_ERROR);
            goto err;
        }
        if (tmp>0xffff) {
            ESNIerr(ESNI_F_NEW_FROM_BASE64, ESNI_R_RR_DECODE_ERROR);
            goto err;
        }
        group_id=(uint16_t)tmp;

        EVP_PKEY *kn=ssl_generate_param_group(group_id);
        if (kn==NULL) {
            ESNIerr(ESNI_F_NEW_FROM_BASE64, ESNI_R_RR_DECODE_ERROR);
            goto err;
        }
        /* stash encoded public value for later */
        size_t thislen=PACKET_remaining(&encoded_pt);
        unsigned char *thisencoded=NULL;
        thisencoded=OPENSSL_malloc(PACKET_remaining(&encoded_pt));
        if (thisencoded==NULL) {
            ESNIerr(ESNI_F_NEW_FROM_BASE64, ESNI_R_RR_DECODE_ERROR);
            goto err;
        }
        memcpy(thisencoded,PACKET_data(&encoded_pt),thislen);
        if (!EVP_PKEY_set1_tls_encodedpoint(kn,thisencoded,thislen)) {
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
        group_ids=(uint16_t*)OPENSSL_realloc(group_ids,nkeys*sizeof(uint16_t));
        if (group_ids == NULL ) {
            ESNIerr(ESNI_F_NEW_FROM_BASE64, ESNI_R_RR_DECODE_ERROR);
            goto err;
        }
        group_ids[nkeys-1]=group_id;
        encoded_lens=(size_t*)OPENSSL_realloc(encoded_lens,nkeys*sizeof(size_t));
        if (encoded_lens == NULL ) {
            ESNIerr(ESNI_F_NEW_FROM_BASE64, ESNI_R_RR_DECODE_ERROR);
            goto err;
        }
        encoded_lens[nkeys-1]=thislen;
        encoded_keys=(unsigned char **)OPENSSL_realloc(encoded_keys,nkeys*sizeof(unsigned char **));
        if (encoded_keys==NULL) {
            ESNIerr(ESNI_F_NEW_FROM_BASE64, ESNI_R_RR_DECODE_ERROR);
            goto err;
        }
        encoded_keys[nkeys-1]=thisencoded;

    }
    er.nkeys=nkeys;
    er.keys=keys;
    er.group_ids=group_ids;
    er.encoded_lens=encoded_lens;
    er.encoded_keys=encoded_keys;

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
    er.ciphersuites=sk;

    if (!PACKET_get_net_2(&pkt,&er.padded_length)) {
        ESNIerr(ESNI_F_NEW_FROM_BASE64, ESNI_R_RR_DECODE_ERROR);
        goto err;
    }
    /*
     * TODO: check bleedin not_before/not_after as if that's gonna help;-)
     */
    unsigned char nbs[8];
    if (!PACKET_copy_bytes(&pkt,nbs,8)) {
        ESNIerr(ESNI_F_NEW_FROM_BASE64, ESNI_R_RR_DECODE_ERROR);
        goto err;
    }
    er.not_before=uint64_from_bytes(nbs);
    if (!PACKET_copy_bytes(&pkt,nbs,8)) {
        ESNIerr(ESNI_F_NEW_FROM_BASE64, ESNI_R_RR_DECODE_ERROR);
        goto err;
    }
    er.not_after=uint64_from_bytes(nbs);
    /*
     * Extensions: we don't yet support any (does anyone?)
     * TODO: add extensions support at some level 
     */
    if (!PACKET_get_net_2(&pkt,&er.nexts)) {
        ESNIerr(ESNI_F_NEW_FROM_BASE64, ESNI_R_RR_DECODE_ERROR);
        goto err;
    }
    if (er.nexts != 0 ) {
        ESNIerr(ESNI_F_NEW_FROM_BASE64, ESNI_R_RR_DECODE_ERROR);
        goto err;

    }
    int leftover=PACKET_remaining(&pkt);
    if (leftover!=0) {
        ESNIerr(ESNI_F_NEW_FROM_BASE64, ESNI_R_RR_DECODE_ERROR);
        goto err;
    }

    /*
     * Fixed bits of RR to use
     */
    newesni->not_before=er.not_before;
    newesni->not_after=er.not_after;
    newesni->padded_length=er.padded_length;
    /* 
     * now decide which bits of er we like and remember those 
     * pick the 1st key/group/ciphersutie that works
     * TODO: more sophisticated selection:-)
     */
    int rec2pick=0;
    newesni->ciphersuite=sk_SSL_CIPHER_value(er.ciphersuites,rec2pick);
    newesni->ciphersuites=er.ciphersuites;
    newesni->group_id=er.group_ids[rec2pick];

    unsigned char *tmp=NULL;
    size_t tlen=0;

    newesni->esni_server_pkey=ssl_generate_param_group(newesni->group_id);
    if (newesni->esni_server_pkey==NULL) {
        ESNIerr(ESNI_F_ENC, ERR_R_INTERNAL_ERROR);
        goto err;
    }
    if (!EVP_PKEY_set1_tls_encodedpoint(newesni->esni_server_pkey,
                er.encoded_keys[rec2pick],er.encoded_lens[rec2pick])) {
            ESNIerr(ESNI_F_NEW_FROM_BASE64, ESNI_R_RR_DECODE_ERROR);
            goto err;
    }
    tlen = EVP_PKEY_get1_tls_encodedpoint(newesni->esni_server_pkey,&tmp); 
    if (tlen == 0) {
        ESNIerr(ESNI_F_ENC, ERR_R_INTERNAL_ERROR);
        goto err;
    }
    newesni->esni_server_keyshare=wrap_keyshare(tmp,tlen,newesni->group_id,&newesni->esni_server_keyshare_len);
    if (newesni->esni_server_keyshare==NULL) {
        ESNIerr(ESNI_F_ENC, ERR_R_INTERNAL_ERROR);
        goto err;
    }
    OPENSSL_free(tmp);

    const SSL_CIPHER *sc=newesni->ciphersuite;
    const EVP_MD *md=ssl_md(sc->algorithm2);
    newesni->rd=esni_make_rd(outbuf,declen,md,&newesni->rd_len);
    if (newesni->rd==NULL) {
        ESNIerr(ESNI_F_ENC, ERR_R_INTERNAL_ERROR);
        goto err;
    }
    /*
     * Free up unwanted stuff
     */
    ESNI_RECORD_free(&er);

    return(newesni);
err:
    ESNI_RECORD_free(&er);
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
    if (buf==NULL || blen==0) {
        BIO_printf(out,"OPENSSL: %s is NULL\n",msg);
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

#ifdef ESNI_CRYPT_INTEROP
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
    if (esni==NULL) {
        BIO_printf(out,"ESNI is NULL!\n");
        return 0;
    }
    if (esni->encoded_rr==NULL) {
        BIO_printf(out,"ESNI has no RRs!\n");
        return 0;
    } 
    esni_pbuf(out,"ESNI Encoded RR",esni->encoded_rr,esni->encoded_rr_len,indent);
    esni_pbuf(out,"ESNI DNS record_digest", esni->rd,esni->rd_len,indent);
    esni_pbuf(out,"ESNI Server KeyShare from DNS:",esni->esni_server_keyshare,esni->esni_server_keyshare_len,indent);
    BIO_printf(out,"ESNI Server groupd Id: %04x\n",esni->group_id);
    if (esni->ciphersuite!=NULL) {
        BIO_printf(out,"ESNI Server Ciphersuite is %s\n",esni->ciphersuite->name);
    } else {
        BIO_printf(out,"ENSI Server Ciphersuite is NULL\n");
    }
    BIO_printf(out,"ESNI Server padded_length: %zd\n",esni->padded_length);
    BIO_printf(out,"ESNI Server not_before: %ju\n",esni->not_before);
    BIO_printf(out,"ESNI Server not_after: %ju\n",esni->not_after);
    BIO_printf(out,"ESNI Server number of extensions: %d\n",esni->nexts);
    if (esni->nexts!=0) {
        BIO_printf(out,"\tOops - I don't support extensions but you have some. Bummer.\n");
    }
    esni_pbuf(out,"ESNI Nonce",esni->nonce,esni->nonce_len,indent);
    esni_pbuf(out,"ESNI H/S Client Random",esni->hs_cr,esni->hs_cr_len,indent);
    esni_pbuf(out,"ESNI H/S Client KeyShare",esni->hs_kse,esni->hs_kse_len,indent);
    if (esni->keyshare!=NULL) {
        BIO_printf(out,"ESNI Client ESNI KeyShare: ");
        EVP_PKEY_print_public(out, esni->keyshare, indent, NULL);
    } else {
        BIO_printf(out,"ESNI Client ESNI KeyShare is NULL ");
    }
    esni_pbuf(out,"ESNI Encoded ESNIContents (hash input)",esni->hi,esni->hi_len,indent);
    esni_pbuf(out,"ESNI Encoded ESNIContents (hash output)",esni->hash,esni->hash_len,indent);
    esni_pbuf(out,"ESNI Padded SNI",esni->realSNI, esni->realSNI_len, indent);
    BIO_printf(out,"ESNI Cryptovars group id: %04x\n",esni->group_id);
    esni_pbuf(out,"ESNI Cryptovars Z",esni->Z,esni->Z_len,indent);
    esni_pbuf(out,"ESNI Cryptovars Zx",esni->Zx,esni->Zx_len,indent);
    esni_pbuf(out,"ESNI Cryptovars key",esni->key,esni->key_len,indent);
    esni_pbuf(out,"ESNI Cryptovars iv",esni->iv,esni->iv_len,indent);
    esni_pbuf(out,"ESNI Cryptovars aad",esni->aad,esni->aad_len,indent);
    esni_pbuf(out,"ESNI Cryptovars plain",esni->plain,esni->plain_len,indent);
    esni_pbuf(out,"ESNI Cryptovars tag",esni->tag,esni->tag_len,indent);
    esni_pbuf(out,"ESNI Cryptovars cipher",esni->cipher,esni->cipher_len,indent);
    return(1);
}

/*
 * Make a 16 octet nonce for ESNI
 */
static unsigned char *esni_nonce(size_t nl)
{
#ifdef ESNI_CRYPT_INTEROP
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
    /*
     * This is a "dummy" SSL structure - the implementation of
     * tls13_hkdf_expand doesn't even refer to s except for an
     * error
     */
    SSL s;
    unsigned char *out=OPENSSL_malloc(*expanded_len);
    int rv=tls13_hkdf_expand(&s, md, Zx, 
                            (const unsigned char*)label, strlen(label),
                            hash, hash_len,
                            out, *expanded_len);
    if (rv!=1) {
        return NULL;
    }
    return out;
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

    if (SSL_CIPHER_is_aead(ciph)!=1) {
        ESNIerr(ESNI_F_ENC, ERR_R_INTERNAL_ERROR);
        goto err;
    }
    /*
     * We'll allocate this much extra for ciphertext and check the AEAD doesn't require more later
     * If it does, we'll fail.
     */
    size_t alloced_oh=64;

    ciphertext=OPENSSL_malloc(plain_len+alloced_oh);
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
    if (tag_len > alloced_oh) {
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


/*
 * Produce the encrypted SNI value for the CH
 */
int SSL_ESNI_enc(SSL_ESNI *esnikeys, 
                char *encservername, 
                char *covername, 
                size_t  client_random_len,
                unsigned char *client_random,
                uint16_t curve_id,
                size_t  client_keyshare_len,
                unsigned char *client_keyshare,
                CLIENT_ESNI **the_esni)
{
    int ret = 0;
    unsigned char *tmp=NULL;
    EVP_PKEY_CTX *pctx=NULL;

    /*
     * checking and copying
     */

    if (esnikeys->esni_server_pkey==NULL) {
        ESNIerr(ESNI_F_ENC, ERR_R_MALLOC_FAILURE);
        goto err;
    }
    if (esnikeys->hs_cr==NULL) {
        esnikeys->hs_cr_len=client_random_len;
        esnikeys->hs_cr=OPENSSL_malloc(esnikeys->hs_cr_len);
        if (esnikeys->hs_cr == NULL ) {
            ESNIerr(ESNI_F_ENC, ERR_R_MALLOC_FAILURE);
            goto err;
        }
        memcpy(esnikeys->hs_cr,client_random,esnikeys->hs_cr_len);
    }
    if (esnikeys->encservername==NULL) {
        esnikeys->encservername=OPENSSL_strdup(encservername);
        if (esnikeys->encservername==NULL) {
            ESNIerr(ESNI_F_ENC, ERR_R_MALLOC_FAILURE);
            goto err;
        }
    }
    if (esnikeys->covername==NULL && covername!=NULL) {
        esnikeys->covername=OPENSSL_strdup(covername);
        if (esnikeys->covername==NULL) {
            ESNIerr(ESNI_F_ENC, ERR_R_MALLOC_FAILURE);
            goto err;
        }
    }
    /*
     * We better have the right name set to do anything
     */
    if (esnikeys->encservername==NULL) {
        ESNIerr(ESNI_F_ENC, ERR_R_INTERNAL_ERROR);
        goto err;
    }
    /*
     * There is no point in doing this is SNI and ESNI payloads
     * are the same!!!
     */
    if (esnikeys->covername!=NULL && esnikeys->encservername!=NULL) {
        if (OPENSSL_strnlen(esnikeys->covername,TLSEXT_MAXLEN_host_name)==
            OPENSSL_strnlen(esnikeys->encservername,TLSEXT_MAXLEN_host_name)) {
            if (CRYPTO_memcmp(esnikeys->covername,esnikeys->encservername,
                OPENSSL_strnlen(esnikeys->covername,TLSEXT_MAXLEN_host_name))) {
                /*
                 * Shit - same names, that's silly
                 */
                ESNIerr(ESNI_F_ENC, ERR_R_INTERNAL_ERROR);
                goto err;
            }
        }
    }
    if (esnikeys->hs_kse==NULL) {
        esnikeys->hs_kse=OPENSSL_malloc(client_keyshare_len);
        if (esnikeys->hs_kse==NULL) {
            ESNIerr(ESNI_F_ENC, ERR_R_MALLOC_FAILURE);
            goto err;
        }
        memcpy(esnikeys->hs_kse,client_keyshare,client_keyshare_len);
        esnikeys->hs_kse_len=client_keyshare_len;
    }

    /*
     * - make my private key
     * - generate shared secret
     * - encrypt encservername
     * - encode packet and return
     */

    /* prepare nid and EVP versions for later checks */
    int cipher_nid = SSL_CIPHER_get_cipher_nid(esnikeys->ciphersuite);
    const EVP_CIPHER *e_ciph = EVP_get_cipherbynid(cipher_nid);
    if (e_ciph==NULL) {
        ESNIerr(ESNI_F_ENC, ERR_R_INTERNAL_ERROR);
        goto err;
    }

#ifdef ESNI_CRYPT_INTEROP

    if (esnikeys->private_str==NULL) {
        esnikeys->keyshare = ssl_generate_pkey(esnikeys->esni_server_pkey);
        if (esnikeys->keyshare == NULL) {
            ESNIerr(ESNI_F_ENC, ERR_R_INTERNAL_ERROR);
            goto err;
        }
    } else {
        /*
         * fixed sizes are ok here - it's just for NSS interop
         */
        unsigned char binpriv[64];
        size_t bp_len=32;
        for (int i=0;i!=32;i++) {
            binpriv[i]=AH2B(esnikeys->private_str[2*i])*16+AH2B(esnikeys->private_str[(2*i)+1]);
        }
        so_esni_pbuf("CRYPTO_INTEROP  private",binpriv,bp_len,0);
    
        int foo=EVP_PKEY_X25519;
        esnikeys->keyshare=EVP_PKEY_new_raw_private_key(foo,NULL,binpriv,bp_len);
        if (esnikeys->keyshare == NULL) {
            ESNIerr(ESNI_F_ENC, ERR_R_INTERNAL_ERROR);
            goto err;
        }
    }
#else
    // random new private
    esnikeys->keyshare = ssl_generate_pkey(esnikeys->esni_server_pkey);
    if (esnikeys->keyshare == NULL) {
        ESNIerr(ESNI_F_ENC, ERR_R_INTERNAL_ERROR);
        goto err;
    }
#endif

    pctx = EVP_PKEY_CTX_new(esnikeys->keyshare,NULL);
    if (EVP_PKEY_derive_init(pctx) <= 0 ) {
        ESNIerr(ESNI_F_ENC, ERR_R_INTERNAL_ERROR);
        goto err;
    }
    if (EVP_PKEY_derive_set_peer(pctx, esnikeys->esni_server_pkey) <= 0 ) {
        ESNIerr(ESNI_F_ENC, ERR_R_INTERNAL_ERROR);
        goto err;
    }
    int rv;
    if ((rv=EVP_PKEY_derive(pctx, NULL, &esnikeys->Z_len)) <= 0) {
        ESNIerr(ESNI_F_ENC, ERR_R_INTERNAL_ERROR);
        goto err;
    }
    esnikeys->Z=OPENSSL_malloc(esnikeys->Z_len);
    if (esnikeys->Z == NULL) {
        ESNIerr(ESNI_F_ENC, ERR_R_INTERNAL_ERROR);
        goto err;
    }
    if (EVP_PKEY_derive(pctx, esnikeys->Z, &esnikeys->Z_len) <= 0) {
        ESNIerr(ESNI_F_ENC, ERR_R_INTERNAL_ERROR);
        goto err;
    }

    /* 
     * encode up my own keyshare for inclusion in ESNIContents
     */
    size_t tlen=0;
    tlen = EVP_PKEY_get1_tls_encodedpoint(esnikeys->keyshare,&tmp); 
    if (tlen == 0) {
        ESNIerr(ESNI_F_ENC, ERR_R_INTERNAL_ERROR);
        goto err;
    }
    esnikeys->encoded_keyshare=wrap_keyshare(tmp,tlen,esnikeys->group_id,&esnikeys->encoded_keyshare_len);
    if (esnikeys->encoded_keyshare==NULL) {
        OPENSSL_free(tmp);
        ESNIerr(ESNI_F_ENC, ERR_R_INTERNAL_ERROR);
        goto err;
    }
    OPENSSL_free(tmp);

    // drop top two bytes from this version of encoded_keyshare (sigh!)
    esnikeys->hi_len=2+esnikeys->rd_len+esnikeys->encoded_keyshare_len-2+esnikeys->hs_cr_len;
    esnikeys->hi=OPENSSL_malloc(esnikeys->hi_len);
    if (esnikeys->hi==NULL) {
        ESNIerr(ESNI_F_ENC, ERR_R_INTERNAL_ERROR);
        goto err;
    }
    unsigned char *ecp=esnikeys->hi;
    *ecp++=esnikeys->rd_len/256;
    *ecp++=esnikeys->rd_len%256;
    memcpy(ecp,esnikeys->rd,esnikeys->rd_len);ecp+=esnikeys->rd_len;
    memcpy(ecp,esnikeys->encoded_keyshare+2,esnikeys->encoded_keyshare_len-2);ecp+=esnikeys->encoded_keyshare_len-2;
    memcpy(ecp,esnikeys->hs_cr,esnikeys->hs_cr_len);ecp+=esnikeys->hs_cr_len;

    /*
     * Form up the inner SNI stuff
     */
    esnikeys->realSNI_len=esnikeys->padded_length;
    esnikeys->realSNI=esni_pad(esnikeys->encservername,esnikeys->realSNI_len);
    if (esnikeys->realSNI==NULL) {
        ESNIerr(ESNI_F_ENC, ERR_R_INTERNAL_ERROR);
        goto err;
    }
    esnikeys->nonce_len=16;
    esnikeys->nonce=esni_nonce(esnikeys->nonce_len);
    if (!esnikeys->nonce) {
        ESNIerr(ESNI_F_ENC, ERR_R_INTERNAL_ERROR);
        goto err;
    }

    /*
     * encode into our plaintext
     */
    esnikeys->plain_len=esnikeys->nonce_len+esnikeys->realSNI_len;
    esnikeys->plain=OPENSSL_malloc(esnikeys->plain_len);
    if (esnikeys->plain == NULL) {
        ESNIerr(ESNI_F_ENC, ERR_R_INTERNAL_ERROR);
        goto err;
    }
    unsigned char *pip=esnikeys->plain;
    memcpy(pip,esnikeys->nonce,esnikeys->nonce_len); pip+=esnikeys->nonce_len;
    memcpy(pip,esnikeys->realSNI,esnikeys->realSNI_len); pip+=esnikeys->realSNI_len;

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

    /*
     * Form up input for hashing, and hash it
     */
    const SSL_CIPHER *sc=esnikeys->ciphersuite;
    const EVP_MD *md=ssl_md(sc->algorithm2);
    EVP_MD_CTX *mctx = NULL;
    mctx = EVP_MD_CTX_new();
    esnikeys->hash_len = EVP_MD_size(md);
    esnikeys->hash=OPENSSL_malloc(esnikeys->hash_len);
    if (esnikeys->hash==NULL) {
        goto err;
    }
    if (mctx == NULL
            || EVP_DigestInit_ex(mctx, md, NULL) <= 0
            || EVP_DigestUpdate(mctx, esnikeys->hi, esnikeys->hi_len) <= 0
            || EVP_DigestFinal_ex(mctx, esnikeys->hash, NULL) <= 0) {
        ESNIerr(ESNI_F_ENC, ERR_R_INTERNAL_ERROR);
        goto err;
    }
    EVP_MD_CTX_free(mctx);

    /*
     * Derive key and encrypt
     * encrypt the actual SNI based on shared key, Z - the I-D says:
     *    Zx = HKDF-Extract(0, Z)
     *    key = HKDF-Expand-Label(Zx, "esni key", Hash(ESNIContents), key_length)
     *    iv = HKDF-Expand-Label(Zx, "esni iv", Hash(ESNIContents), iv_length)
     */
    esnikeys->Zx_len=0;
    esnikeys->Zx=esni_hkdf_extract(esnikeys->Z,esnikeys->Z_len,&esnikeys->Zx_len,md);
    if (esnikeys->Zx==NULL) {
        ESNIerr(ESNI_F_ENC, ERR_R_INTERNAL_ERROR);
        goto err;
    }

    /* 
     * derive key and iv length from suite
     */

    esnikeys->key_len=EVP_CIPHER_key_length(e_ciph);
    esnikeys->key=esni_hkdf_expand_label(esnikeys->Zx,esnikeys->Zx_len,"esni key",
                    esnikeys->hash,esnikeys->hash_len,&esnikeys->key_len,md);
    if (esnikeys->key==NULL) {
        ESNIerr(ESNI_F_ENC, ERR_R_INTERNAL_ERROR);
        goto err;
    }
    esnikeys->iv_len=EVP_CIPHER_iv_length(e_ciph);
    esnikeys->iv=esni_hkdf_expand_label(esnikeys->Zx,esnikeys->Zx_len,"esni iv",
                    esnikeys->hash,esnikeys->hash_len,&esnikeys->iv_len,md);
    if (esnikeys->iv==NULL) {
        ESNIerr(ESNI_F_ENC, ERR_R_INTERNAL_ERROR);
        goto err;
    }

    /*
     * The actual encryption... from the I-D:
     *     encrypted_sni = AEAD-Encrypt(key, iv, ClientHello.KeyShareClientHello, ClientESNIInner)
     */

    /*
     * Put a few encoding bytes around the TLS h/s key share
     */
    esnikeys->aad=wrap_keyshare(esnikeys->hs_kse,esnikeys->hs_kse_len,curve_id,&esnikeys->aad_len);
    if (esnikeys->aad==NULL) {
        ESNIerr(ESNI_F_ENC, ERR_R_MALLOC_FAILURE);
        goto err;
    }

    /*
     * Tag is in ciphertext anyway, but sure may as well keep it
     */
    esnikeys->tag_len=EVP_GCM_TLS_TAG_LEN;
    esnikeys->tag=OPENSSL_malloc(esnikeys->tag_len);
    if (esnikeys->tag == NULL) {
        ESNIerr(ESNI_F_ENC, ERR_R_MALLOC_FAILURE);
        goto err;
    }

    esnikeys->cipher=esni_aead_enc(esnikeys->key, esnikeys->key_len,
            esnikeys->iv, esnikeys->iv_len,
            esnikeys->aad, esnikeys->aad_len,
            esnikeys->plain, esnikeys->plain_len,
            esnikeys->tag, esnikeys->tag_len,
            &esnikeys->cipher_len,
            esnikeys->ciphersuite);
    if (esnikeys->cipher==NULL) {
        ESNIerr(ESNI_F_ENC, ERR_R_INTERNAL_ERROR);
        goto err;
    }

    if (esnikeys->cipher_len>SSL_MAX_SSL_ENCRYPTED_SNI_LENGTH) {
        ESNIerr(ESNI_F_ENC, ERR_R_INTERNAL_ERROR);
        goto err;
    }
    EVP_PKEY_CTX_free(pctx);

    /* 
     * finish up
     */

    CLIENT_ESNI *tc=OPENSSL_malloc(sizeof(CLIENT_ESNI));
    if (tc==NULL) {
        ESNIerr(ESNI_F_ENC, ERR_R_INTERNAL_ERROR);
        goto err;
    }
    tc->ciphersuite=esnikeys->ciphersuite;
    tc->encoded_keyshare=esnikeys->encoded_keyshare;
    tc->encoded_keyshare_len=esnikeys->encoded_keyshare_len;
    tc->record_digest=esnikeys->rd;
    tc->record_digest_len=esnikeys->rd_len;
    tc->encrypted_sni=esnikeys->cipher;
    tc->encrypted_sni_len=esnikeys->cipher_len;
    *the_esni=tc;
    esnikeys->the_esni=tc;

    ret = 1;
    return(ret);
 err:
    if (tmp!=NULL) OPENSSL_free(tmp);
    if (pctx!=NULL) EVP_PKEY_CTX_free(pctx);
    return ret;
}

/*
* Check names for length, maybe add more checks later before starting...
*/
int SSL_esni_checknames(const char *encservername, const char *covername)
{
    int elen=0;
    int flen=0;
    if (encservername==NULL) {
        /*
         * Makes no sense
         */
        return 0;
    }
    elen=strlen(encservername);
    if (covername!=NULL) {
        flen=strlen(covername);
    }
    if (elen >= TLSEXT_MAXLEN_host_name) {
        return(0);
    }
    if (flen >= TLSEXT_MAXLEN_host_name) {
        return(0);
    }
    if (elen==flen && !strncmp(encservername,covername,elen)) {
        /*
         * Silly!
         */
        return(0);
    }
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
    if (s->ext.encservername!=NULL) {
        OPENSSL_free(s->ext.encservername);
		s->ext.encservername=NULL;
    }
    if (hidden!=NULL ) {
        s->ext.encservername=OPENSSL_strndup(hidden,TLSEXT_MAXLEN_host_name);
    }
    if (s->ext.hostname!=NULL) {
        OPENSSL_free(s->ext.hostname);
		s->ext.hostname=NULL;
    }
    if (cover != NULL && s->ext.covername!=NULL) {
        OPENSSL_free(s->ext.covername);
		s->ext.covername=NULL;
    }
    if (cover != NULL) {
        s->ext.hostname=OPENSSL_strndup(cover,TLSEXT_MAXLEN_host_name);
        s->ext.covername=OPENSSL_strndup(cover,TLSEXT_MAXLEN_host_name);
    }
    if (s->esni!=NULL) {
        SSL_ESNI_free(s->esni);
    }
    if (esni!=NULL) {
        s->esni=esni;
    }
    /*
     * Set to 1 when nonce returned
     * Checked for 0 when final_esni called
     */
    s->esni_done=0;
    return 1;
}


/*
 * API t allow calling code know ESNI outcome, post-handshake
 */
int SSL_get_esni_status(SSL *s, char **cover, char **hidden)
{
    if (cover==NULL || hidden==NULL) {
        return SSL_ESNI_BAD_STATUS_CALL;
    }
    *cover=NULL;
    *hidden=NULL;
    if (s->esni!=NULL) {
        *hidden=s->esni->encservername;
        *cover=s->esni->covername;
        if (s->esni_done==1) {
            return SSL_ESNI_STATUS_SUCCESS;
        } else {
            return SSL_ESNI_STATUS_FAILED;
        }
    } 
    return SSL_ESNI_STATUS_NOT_TRIED;
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
#ifdef ESNI_CRYPT_INTEROP
    esni->private_str=private;
#endif
    return 1;
}

int SSL_ESNI_set_nonce(SSL_ESNI *esni, unsigned char *nonce, size_t nlen)
{
#ifdef ESNI_CRYPT_INTEROP
    lg_nonce=nonce;
    lg_nonce_len=nlen;
#endif
    return 1;
}

#endif


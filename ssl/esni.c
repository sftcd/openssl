/*
 * Copyright 2018 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the OpenSSL license (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

/**
 * File: esni.c - the core implementation of drat-ietf-tls-esni-02
 * Author: stephen.farrell@cs.tcd.ie
 * Date: 2018 December-ish
 */

#include <ctype.h>
#include "ssl_locl.h"
#include <openssl/ssl.h>
#include <openssl/rand.h>
#include <openssl/kdf.h>
#include <openssl/evp.h>
#include <openssl/esni.h>
#include <openssl/esnierr.h>

#ifndef OPENSSL_NO_ESNI

/*
 * Purely debug
 */
#ifdef ESNI_CRYPT_INTEROP
unsigned char *lg_nonce=NULL;
size_t lg_nonce_len=0;
static void so_esni_pbuf(char *msg,unsigned char *buf,size_t blen,int indent);
#endif


/**
 * Handle padding - the server needs to do padding in case the
 * certificate/key-size exposes the ESNI. But so can lots of 
 * the other application interactions, so to be at least a bit
 * cautious, we'll also pad the crap out of everything on the
 * client side (at least to see what happens:-)
 * This could be over-ridden by the client appication if it
 * wants by setting a callback via SSL_set_record_padding_callback
 * We'll try set to 486 bytes, so that 3 plaintexts are likely
 * to fit in a 1500 byte MTU. (That's a pretty arbitrary
 * decision:-)
 * TODO: test and see how this padding affects a real application
 * as soon as we've integrated with one
*/
#define ESNI_DEFAULT_PADDED 486  ///< We'll pad all TLS plaintext to this size

/*
 * Utility functions
 */

/**
 * @brief map 8 bytes in n/w byte order from PACKET to a 64-bit time value
 *
 * @todo TODO: there must be code for this somewhere - find it
 * 
 * @param buf is a bit of the PACKET with the 8 octets of interest
 * @return is the 64 bit value from those 8 octets
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

/**
 * @brief decode ascii hex to a binary buffer
 *
 * @todo TODO: there should be an OPENSSL_* function somewhere for this I guess - find it
 * This assumes string is correctly ascii hex encoded
 *
 * @param ahlen is the ascii hex string length
 * @param ahstr is the ascii hex string
 * @param blen is a pointer to the returned binary length
 * @param buf is a pointer to the internally allocated binary buffer
 * @return zero for error, 1 for success 
 */
static int ah_decode(size_t ahlen, const char *ah, size_t *blen, unsigned char **buf)
{
    size_t lblen=0;
    unsigned char *lbuf=NULL;
    if (ahlen <=0 || ah==NULL || blen==NULL || buf==NULL) {
        return 0;
    }
    if (ahlen%1) {
        return 0;
    }
    lblen=ahlen/2;
    lbuf=OPENSSL_malloc(lblen);
    if (lbuf==NULL) {
        return 0;
    }
    for (int i=0;i!=lblen;i++) {
        lbuf[i]=A2B(ah[2*i])*16+A2B(ah[2*i+1]);
    }
    *blen=lblen;
    *buf=lbuf;
    return 1;
}

/**
 * @brief Decode from TXT RR to binary buffer
 *
 * This was the same as ct_base64_decode from crypto/ct/ct_b64.c
 * which function is declared static but could otherwise
 * have been be re-used. Returns -1 for error or length of decoded
 * buffer length otherwise (wasn't clear to me at first
 * glance). Possible future change: re-use the ct code by
 * exporting it.
 * With draft-03, we're extending to allow a set of 
 * semi-colon separated strings as the input to handle
 * multivalued RRs.
 *
 * Decodes the base64 string |in| into |out|.
 * A new string will be malloc'd and assigned to |out|. This will be owned by
 * the caller. Do not provide a pre-allocated string in |out|.
 * The input is modified if multivalued (NULL bytes are added in 
 * place of semi-colon separators.
 *
 * @param in is the base64 encoded string
 * @param out is the binary equivalent
 * @return is the number of octets in |out| if successful, <=0 for failure
 */
static int esni_base64_decode(char *in, unsigned char **out)
{
    const char* sepstr=";";
    size_t inlen = strlen(in);
    int i=0;
    int outlen=0;
    unsigned char *outbuf = NULL;
    int overallfraglen=0;

    if (out == NULL) {
        return 0;
    }
    if (inlen == 0) {
        *out = NULL;
        return 0;
    }

    /*
     * overestimate of space but easier than base64 finding padding right now
     */
    outbuf = OPENSSL_malloc(inlen);
    if (outbuf == NULL) {
        ESNIerr(ESNI_F_ESNI_BASE64_DECODE, ERR_R_MALLOC_FAILURE);
        goto err;
    }

    char *inp=in;
    unsigned char *outp=outbuf;

    while (overallfraglen<inlen) {

        /* find length of 1st b64 string */
        int ofraglen=0;
        int thisfraglen=strcspn(inp,sepstr);
        inp[thisfraglen]='\0';
        overallfraglen+=(thisfraglen+1);

        ofraglen = EVP_DecodeBlock(outp, (unsigned char *)inp, thisfraglen);
        if (ofraglen < 0) {
            ESNIerr(ESNI_F_ESNI_BASE64_DECODE, ESNI_R_BASE64_DECODE_ERROR);
            goto err;
        }

        /* Subtract padding bytes from |outlen|.  Any more than 2 is malformed. */
        i = 0;
        while (inp[thisfraglen-i-1] == '=') {
            if (++i > 2) {
                ESNIerr(ESNI_F_ESNI_BASE64_DECODE, ESNI_R_BASE64_DECODE_ERROR);
                goto err;
            }
        }
        outp+=(ofraglen-i);
        outlen+=(ofraglen-i);
        inp+=(thisfraglen+1);

    }

    *out = outbuf;
    return outlen;
err:
    OPENSSL_free(outbuf);
    ESNIerr(ESNI_F_ESNI_BASE64_DECODE, ESNI_R_BASE64_DECODE_ERROR);
    return -1;
}

static const SSL_CIPHER *cs2sc(uint16_t ciphersuite)
{
    const SSL_CIPHER *new;
    unsigned char encoding[2];
    encoding[0]=ciphersuite/256;
    encoding[1]=ciphersuite%256;
    new=ssl3_get_cipher_by_char(encoding);
    return new;
}

/**
 * @brief Free up an ENSI_RECORD 
 *
 * ESNI_RECORD is our struct for what's in the DNS
 * 
 * @wparam er is a pointer to the record
 */
void ESNI_RECORD_free(ESNI_RECORD *er)
{
    int i; /* loop counter - android build doesn't like C99;-( */
    if (er==NULL) return;
    if (er->group_ids!=NULL) OPENSSL_free(er->group_ids);
    if (er->public_name!=NULL) OPENSSL_free(er->public_name);
    for (i=0;i!=er->nkeys;i++) {
        EVP_PKEY *pk=er->keys[i];
        EVP_PKEY_free(pk);
        if (er->encoded_keys[i]!=NULL) OPENSSL_free(er->encoded_keys[i]);
    }
    if (er->keys!=NULL) OPENSSL_free(er->keys);

#ifdef DEEP_COPY_EXTS
    /*
     * Extension-related values were shallow copied to above so don't free here
     */
    for (i=0;i!=er->nexts;i++) {
        if (er->exts && er->exts[i]!=NULL) OPENSSL_free(er->exts[i]);
    }
    if (er->exts!=NULL) OPENSSL_free(er->exts);
    if (er->exttypes!=NULL) OPENSSL_free(er->exttypes);
    if (er->extlens!=NULL) OPENSSL_free(er->extlens);
#endif

    if (er->ciphersuites!=NULL) OPENSSL_free(er->ciphersuites);
    if (er->encoded_lens!=NULL) OPENSSL_free(er->encoded_lens);
    if (er->encoded_keys!=NULL) OPENSSL_free(er->encoded_keys);
    return;
}


/**
 * Free up an SSL_ESNI structure 
 *
 * Note that we don't free the top level, caller should do that
 * This will free the CLIENT_ESNI structure contained in here.
 *
 * @param esni a ptr to an SSL_ESNI str
 */
void SSL_ESNI_free(SSL_ESNI *deadesni)
{
    for (int i=0;i!=deadesni->num_esni_rrs;i++) {
        SSL_ESNI *esni=&deadesni[i];
        if (esni==NULL) return;
        if (esni->the_esni) {
            /*
             * The CLIENT_ESNI structure (the_esni) doesn't have separately
             * allocated buffers on the client, but it does on the server.
             * So we check if they're pointers to other SSL_ESNI fields 
             * or need to be freed
             */
            CLIENT_ESNI *ce=esni->the_esni;
            if (ce->encoded_keyshare!= NULL && ce->encoded_keyshare!=esni->encoded_keyshare) OPENSSL_free(ce->encoded_keyshare);
            if (ce->record_digest != NULL && ce->record_digest!=esni->rd) OPENSSL_free(ce->record_digest);
            if (ce->encrypted_sni != NULL && ce->encrypted_sni!=esni->cipher) OPENSSL_free(ce->encrypted_sni);
        }
        if (esni->encservername!=NULL) OPENSSL_free(esni->encservername);
        if (esni->covername!=NULL) OPENSSL_free(esni->covername);
        if (esni->public_name!=NULL) OPENSSL_free(esni->public_name);
        if (esni->encoded_rr!=NULL) OPENSSL_free(esni->encoded_rr);
        if (esni->rd!=NULL) OPENSSL_free(esni->rd);
        if (esni->esni_peer_keyshare!=NULL) OPENSSL_free(esni->esni_peer_keyshare);
        if (esni->esni_peer_pkey!=NULL) EVP_PKEY_free(esni->esni_peer_pkey);
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
        /* the buffers below here were freed above if needed */
        if (esni->the_esni!=NULL) OPENSSL_free(esni->the_esni); 
        if (esni->nexts!=0) {
            int j=0;
            for (j=0;j!=esni->nexts;j++) {
                if (esni->exts && esni->exts[j]!=NULL) OPENSSL_free(esni->exts[j]);
            }
            if (esni->exts!=NULL) OPENSSL_free(esni->exts);
            if (esni->exttypes!=NULL) OPENSSL_free(esni->exttypes);
            if (esni->extlens!=NULL) OPENSSL_free(esni->extlens);
        }
    }
    return;
}

/**
 * @brief Verify the SHA256 checksum that should be in the DNS record
 *
 * Fixed SHA256 hash in this case, we work on the offset here,
 * (bytes 2 bytes then 4 checksum bytes then rest) with no other 
 * knowledge of the encoding.
 *
 * @param buf is the buffer
 * @param buf_len is obvous
 * @return 1 for success, not 1 otherwise
 */
static int esni_checksum_check(unsigned char *buf, size_t buf_len)
{
    /* 
     * copy input with zero'd checksum, do SHA256 hash, compare with checksum, tedious but easy enough
     */
    unsigned char *buf_zeros=NULL;
    /*
     * Length has to be >6 to fit version and checksum
     */
    if (buf==NULL || buf_len <= 6 || buf_len >= ESNI_MAX_RRVALUE_LEN ) {
        ESNIerr(ESNI_F_ESNI_CHECKSUM_CHECK, ERR_R_MALLOC_FAILURE);
        goto err;
    }
    buf_zeros=OPENSSL_malloc(buf_len);
    if (buf_zeros==NULL) {
        ESNIerr(ESNI_F_ESNI_CHECKSUM_CHECK, ERR_R_MALLOC_FAILURE);
        goto err;
    }
    memcpy(buf_zeros,buf,buf_len);
    memset(buf_zeros+2,0,4);
    unsigned char md[EVP_MAX_MD_SIZE];
    SHA256_CTX context;
    if(!SHA256_Init(&context)) {
        ESNIerr(ESNI_F_ESNI_CHECKSUM_CHECK, ERR_R_INTERNAL_ERROR);
        goto err;
    }
    if(!SHA256_Update(&context, buf_zeros, buf_len)) {
        ESNIerr(ESNI_F_ESNI_CHECKSUM_CHECK, ERR_R_INTERNAL_ERROR);
        goto err;
    }
    if(!SHA256_Final(md, &context)) {
        ESNIerr(ESNI_F_ESNI_CHECKSUM_CHECK, ERR_R_INTERNAL_ERROR);
        goto err;
    }
    OPENSSL_free(buf_zeros);
    if (CRYPTO_memcmp(buf+2,md,4)) {
        /* non match - bummer */
        return 0;
    } else {
        return 1;
    }
err:
    if (buf_zeros!=NULL) OPENSSL_free(buf_zeros);
    return 0;
}

/**
 * @brief Hash the buffer as per the ciphersuite specified therein
 *
 * Note that this isn't quite what the I-D says - It seems that NSS uses the 
 * entire buffer, incl. the version, so I've also done that as it works!
 * Opened issue: https://github.com/tlswg/draft-ietf-tls-esni/issues/119
 *
 * @param buf is the input buffer
 * @param blen is the input buffer length
 * @param md is the hash function
 * @param rd_len is (a ptr to) the output hash length
 * @return a pointer to the hash buffer allocated within the function or NULL on error
 */
static unsigned char *esni_make_rd(const unsigned char *buf,const size_t blen, const EVP_MD *md, size_t *rd_len)
{
    /*
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
        ESNIerr(ESNI_F_ESNI_MAKE_RD, ERR_R_INTERNAL_ERROR);
        goto err;
    }
    EVP_MD_CTX_free(mctx);
    *rd_len=lc_rd_len;
    return rd;
err:
    return NULL;
}

/**
 * @brief wrap a "raw" key share in the relevant TLS presentation layer encoding
 *
 * Put the outer length and curve ID around a key share.
 * This just exists because we do it twice: for the ESNI
 * client keyshare and for handshake client keyshare.
 * The input keyshare is the e.g. 32 octets of a point
 * on curve 25519 as used in X25519.
 * There's no magic here, it's just that this code recurs
 * in handling ESNI. Theere might be some existing API to
 * use that'd be better.
 *
 * @param keyshare is the input keyshare which'd be 32 octets for x25519
 * @param keyshare_len is the length of the above (0x20 for x25519)
 * @param curve_id is the IANA registered value for the curve e.g. 0x1d for X25519
 * @param outlen is the length of the encoded version of the above
 * @return is NULL (on error) or a pointer to the encoded version buffer
 */
unsigned char *SSL_ESNI_wrap_keyshare(
                const unsigned char *keyshare,
                const size_t keyshare_len,
                const uint16_t curve_id,
                size_t *outlen)

{
    if (outlen==NULL) {
        ESNIerr(ESNI_F_SSL_ESNI_WRAP_KEYSHARE, ERR_R_MALLOC_FAILURE);
        return NULL;
    }
    unsigned char *dest=NULL;
    size_t destlen=keyshare_len+6;
    dest=OPENSSL_zalloc(destlen);
    if (dest==NULL) {
        ESNIerr(ESNI_F_SSL_ESNI_WRAP_KEYSHARE, ERR_R_MALLOC_FAILURE);
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

/**
 * @brief Decode from binary to ESNI_RECORD
 *
 * @param binbuf is the buffer with the encoding
 * @param binblen is the length of binbunf
 * @param leftover is the number of unused octets from the input
 * @return NULL on error, or an ESNI_RECORD structure 
 */
static ESNI_RECORD *SSL_ESNI_RECORD_new_from_binary(unsigned char *binbuf, size_t binblen, int *leftover)
{
    ESNI_RECORD *er=NULL;

    if (leftover==NULL) {
        ESNIerr(ESNI_F_SSL_ESNI_RECORD_NEW_FROM_BINARY, ERR_R_INTERNAL_ERROR);
        goto err;
    }

    er=(ESNI_RECORD*)OPENSSL_malloc(sizeof(ESNI_RECORD));
    if (er==NULL) {
        ESNIerr(ESNI_F_SSL_ESNI_RECORD_NEW_FROM_BINARY, ERR_R_INTERNAL_ERROR);
        goto err;
    }
    memset(er,0,sizeof(ESNI_RECORD));

    PACKET pkt={binbuf,binblen};
    /* sanity check: version + checksum + KeyShareEntry have to be there - min len >= 10 */
    if (binblen < 10) {
        ESNIerr(ESNI_F_SSL_ESNI_RECORD_NEW_FROM_BINARY, ESNI_R_BASE64_DECODE_ERROR);
        goto err;
    }
    /* version */
    if (!PACKET_get_net_2(&pkt,&er->version)) {
        ESNIerr(ESNI_F_SSL_ESNI_RECORD_NEW_FROM_BINARY, ESNI_R_RR_DECODE_ERROR);
        goto err;
    }
    /*
     * check version and fail early if failing 
     */
    switch (er->version) {
        case ESNI_DRAFT_02_VERSION:
            break;
        case ESNI_DRAFT_03_VERSION:
            printf("Draft-03 code is a work-in-progress...\n");
            break;
        default:
            ESNIerr(ESNI_F_SSL_ESNI_RECORD_NEW_FROM_BINARY, ESNI_R_RR_DECODE_ERROR);
            goto err;
    }
    /* checksum decode */
    if (!PACKET_copy_bytes(&pkt,er->checksum,4)) {
        ESNIerr(ESNI_F_SSL_ESNI_RECORD_NEW_FROM_BINARY, ESNI_R_RR_DECODE_ERROR);
        goto err;
    }
    if (er->version==ESNI_DRAFT_03_VERSION) {
        /* 
         * read public_name 
         */
        PACKET public_name_pkt;
        if (!PACKET_get_length_prefixed_2(&pkt, &public_name_pkt)) {
            ESNIerr(ESNI_F_SSL_ESNI_RECORD_NEW_FROM_BINARY, ESNI_R_RR_DECODE_ERROR);
            goto err;
        }
        er->public_name_len=PACKET_remaining(&public_name_pkt);
        if (er->public_name_len<=4||er->public_name_len>TLSEXT_MAXLEN_host_name) {
            ESNIerr(ESNI_F_SSL_ESNI_RECORD_NEW_FROM_BINARY, ESNI_R_RR_DECODE_ERROR);
            goto err;
        }
        er->public_name=OPENSSL_malloc(er->public_name_len+1);
        if (er->public_name==NULL) {
            ESNIerr(ESNI_F_SSL_ESNI_RECORD_NEW_FROM_BINARY, ESNI_R_RR_DECODE_ERROR);
            goto err;
        }
        PACKET_copy_bytes(&public_name_pkt,er->public_name,er->public_name_len);
        er->public_name[er->public_name_len]='\0';
    }
    /* 
     * list of KeyShareEntry elements - 
     * inspiration: ssl/statem/extensions_srvr.c:tls_parse_ctos_key_share 
     */
    PACKET key_share_list;
    if (!PACKET_get_length_prefixed_2(&pkt, &key_share_list)) {
        ESNIerr(ESNI_F_SSL_ESNI_RECORD_NEW_FROM_BINARY, ESNI_R_RR_DECODE_ERROR);
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
            ESNIerr(ESNI_F_SSL_ESNI_RECORD_NEW_FROM_BINARY, ESNI_R_RR_DECODE_ERROR);
            goto err;
        }
        if (tmp>ESNI_MAX_RRVALUE_LEN) {
            ESNIerr(ESNI_F_SSL_ESNI_RECORD_NEW_FROM_BINARY, ESNI_R_RR_DECODE_ERROR);
            goto err;
        }
        group_id=(uint16_t)tmp;
        EVP_PKEY *kn=ssl_generate_param_group(group_id);
        if (kn==NULL) {
            ESNIerr(ESNI_F_SSL_ESNI_RECORD_NEW_FROM_BINARY, ESNI_R_RR_DECODE_ERROR);
            goto err;
        }
        /* stash encoded public value for later */
        size_t thislen=PACKET_remaining(&encoded_pt);
        unsigned char *thisencoded=NULL;
        thisencoded=OPENSSL_malloc(PACKET_remaining(&encoded_pt));
        if (thisencoded==NULL) {
            ESNIerr(ESNI_F_SSL_ESNI_RECORD_NEW_FROM_BINARY, ESNI_R_RR_DECODE_ERROR);
            goto err;
        }
        memcpy(thisencoded,PACKET_data(&encoded_pt),thislen);
        if (!EVP_PKEY_set1_tls_encodedpoint(kn,thisencoded,thislen)) {
            ESNIerr(ESNI_F_SSL_ESNI_RECORD_NEW_FROM_BINARY, ESNI_R_RR_DECODE_ERROR);
            goto err;
        }
        nkeys++;
        EVP_PKEY** tkeys=(EVP_PKEY**)OPENSSL_realloc(keys,nkeys*sizeof(EVP_PKEY*));
        if (tkeys == NULL ) {
            ESNIerr(ESNI_F_SSL_ESNI_RECORD_NEW_FROM_BINARY, ESNI_R_RR_DECODE_ERROR);
            goto err;
        }
        keys=tkeys;
        keys[nkeys-1]=kn;
        group_ids=(uint16_t*)OPENSSL_realloc(group_ids,nkeys*sizeof(uint16_t));
        if (group_ids == NULL ) {
            ESNIerr(ESNI_F_SSL_ESNI_RECORD_NEW_FROM_BINARY, ESNI_R_RR_DECODE_ERROR);
            goto err;
        }
        group_ids[nkeys-1]=group_id;
        encoded_lens=(size_t*)OPENSSL_realloc(encoded_lens,nkeys*sizeof(size_t));
        if (encoded_lens == NULL ) {
            ESNIerr(ESNI_F_SSL_ESNI_RECORD_NEW_FROM_BINARY, ESNI_R_RR_DECODE_ERROR);
            goto err;
        }
        encoded_lens[nkeys-1]=thislen;
        encoded_keys=(unsigned char **)OPENSSL_realloc(encoded_keys,nkeys*sizeof(unsigned char **));
        if (encoded_keys==NULL) {
            ESNIerr(ESNI_F_SSL_ESNI_RECORD_NEW_FROM_BINARY, ESNI_R_RR_DECODE_ERROR);
            goto err;
        }
        encoded_keys[nkeys-1]=thisencoded;
    }
    er->nkeys=nkeys;
    er->keys=keys;
    er->group_ids=group_ids;
    er->encoded_lens=encoded_lens;
    er->encoded_keys=encoded_keys;
    /*
     * List of ciphersuites - 2 byte len + 2 bytes per ciphersuite
     * Code here inspired by ssl/ssl_lib.c:bytes_to_cipher_list
     */
    PACKET cipher_suites;
    if (!PACKET_get_length_prefixed_2(&pkt, &cipher_suites)) {
        ESNIerr(ESNI_F_SSL_ESNI_RECORD_NEW_FROM_BINARY, ESNI_R_RR_DECODE_ERROR);
        goto err;
    }
    int nsuites=PACKET_remaining(&cipher_suites);
    er->nsuites=nsuites/2; /* local var is #bytes */
    er->ciphersuites=OPENSSL_malloc(er->nsuites*sizeof(uint16_t));
    if (er->ciphersuites==NULL) {
        ESNIerr(ESNI_F_SSL_ESNI_RECORD_NEW_FROM_BINARY, ESNI_R_RR_DECODE_ERROR);
        goto err;
    }
    if (!nsuites || (nsuites % 1)) {
        ESNIerr(ESNI_F_SSL_ESNI_RECORD_NEW_FROM_BINARY, ESNI_R_RR_DECODE_ERROR);
        goto err;
    }
    unsigned char cipher[TLS_CIPHER_LEN];
    int ci=0;
    while (PACKET_copy_bytes(&cipher_suites, cipher, TLS_CIPHER_LEN)) {
        er->ciphersuites[ci++]=cipher[0]*256+cipher[1];
    }
    if (PACKET_remaining(&cipher_suites) > 0) {
        ESNIerr(ESNI_F_SSL_ESNI_RECORD_NEW_FROM_BINARY, ESNI_R_RR_DECODE_ERROR);
        goto err;
    }
    if (!PACKET_get_net_2(&pkt,&er->padded_length)) {
        ESNIerr(ESNI_F_SSL_ESNI_RECORD_NEW_FROM_BINARY, ESNI_R_RR_DECODE_ERROR);
        goto err;
    }
    /*
     * note: not_before/not_after checking is done elsewhere/elsewhen
     */
    unsigned char nbs[8];
    if (!PACKET_copy_bytes(&pkt,nbs,8)) {
        ESNIerr(ESNI_F_SSL_ESNI_RECORD_NEW_FROM_BINARY, ESNI_R_RR_DECODE_ERROR);
        goto err;
    }
    er->not_before=uint64_from_bytes(nbs);
    if (!PACKET_copy_bytes(&pkt,nbs,8)) {
        ESNIerr(ESNI_F_SSL_ESNI_RECORD_NEW_FROM_BINARY, ESNI_R_RR_DECODE_ERROR);
        goto err;
    }
    er->not_after=uint64_from_bytes(nbs);
    /*
     * Extensions: we'll just store 'em for now and try parse any
     * we understand a little later
     */
    PACKET exts;
    if (!PACKET_get_length_prefixed_2(&pkt, &exts)) {
        ESNIerr(ESNI_F_SSL_ESNI_RECORD_NEW_FROM_BINARY, ESNI_R_RR_DECODE_ERROR);
        goto err;
    }
    while (PACKET_remaining(&exts) > 0) {
        er->nexts+=1;
        /*
         * a two-octet length prefixed list of:
         * two octet extension type
         * two octet extension length
         * length octets
         */
        unsigned int exttype=0;
        if (!PACKET_get_net_2(&exts,&exttype)) {
            ESNIerr(ESNI_F_SSL_ESNI_RECORD_NEW_FROM_BINARY, ESNI_R_RR_DECODE_ERROR);
            goto err;
        }
        unsigned int extlen=0;
        if (extlen>=ESNI_MAX_RRVALUE_LEN) {
            ESNIerr(ESNI_F_SSL_ESNI_RECORD_NEW_FROM_BINARY, ESNI_R_RR_DECODE_ERROR);
            goto err;
        }
        if (!PACKET_get_net_2(&exts,&extlen)) {
            ESNIerr(ESNI_F_SSL_ESNI_RECORD_NEW_FROM_BINARY, ESNI_R_RR_DECODE_ERROR);
            goto err;
        }
        unsigned char *extval=NULL;
        if (extlen != 0 ) {
            extval=(unsigned char*)OPENSSL_malloc(extlen);
            if (extval==NULL) {
                ESNIerr(ESNI_F_SSL_ESNI_RECORD_NEW_FROM_BINARY, ESNI_R_RR_DECODE_ERROR);
                goto err;
            }
            if (!PACKET_copy_bytes(&exts,extval,extlen)) {
                OPENSSL_free(extval);
                ESNIerr(ESNI_F_SSL_ESNI_RECORD_NEW_FROM_BINARY, ESNI_R_RR_DECODE_ERROR);
                goto err;
            }
        }

        /* assign fields to lists, have to realloc */
        unsigned int *tip=(unsigned int*)OPENSSL_realloc(er->exttypes,er->nexts*sizeof(er->exttypes[0]));
        if (tip==NULL) {
            OPENSSL_free(extval);
            ESNIerr(ESNI_F_SSL_ESNI_RECORD_NEW_FROM_BINARY, ESNI_R_RR_DECODE_ERROR);
            goto err;
        }
        er->exttypes=tip;
        er->exttypes[er->nexts-1]=exttype;

        size_t *lip=(size_t*)OPENSSL_realloc(er->extlens,er->nexts*sizeof(er->extlens[0]));
        if (lip==NULL) {
            OPENSSL_free(extval);
            ESNIerr(ESNI_F_SSL_ESNI_RECORD_NEW_FROM_BINARY, ESNI_R_RR_DECODE_ERROR);
            goto err;
        }
        er->extlens=lip;
        er->extlens[er->nexts-1]=extlen;

        unsigned char **vip=(unsigned char**)OPENSSL_realloc(er->exts,er->nexts*sizeof(unsigned char*));
        if (vip==NULL) {
            OPENSSL_free(extval);
            ESNIerr(ESNI_F_SSL_ESNI_RECORD_NEW_FROM_BINARY, ESNI_R_RR_DECODE_ERROR);
            goto err;
        }
        er->exts=vip;
        er->exts[er->nexts-1]=extval;

    }
    int lleftover=PACKET_remaining(&pkt);
    if (lleftover<0 || lleftover>binblen) {
        ESNIerr(ESNI_F_SSL_ESNI_RECORD_NEW_FROM_BINARY, ERR_R_INTERNAL_ERROR);
        goto err;
    }
    int cksum_ok=esni_checksum_check(binbuf,binblen-lleftover);
    if (cksum_ok!=1) {
        ESNIerr(ESNI_F_SSL_ESNI_RECORD_NEW_FROM_BINARY, ERR_R_INTERNAL_ERROR);
        goto err;
    }
    *leftover=lleftover;
    return er;

err:
    if (er!=NULL) {
        ESNI_RECORD_free(er);
        OPENSSL_free(er);
    }
    return NULL;
}

/**
 * @brief populate an SSL_ESNI from an ESNI_RECORD
 *
 * This is used by both client and server in (almost) identical ways.
 * Note that se->encoded_rr and se->encodded_rr_len must be set before
 * calling this, but that's usually fine.
 *
 * @todo TODO: handle >1 of the many things that can 
 * have >1 instance (maybe at a higher layer)
 *
 * @param er is the ESNI_RECORD
 * @param se is the SSL_ESNI
 * @param server is 1 if we're a TLS server, 0 otherwise, (just in case there's a difference)
 * @return 1 for success, not 1 otherwise
 */
static int esni_make_se_from_er(ESNI_RECORD* er, SSL_ESNI *se, int server)
{
    unsigned char *tmp=NULL;
    size_t tlen=0;
    /* 
     * zap as needed
     */
    //SSL_ESNI_free(se);
    //memset(se,0,sizeof(*se));
    /*
     * Fixed bits of RR to use
     */
    se->version=er->version;
    se->not_before=er->not_before;
    se->not_after=er->not_after;
    se->padded_length=er->padded_length;
    if (er->public_name && er->public_name_len>0) {
        se->public_name=OPENSSL_malloc(er->public_name_len+1);
        if (se->public_name==NULL) {
            ESNIerr(ESNI_F_ESNI_MAKE_SE_FROM_ER, ERR_R_INTERNAL_ERROR);
            goto err;
        }
        memcpy(se->public_name,er->public_name,er->public_name_len);
        se->public_name[er->public_name_len]='\0';
    }
    /* 
     * now decide which bits of er we like and remember those 
     * pick the 1st key/group/ciphersutie that works
     */
    int rec2pick=0;
    se->ciphersuite=er->ciphersuites[rec2pick];
    se->group_id=er->group_ids[rec2pick];
    se->esni_peer_pkey=ssl_generate_param_group(se->group_id);
    if (se->esni_peer_pkey==NULL) {
        ESNIerr(ESNI_F_ESNI_MAKE_SE_FROM_ER, ERR_R_INTERNAL_ERROR);
        goto err;
    }
    if (!EVP_PKEY_set1_tls_encodedpoint(se->esni_peer_pkey,
                er->encoded_keys[rec2pick],er->encoded_lens[rec2pick])) {
            ESNIerr(ESNI_F_ESNI_MAKE_SE_FROM_ER, ESNI_R_RR_DECODE_ERROR);
            goto err;
    }
    tlen = EVP_PKEY_get1_tls_encodedpoint(se->esni_peer_pkey,&tmp); 
    if (tlen == 0) {
        ESNIerr(ESNI_F_ESNI_MAKE_SE_FROM_ER, ERR_R_INTERNAL_ERROR);
        goto err;
    }
    /* the public value goes in different places for client and server */
    if (server) {
        se->encoded_keyshare=SSL_ESNI_wrap_keyshare(tmp,tlen,se->group_id,&se->encoded_keyshare_len);
        if (se->encoded_keyshare==NULL) {
            ESNIerr(ESNI_F_ESNI_MAKE_SE_FROM_ER, ERR_R_INTERNAL_ERROR);
            goto err;
        }
    } else {
        se->esni_peer_keyshare=SSL_ESNI_wrap_keyshare(tmp,tlen,se->group_id,&se->esni_peer_keyshare_len);
        if (se->esni_peer_keyshare==NULL) {
            ESNIerr(ESNI_F_ESNI_MAKE_SE_FROM_ER, ERR_R_INTERNAL_ERROR);
            goto err;
        }
    }
    OPENSSL_free(tmp);
    const SSL_CIPHER *sc=cs2sc(se->ciphersuite);
    const EVP_MD *md=ssl_md(sc->algorithm2);
    se->rd=esni_make_rd(se->encoded_rr,se->encoded_rr_len,md,&se->rd_len);
    if (se->rd==NULL) {
        ESNIerr(ESNI_F_ESNI_MAKE_SE_FROM_ER, ERR_R_INTERNAL_ERROR);
        goto err;
    }
    /*
     * Handle extensions. Initially shallow copy, maybe deeper later
     * Then when copied, parse known extensions.
     */
    if (er->nexts>0) {
        se->nexts=er->nexts;
        se->exttypes=er->exttypes;
        se->extlens=er->extlens;
        se->exts=er->exts;
    }
    return 1;
err:
    if (tmp!=NULL) {
        OPENSSL_free(tmp);
    }
    return 0;
}

/**
 * Try figure out ESNIKeys encodng
 *
 * @param eklen is the length of esnikeys
 * @param esnikeys is encoded ESNIKeys structure
 * @param guessedfmt is our returned guess at the format
 * @return 1 for success, 0 for error
 */
static int esni_guess_fmt(const size_t eklen, 
                    const char *esnikeys,
                    short *guessedfmt)
{
    if (!guessedfmt || eklen <=0 || !esnikeys) {
        return(0);
    }
    /* asci hex is easy:-) either case allowed*/
    const char *AH_alphabet="0123456789ABCDEFabcdef";
    /* we actually add a semi-colon here as we accept multiple semi-colon separated values */
    const char *B64_alphabet="ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/=;";
    /*
     * Try from most constrained to least in that order
     */
    if (eklen<=strspn(esnikeys,AH_alphabet)) {
        *guessedfmt=ESNI_RRFMT_ASCIIHEX;
    } else if (eklen<=strspn(esnikeys,B64_alphabet)) {
        *guessedfmt=ESNI_RRFMT_B64TXT;
    } else {
        // fallback - try binary
        *guessedfmt=ESNI_RRFMT_BIN;
    }
    return(1);
} 


/**
 * Decode and check the value retieved from DNS (binary, base64 or ascii-hex encoded)
 *
 * The esnnikeys value here may be the catenation of multiple encoded ESNIKeys RR values 
 * (or TXT values for draft-02), we'll internally try decode and handle those and (later)
 * use whichever is relevant/best. The fmt parameter can be e.g. ESNI_RRFMT_ASCII_HEX
 *
 * @param ekfmt specifies the format of the input text string
 * @param eklen is the length of the binary, base64 or ascii-hex encoded value from DNS
 * @param esnikeys is the binary, base64 or ascii-hex encoded value from DNS
 * @param num_esnis says how many SSL_ESNI structures are in the returned array
 * @return is an SSL_ESNI structure
 */
SSL_ESNI* SSL_ESNI_new_from_buffer(const short ekfmt, const size_t eklen, const char *esnikeys, int *num_esnis)
{
    short detfmt=ESNI_RRFMT_GUESS;
    int nlens=0;                    /* number of values detected */

    switch (ekfmt) {
        case ESNI_RRFMT_GUESS:
            break;
        case ESNI_RRFMT_ASCIIHEX:
        case ESNI_RRFMT_B64TXT:
            detfmt=ekfmt;
            break;
        default:
            return(NULL);
    }

    if (eklen==0 || esnikeys==NULL) {
        return(NULL);
    }

    if (num_esnis==NULL) {
        return(NULL);
    }

    char *ekcpy=NULL;
    ekcpy=OPENSSL_malloc(eklen+1);
    if (ekcpy==NULL) {
        return(NULL);
    }
    memcpy(ekcpy,esnikeys,eklen);
    ekcpy[eklen]=0;

    /*
     * try decode to binary form
     */
    if (detfmt==ESNI_RRFMT_GUESS) {
        int rv=esni_guess_fmt(eklen,ekcpy,&detfmt);
        if (rv!=1) {
            ESNIerr(ESNI_F_SSL_ESNI_NEW_FROM_BUFFER, ESNI_R_BASE64_DECODE_ERROR);
            goto err;
        }
    }

    unsigned char *outbuf = NULL;   /* a binary representation of an ESNIKeys */
    size_t declen=0;                /* a length of binary representation of an ESNIKeys */
    if (detfmt==ESNI_RRFMT_B64TXT) {
        declen = esni_base64_decode(ekcpy, &outbuf);
        if (declen < 0) {
            ESNIerr(ESNI_F_SSL_ESNI_NEW_FROM_BUFFER, ESNI_R_BASE64_DECODE_ERROR);
            goto err;
        }
        OPENSSL_free(ekcpy);
        ekcpy=NULL;
    }

    if (detfmt==ESNI_RRFMT_ASCIIHEX) {
        /* Yay AH */
        int adr=ah_decode(eklen,ekcpy,&declen,&outbuf);
        if (adr==0) {
            ESNIerr(ESNI_F_SSL_ESNI_NEW_FROM_BUFFER, ESNI_R_ASCIIHEX_DECODE_ERROR);
            goto err;
        }
        OPENSSL_free(ekcpy);
        ekcpy=NULL;
    }
    if (detfmt==ESNI_RRFMT_BIN) {
        /* just copy over the input to where we'd expect it */
        declen=eklen;
        outbuf=OPENSSL_malloc(declen);
        if (outbuf==NULL){
            ESNIerr(ESNI_F_SSL_ESNI_NEW_FROM_BUFFER, ESNI_R_BASE64_DECODE_ERROR);
            goto err;
        }
        memcpy(outbuf,ekcpy,declen);
    }

    /*
     * Now try decode each binary encoding if we can
     */

    SSL_ESNI *retesnis=NULL;        ///< output array
    ESNI_RECORD *er=NULL;           ///< individual public value structure (initial decoding)
    SSL_ESNI *newesni=NULL;         ///< individual public value structure (after more decoding)

    int done=0;
    unsigned char *outp=outbuf;
    int oleftover=declen;
    while (!done) {
        nlens+=1;
        SSL_ESNI *ts=OPENSSL_realloc(retesnis,nlens*sizeof(SSL_ESNI));
        if (!ts) {
            ESNIerr(ESNI_F_SSL_ESNI_NEW_FROM_BUFFER, ERR_R_MALLOC_FAILURE);
            goto err;
        }
        retesnis=ts;

        newesni=&retesnis[nlens-1];
        memset(newesni,0,sizeof(SSL_ESNI));
    
        int leftover=oleftover;
        er=SSL_ESNI_RECORD_new_from_binary(outp,oleftover,&leftover);
        //so_esni_pbuf("BINBUF:",outp,oleftover,0);
        if (er==NULL) {
            ESNIerr(ESNI_F_SSL_ESNI_NEW_FROM_BUFFER, ERR_R_INTERNAL_ERROR);
            goto err;
        }
        if (leftover<=0) {
           done=1;
        }
        newesni->encoded_rr_len=oleftover-leftover;
        if (newesni->encoded_rr_len <=0 || newesni->encoded_rr_len>ESNI_MAX_RRVALUE_LEN) {
            ESNIerr(ESNI_F_SSL_ESNI_NEW_FROM_BUFFER, ERR_R_INTERNAL_ERROR);
            goto err;
        }
        newesni->encoded_rr=OPENSSL_malloc(newesni->encoded_rr_len);
        if (newesni->encoded_rr==NULL) {
            ESNIerr(ESNI_F_SSL_ESNI_NEW_FROM_BUFFER, ERR_R_INTERNAL_ERROR);
            goto err;
        }
        memcpy(newesni->encoded_rr,outp,newesni->encoded_rr_len);
        oleftover=leftover;
        outp+=newesni->encoded_rr_len;

        if (esni_make_se_from_er(er,newesni,0)!=1) {
            ESNIerr(ESNI_F_SSL_ESNI_NEW_FROM_BUFFER, ERR_R_INTERNAL_ERROR);
            goto err;
        }
        ESNI_RECORD_free(er);
        OPENSSL_free(er);
        er=NULL;
    }
    for (int i=0;i!=nlens;i++) {
        retesnis[i].num_esni_rrs=nlens;
    }
    
    if (outbuf!=NULL) {
        OPENSSL_free(outbuf);
    }

    *num_esnis=nlens;

    return(retesnis);
err:
    /*
     * May need to fix up nlens if error happened before we normally do that
     */
    for (int i=0;i!=nlens;i++) {
        retesnis[i].num_esni_rrs=nlens;
    }
    if (ekcpy!=NULL) {
        OPENSSL_free(ekcpy);
    }
    if (outbuf!=NULL) {
        OPENSSL_free(outbuf);
    }
    if (er!=NULL) {
        ESNI_RECORD_free(er);
        OPENSSL_free(er);
    }
    if (retesnis!=NULL) {
        SSL_ESNI_free(retesnis);
        OPENSSL_free(retesnis);
    }
    return(NULL);
}

/**
 * @brief print a buffer nicely
 *
 * This is used in SSL_ESNI_print
 */
static void esni_pbuf(BIO *out,char *msg,unsigned char *buf,size_t blen,int indent)
{
    /*
     * The "OPENSSL: " prefix helps as I instrumented an NSS build
     * to preface the same variables with "NSS: ". That can however
     * be removed once the ESNI spec's crypto is stable.
     */
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

/**
 * @brief stdout version of esni_pbuf - just for odd/occasional debugging
 */
static void so_esni_pbuf(char *msg,unsigned char *buf,size_t blen,int indent)
{
    if (buf==NULL) {
        printf("OPENSSL: %s is NULL\n",msg);
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

/**
 * @brief Print out an array of SSL_ESNI structures 
 *
 * This is called via callback
 *
 * @param out is the BIO* 
 * @param esniarr is an array of SSL_ESNI structures
 * @return 1 is good
 */
int SSL_ESNI_print(BIO* out, SSL_ESNI *esniarr)
{
    SSL_ESNI *esni=NULL;
    int nesnis=0;
    int indent=0;
    if (esniarr==NULL) {
        BIO_printf(out,"ESNI is NULL!\n");
        return 0;
    }
    nesnis=esniarr->num_esni_rrs;
    for (int i=0;i!=nesnis;i++) {

        esni=&esniarr[i];

        BIO_printf(out,"Printing SSL_ESNI structure number %d\n",i);
        BIO_printf(out,"ESNI Version: %x\n",esni->version);
	
	    if (esni->encoded_rr==NULL) {
	        BIO_printf(out,"ESNI has no RRs!\n");
	        return 0;
	    } 
	    // carefully print these - might be attack content
	    if (esni->encservername==NULL) {
	        BIO_printf(out, "ESNI encservername is NULL\n");
	    } else {
	        BIO_printf(out, "ESNI encservername: \"");
	        const char *cp=esni->encservername;
	        unsigned char uc;
	        while ((uc = *cp++) != 0)
	            BIO_printf(out, isascii(uc) && isprint(uc) ? "%c" : "\\x%02x", uc);
	        BIO_printf(out, "\"\n");
	    }
	    if (esni->covername==NULL) {
	        BIO_printf(out, "ESNI covername is NULL\n");
	    } else {
	        BIO_printf(out, "ESNI covername: \"");
	        const char *cp=esni->covername;
	        unsigned char uc;
	        while ((uc = *cp++) != 0)
	            BIO_printf(out, isascii(uc) && isprint(uc) ? "%c" : "\\x%02x", uc);
	        BIO_printf(out, "\"\n");
	    }
	    if (esni->public_name==NULL) {
	        BIO_printf(out, "ESNI public_name is NULL\n");
	    } else {
	        BIO_printf(out, "ESNI public_name: \"");
	        const char *cp=esni->public_name;
	        unsigned char uc;
	        while ((uc = *cp++) != 0)
	            BIO_printf(out, isascii(uc) && isprint(uc) ? "%c" : "\\x%02x", uc);
	        BIO_printf(out, "\"\n");
	    }
	    esni_pbuf(out,"ESNI Encoded RR",esni->encoded_rr,esni->encoded_rr_len,indent);
	    esni_pbuf(out,"ESNI DNS record_digest", esni->rd,esni->rd_len,indent);
	    esni_pbuf(out,"ESNI Peer KeyShare:",esni->esni_peer_keyshare,esni->esni_peer_keyshare_len,indent);
	    BIO_printf(out,"ESNI Server groupd Id: %04x\n",esni->group_id);
	    BIO_printf(out,"ENSI Server Ciphersuite is %04x\n",esni->ciphersuite);
	    BIO_printf(out,"ESNI Server padded_length: %zd\n",esni->padded_length);
	    BIO_printf(out,"ESNI Server not_before: %ju\n",esni->not_before);
	    BIO_printf(out,"ESNI Server not_after: %ju\n",esni->not_after);
	    BIO_printf(out,"ESNI Server number of extensions: %d\n",esni->nexts);
	    if (esni->nexts!=0) {
            for (int i=0;i!=esni->nexts;i++) {
                BIO_printf(out,"ESNI Extension type %d\n",esni->exttypes[i]);
	            esni_pbuf(out,"ESNI Extension value",esni->exts[i],esni->extlens[i],indent+4);
            }
	    } else {
	        BIO_printf(out,"ESNI no extensions\n");
        }
        if (esni->naddrs!=0) {
            BIO_printf(out,"\tOops - I need to print addresses!\n");
        }
	    esni_pbuf(out,"ESNI Nonce",esni->nonce,esni->nonce_len,indent);
	    esni_pbuf(out,"ESNI H/S Client Random",esni->hs_cr,esni->hs_cr_len,indent);
	    esni_pbuf(out,"ESNI H/S Client KeyShare",esni->hs_kse,esni->hs_kse_len,indent);
	    if (esni->keyshare!=NULL) {
	        BIO_printf(out,"ESNI Client ESNI KeyShare: ");
	        EVP_PKEY_print_public(out, esni->keyshare, indent, NULL);
	    } else {
	        BIO_printf(out,"ESNI Client ESNI KeyShare is NULL\n");
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
	    if (esni->the_esni) {
	        BIO_printf(out,"ESNI CLIENT_ESNI structure (repetitive on client):\n");
	        BIO_printf(out,"CLIENT_ESNI Ciphersuite is %04x\n",esni->the_esni->ciphersuite);
	        esni_pbuf(out,"CLIENT_ESNI encoded_keyshare",esni->the_esni->encoded_keyshare,esni->the_esni->encoded_keyshare_len,indent);
	        esni_pbuf(out,"CLIENT_ESNI record_digest",esni->the_esni->record_digest,esni->the_esni->record_digest_len,indent);
	        esni_pbuf(out,"CLIENT_ESNI encrypted_sni",esni->the_esni->encrypted_sni,esni->the_esni->encrypted_sni_len,indent);
	    } else {
	        BIO_printf(out,"ESNI CLIENT_ESNI is NULL\n");
	    }
	
    }
    return(1);
}

/**
 * @brief Make a 16 octet nonce for ESNI
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

/**
 * @brief Pad an SNI before encryption with zeros on the right to the required length
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

/**
 * @brief Local wrapper for HKDF-Extract(salt,IVM)=HMAC-Hash(salt,IKM) according to RFC5689
 *
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


/**
 * @brief expand a label as per the I-D
 *
 * @todo TODO: this and esni_hkdf_extract should be better integrated
 * There are functions that can do this that require an ```SSL *s```
 * input and we should move to use those.
 */
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
                            out, *expanded_len,0);
    if (rv!=1) {
        return NULL;
    }
    return out;
}

/**
 * @brief do the AEAD encryption as per the I-D
 *
 * Note: The tag output isn't really needed but was useful when I got
 * the aad wrong at one stage to keep it for now.
 * Most parameters obvious but...
 *
 * @param cipher_Len is an output
 * @returns NULL (on error) or pointer to alloced buffer for ciphertext
 */
static unsigned char *esni_aead_enc(
            unsigned char *key, size_t key_len,
            unsigned char *iv, size_t iv_len,
            unsigned char *aad, size_t aad_len,
            unsigned char *plain, size_t plain_len,
            unsigned char *tag, size_t tag_len, 
            size_t *cipher_len,
            uint16_t ciph)
{
    /*
     * From https://wiki.openssl.org/index.php/EVP_Authenticated_Encryption_and_Decryption
     */
    EVP_CIPHER_CTX *ctx=NULL;
    int len;
    size_t ciphertext_len;
    unsigned char *ciphertext=NULL;

    const SSL_CIPHER *sc=cs2sc(ciph);
    if (sc==NULL) {
        ESNIerr(ESNI_F_ESNI_AEAD_ENC, ERR_R_INTERNAL_ERROR);
        goto err;
    }
    if (SSL_CIPHER_is_aead(sc)!=1) {
        ESNIerr(ESNI_F_ESNI_AEAD_ENC, ERR_R_INTERNAL_ERROR);
        goto err;
    }
    /*
     * We'll allocate this much extra for ciphertext and check the AEAD doesn't require more later
     * If it does, we'll fail.
     */
    size_t alloced_oh=64;

    ciphertext=OPENSSL_malloc(plain_len+alloced_oh);
    if (ciphertext==NULL) {
        ESNIerr(ESNI_F_ESNI_AEAD_ENC, ERR_R_INTERNAL_ERROR);
        goto err;
    }

    /* Create and initialise the context */
    if(!(ctx = EVP_CIPHER_CTX_new())) {
        ESNIerr(ESNI_F_ESNI_AEAD_ENC, ERR_R_INTERNAL_ERROR);
        goto err;
    }

    /* Initialise the encryption operation. */
    const EVP_CIPHER *enc=EVP_get_cipherbynid(SSL_CIPHER_get_cipher_nid(sc));
    if (enc == NULL) {
        ESNIerr(ESNI_F_ESNI_AEAD_ENC, ERR_R_INTERNAL_ERROR);
        goto err;
    }

    if(1 != EVP_EncryptInit_ex(ctx, enc, NULL, NULL, NULL)) {
        ESNIerr(ESNI_F_ESNI_AEAD_ENC, ERR_R_INTERNAL_ERROR);
        goto err;
    }

    /* Set IV length if default 12 bytes (96 bits) is not appropriate */
    if(1 != EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, iv_len, NULL)) {
        ESNIerr(ESNI_F_ESNI_AEAD_ENC, ERR_R_INTERNAL_ERROR);
        goto err;
    }

    /* Initialise key and IV */
    if(1 != EVP_EncryptInit_ex(ctx, NULL, NULL, key, iv))  {
        ESNIerr(ESNI_F_ESNI_AEAD_ENC, ERR_R_INTERNAL_ERROR);
        goto err;
    }

    /* Provide any AAD data. This can be called zero or more times as
     * required
     */
    if(1 != EVP_EncryptUpdate(ctx, NULL, &len, aad, aad_len)) {
        ESNIerr(ESNI_F_ESNI_AEAD_ENC, ERR_R_INTERNAL_ERROR);
        goto err;
    }

    /* Provide the message to be encrypted, and obtain the encrypted output.
     * EVP_EncryptUpdate can be called multiple times if necessary
     */
    if(1 != EVP_EncryptUpdate(ctx, ciphertext, &len, plain, plain_len)) {
        ESNIerr(ESNI_F_ESNI_AEAD_ENC, ERR_R_INTERNAL_ERROR);
        goto err;
    }

    ciphertext_len = len;

    /* Finalise the encryption. Normally ciphertext bytes may be written at
     * this stage, but this does not occur in GCM mode
     */
    if(1 != EVP_EncryptFinal_ex(ctx, ciphertext + len, &len))  {
        ESNIerr(ESNI_F_ESNI_AEAD_ENC, ERR_R_INTERNAL_ERROR);
        goto err;
    }

    ciphertext_len += len;

    /* Get the tag */
    /*
     * This isn't a duplicate so needs to be added to the ciphertext
     */
    if(1 != EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_GET_TAG, tag_len, tag)) {
        ESNIerr(ESNI_F_ESNI_AEAD_ENC, ERR_R_INTERNAL_ERROR);
        goto err;
    }
    if (tag_len > alloced_oh) {
        ESNIerr(ESNI_F_ESNI_AEAD_ENC, ERR_R_INTERNAL_ERROR);
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

/**
 * @brief do the AEAD decryption as per the I-D
 *
 * Note: The tag output isn't really needed but was useful when I got
 * the aad wrong at one stage to keep it for now.
 * @param cipher_Len is an output
 * @returns NULL (on error) or pointer to alloced buffer for plaintext
 */
static unsigned char *esni_aead_dec(
            unsigned char *key, size_t key_len,
            unsigned char *iv, size_t iv_len,
            unsigned char *aad, size_t aad_len,
            unsigned char *cipher, size_t cipher_len,
            size_t *plain_len,
            uint16_t ciph)
{
    /*
     * From https://wiki.openssl.org/index.php/EVP_Authenticated_Encryption_and_Decryption
     */
    EVP_CIPHER_CTX *ctx=NULL;
    int len;
    size_t plaintext_len=0;
    unsigned char *plaintext=NULL;
    const SSL_CIPHER *sc=cs2sc(ciph);
    if (SSL_CIPHER_is_aead(sc)!=1) {
        ESNIerr(ESNI_F_ESNI_AEAD_DEC, ERR_R_INTERNAL_ERROR);
        goto err;
    }
    /*
     * We'll allocate this much extra for plaintext and check the AEAD doesn't require more later
     * If it does, we'll fail.
     */
    size_t alloced_oh=64;
    plaintext=OPENSSL_malloc(cipher_len+alloced_oh);
    if (plaintext==NULL) {
        ESNIerr(ESNI_F_ESNI_AEAD_DEC, ERR_R_INTERNAL_ERROR);
        goto err;
    }
    /* Create and initialise the context */
    if(!(ctx = EVP_CIPHER_CTX_new())) {
        ESNIerr(ESNI_F_ESNI_AEAD_DEC, ERR_R_INTERNAL_ERROR);
        goto err;
    }
    /* Initialise the encryption operation. */
    const EVP_CIPHER *enc=EVP_get_cipherbynid(SSL_CIPHER_get_cipher_nid(sc));
    if (enc == NULL) {
        ESNIerr(ESNI_F_ESNI_AEAD_DEC, ERR_R_INTERNAL_ERROR);
        goto err;
    }
    if(1 != EVP_DecryptInit_ex(ctx, enc, NULL, NULL, NULL)) {
        ESNIerr(ESNI_F_ESNI_AEAD_DEC, ERR_R_INTERNAL_ERROR);
        goto err;
    }
    /* Set IV length if default 12 bytes (96 bits) is not appropriate */
    if(1 != EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, iv_len, NULL)) {
        ESNIerr(ESNI_F_ESNI_AEAD_DEC, ERR_R_INTERNAL_ERROR);
        goto err;
    }
    /* Initialise key and IV */
    if(1 != EVP_DecryptInit_ex(ctx, NULL, NULL, key, iv))  {
        ESNIerr(ESNI_F_ESNI_AEAD_DEC, ERR_R_INTERNAL_ERROR);
        goto err;
    }
    /* Provide any AAD data. This can be called zero or more times as
     * required
     */
    if(1 != EVP_DecryptUpdate(ctx, NULL, &len, aad, aad_len)) {
        ESNIerr(ESNI_F_ESNI_AEAD_DEC, ERR_R_INTERNAL_ERROR);
        goto err;
    }
    /* Provide the message to be encrypted, and obtain the encrypted output.
     * EVP_EncryptUpdate can be called multiple times if necessary
     */
    if(1 != EVP_DecryptUpdate(ctx, plaintext, &len, cipher, cipher_len-16)) {
        ESNIerr(ESNI_F_ESNI_AEAD_DEC, ERR_R_INTERNAL_ERROR);
        goto err;
    }
    plaintext_len = len;

    /* Set expected tag value. Works in OpenSSL 1.0.1d and later */
    if(!EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_TAG, 16, cipher+cipher_len-16)) {
        ESNIerr(ESNI_F_ESNI_AEAD_DEC, ERR_R_INTERNAL_ERROR);
        goto err;
    }

    /* 
     * Finalise the decryption. 
     */
    int decrypt_res=EVP_DecryptFinal_ex(ctx, plaintext + len, &len);
    if(decrypt_res<=0)  {
        ESNIerr(ESNI_F_ESNI_AEAD_DEC, ERR_R_INTERNAL_ERROR);
        goto err;
    }

    /* Clean up */
    EVP_CIPHER_CTX_free(ctx);
    *plain_len=plaintext_len;
    return plaintext;
err:
    EVP_CIPHER_CTX_free(ctx);
    if (plaintext!=NULL) OPENSSL_free(plaintext);
    return NULL;
}

/**
 * @brief given an SSL_ESNI create ESNIContent and hash that
 *
 * encode up TLS client's ESNI public keyshare (in a different
 * part of the SSL_ESNI for client and server) and other parts
 * of ESNIContents, and hash those
 *
 * @param esni is the SSL_ESNI structure 
 * @param server is 1 if on the server, 0 for client
 * @return 1 for success, other otherwise
 */
static int makeesnicontenthash(SSL_ESNI *esnikeys,
                    int server)
{
    unsigned char *tmp=NULL;
    size_t tlen=0;
    size_t kslen=0;
    EVP_MD_CTX *mctx = NULL;

    if (esnikeys==NULL) {
        ESNIerr(ESNI_F_MAKEESNICONTENTHASH, ERR_R_INTERNAL_ERROR);
        goto err;
    }
    if (server && esnikeys->the_esni==NULL) {
        ESNIerr(ESNI_F_MAKEESNICONTENTHASH, ERR_R_INTERNAL_ERROR);
        goto err;
    }

    if (!server) {
        tlen = EVP_PKEY_get1_tls_encodedpoint(esnikeys->keyshare,&tmp); 
        if (tlen == 0) {
            ESNIerr(ESNI_F_MAKEESNICONTENTHASH, ERR_R_INTERNAL_ERROR);
            goto err;
        }
        esnikeys->encoded_keyshare=SSL_ESNI_wrap_keyshare(tmp,tlen,esnikeys->group_id,&esnikeys->encoded_keyshare_len);
        if (esnikeys->encoded_keyshare==NULL) {
            ESNIerr(ESNI_F_MAKEESNICONTENTHASH, ERR_R_INTERNAL_ERROR);
            goto err;
        }
        OPENSSL_free(tmp); tmp=NULL;
        kslen=esnikeys->encoded_keyshare_len;
    } else {
        kslen=esnikeys->the_esni->encoded_keyshare_len;
    }
    // drop top two bytes from this version of encoded_keyshare (sigh!)
    esnikeys->hi_len=2+esnikeys->rd_len+kslen-2+esnikeys->hs_cr_len;
    esnikeys->hi=OPENSSL_malloc(esnikeys->hi_len);
    if (esnikeys->hi==NULL) {
        ESNIerr(ESNI_F_MAKEESNICONTENTHASH, ERR_R_INTERNAL_ERROR);
        goto err;
    }
    unsigned char *ecp=esnikeys->hi;
    *ecp++=esnikeys->rd_len/256;
    *ecp++=esnikeys->rd_len%256;
    memcpy(ecp,esnikeys->rd,esnikeys->rd_len);ecp+=esnikeys->rd_len;
    if (!server) {
        memcpy(ecp,esnikeys->encoded_keyshare+2,esnikeys->encoded_keyshare_len-2);ecp+=esnikeys->encoded_keyshare_len-2;
    } else {
        memcpy(ecp,esnikeys->the_esni->encoded_keyshare+2,esnikeys->the_esni->encoded_keyshare_len-2);
        ecp+=esnikeys->the_esni->encoded_keyshare_len-2;
    }
    memcpy(ecp,esnikeys->hs_cr,esnikeys->hs_cr_len);ecp+=esnikeys->hs_cr_len;

    /*
     * now hash it
     */
    const SSL_CIPHER *sc=cs2sc(esnikeys->ciphersuite);
    const EVP_MD *md=ssl_md(sc->algorithm2);
    mctx = EVP_MD_CTX_new();
    esnikeys->hash_len = EVP_MD_size(md);
    esnikeys->hash=OPENSSL_malloc(esnikeys->hash_len);
    if (esnikeys->hash==NULL) {
        ESNIerr(ESNI_F_MAKEESNICONTENTHASH, ERR_R_INTERNAL_ERROR);
        goto err;
    }
    if (mctx == NULL
            || EVP_DigestInit_ex(mctx, md, NULL) <= 0
            || EVP_DigestUpdate(mctx, esnikeys->hi, esnikeys->hi_len) <= 0
            || EVP_DigestFinal_ex(mctx, esnikeys->hash, NULL) <= 0) {
        ESNIerr(ESNI_F_MAKEESNICONTENTHASH, ERR_R_INTERNAL_ERROR);
        goto err;
    }
    EVP_MD_CTX_free(mctx);
    return 1;
err:
    if (mctx!=NULL) EVP_MD_CTX_free(mctx);
    if (tmp!=NULL) OPENSSL_free(tmp);
    return 0;
}

/**
 * @brief from Zx and ESNIContent, derive key, iv and aad
 * 
 * @param esni is the SSL_ESNI structure
 * @return 1 for success, other otherwise
 */
static int key_derivation(SSL_ESNI *esnikeys)
{

    /* prepare nid and EVP versions for later checks */
    uint16_t cipher_nid = esnikeys->ciphersuite;
    const SSL_CIPHER *sc=cs2sc(cipher_nid);
    const EVP_MD *md=ssl_md(sc->algorithm2);
    const EVP_CIPHER *e_ciph=EVP_get_cipherbynid(SSL_CIPHER_get_cipher_nid(sc));
    if (e_ciph==NULL) {
        ESNIerr(ESNI_F_KEY_DERIVATION, ERR_R_INTERNAL_ERROR);
        goto err;
    }
    esnikeys->key_len=EVP_CIPHER_key_length(e_ciph);
    esnikeys->key=esni_hkdf_expand_label(esnikeys->Zx,esnikeys->Zx_len,"esni key",
                    esnikeys->hash,esnikeys->hash_len,&esnikeys->key_len,md);
    if (esnikeys->key==NULL) {
        ESNIerr(ESNI_F_KEY_DERIVATION, ERR_R_INTERNAL_ERROR);
        goto err;
    }
    esnikeys->iv_len=EVP_CIPHER_iv_length(e_ciph);
    esnikeys->iv=esni_hkdf_expand_label(esnikeys->Zx,esnikeys->Zx_len,"esni iv",
                    esnikeys->hash,esnikeys->hash_len,&esnikeys->iv_len,md);
    if (esnikeys->iv==NULL) {
        ESNIerr(ESNI_F_KEY_DERIVATION, ERR_R_INTERNAL_ERROR);
        goto err;
    }
    /*
     * Put a few encoding bytes around the TLS h/s key share
     */
    esnikeys->aad=SSL_ESNI_wrap_keyshare(esnikeys->hs_kse,esnikeys->hs_kse_len,esnikeys->group_id,&esnikeys->aad_len);
    if (esnikeys->aad==NULL) {
        ESNIerr(ESNI_F_KEY_DERIVATION, ERR_R_MALLOC_FAILURE);
        goto err;
    }
    return 1;
err:
    return 0;
}

/**
 * @brief Do the client-side SNI encryption during a TLS handshake
 *
 * This is an internal API called as part of the state machine
 * dealing with this extension.
 *
 * @param esnikeys is the SSL_ESNI structure
 * @param client_random_len is the number of bytes of
 * @param client_random being the TLS h/s client random
 * @param curve_id is the curve_id of the client keyshare
 * @param client_keyshare_len is the number of bytes of
 * @param client_keyshare is the h/s client keyshare
 * @return 1 for success, other otherwise
 */
int SSL_ESNI_enc(SSL_ESNI *esnikeys, 
                size_t  client_random_len,
                unsigned char *client_random,
                uint16_t curve_id,
                size_t  client_keyshare_len,
                unsigned char *client_keyshare,
                CLIENT_ESNI **the_esni)
{

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
     */
    EVP_PKEY_CTX *pctx=NULL;

    /*
     * checking and copying
     */

    if (esnikeys==NULL || esnikeys->esni_peer_pkey==NULL) {
        ESNIerr(ESNI_F_SSL_ESNI_ENC, ERR_R_INTERNAL_ERROR);
        goto err;
    }
    if (esnikeys->hs_cr==NULL) {
        esnikeys->hs_cr_len=client_random_len;
        esnikeys->hs_cr=OPENSSL_malloc(esnikeys->hs_cr_len);
        if (esnikeys->hs_cr == NULL ) {
            ESNIerr(ESNI_F_SSL_ESNI_ENC, ERR_R_MALLOC_FAILURE);
            goto err;
        }
        memcpy(esnikeys->hs_cr,client_random,esnikeys->hs_cr_len);
    }
    if (esnikeys->encservername==NULL) {
        ESNIerr(ESNI_F_SSL_ESNI_ENC, ERR_R_INTERNAL_ERROR);
        goto err;
    }
    /*
     * There is no point in doing this if SNI and ESNI payloads
     * are the same!!!
     */
    if (esnikeys->covername!=NULL && esnikeys->encservername!=NULL) {
        if (OPENSSL_strnlen(esnikeys->covername,TLSEXT_MAXLEN_host_name)==
            OPENSSL_strnlen(esnikeys->encservername,TLSEXT_MAXLEN_host_name)) {
            if (!CRYPTO_memcmp(esnikeys->covername,esnikeys->encservername,
                OPENSSL_strnlen(esnikeys->covername,TLSEXT_MAXLEN_host_name))) {
                /*
                 * Shit - same names, that's silly
                 */
                ESNIerr(ESNI_F_SSL_ESNI_ENC, ERR_R_INTERNAL_ERROR);
                goto err;
            }
        }
    }
    if (esnikeys->public_name!=NULL && esnikeys->encservername!=NULL) {
        if (OPENSSL_strnlen(esnikeys->public_name,TLSEXT_MAXLEN_host_name)==
            OPENSSL_strnlen(esnikeys->encservername,TLSEXT_MAXLEN_host_name)) {
            if (!CRYPTO_memcmp(esnikeys->public_name,esnikeys->encservername,
                OPENSSL_strnlen(esnikeys->public_name,TLSEXT_MAXLEN_host_name))) {
                /*
                 * Shit - same names, that's silly
                 */
                ESNIerr(ESNI_F_SSL_ESNI_ENC, ERR_R_INTERNAL_ERROR);
                goto err;
            }
        }
    }

    if (esnikeys->hs_kse==NULL) {
        esnikeys->hs_kse=OPENSSL_malloc(client_keyshare_len);
        if (esnikeys->hs_kse==NULL) {
            ESNIerr(ESNI_F_SSL_ESNI_ENC, ERR_R_MALLOC_FAILURE);
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

#ifdef ESNI_CRYPT_INTEROP

    if (esnikeys->private_str==NULL) {
        esnikeys->keyshare = ssl_generate_pkey(esnikeys->esni_peer_pkey);
        if (esnikeys->keyshare == NULL) {
            ESNIerr(ESNI_F_SSL_ESNI_ENC, ERR_R_INTERNAL_ERROR);
            goto err;
        }
    } else {
        /*
         * fixed sizes are ok here - it's just for NSS interop
         */
        int i; /* loop counter - android build doesn't like C99;-( */
        unsigned char binpriv[64];
        size_t bp_len=32;
        for (i=0;i!=32;i++) {
            binpriv[i]=A2B(esnikeys->private_str[2*i])*16+A2B(esnikeys->private_str[(2*i)+1]);
        }
        so_esni_pbuf("CRYPTO_INTEROP  private",binpriv,bp_len,0);
    
        int foo=EVP_PKEY_X25519;
        esnikeys->keyshare=EVP_PKEY_new_raw_private_key(foo,NULL,binpriv,bp_len);
        if (esnikeys->keyshare == NULL) {
            ESNIerr(ESNI_F_SSL_ESNI_ENC, ERR_R_INTERNAL_ERROR);
            goto err;
        }
    }
#else
    // random new private
    esnikeys->keyshare = ssl_generate_pkey(esnikeys->esni_peer_pkey);
    if (esnikeys->keyshare == NULL) {
        ESNIerr(ESNI_F_SSL_ESNI_ENC, ERR_R_INTERNAL_ERROR);
        goto err;
    }
#endif

    pctx = EVP_PKEY_CTX_new(esnikeys->keyshare,NULL);
    if (EVP_PKEY_derive_init(pctx) <= 0 ) {
        ESNIerr(ESNI_F_SSL_ESNI_ENC, ERR_R_INTERNAL_ERROR);
        goto err;
    }
    if (EVP_PKEY_derive_set_peer(pctx, esnikeys->esni_peer_pkey) <= 0 ) {
        ESNIerr(ESNI_F_SSL_ESNI_ENC, ERR_R_INTERNAL_ERROR);
        goto err;
    }
    if (EVP_PKEY_derive(pctx, NULL, &esnikeys->Z_len) <= 0) {
        ESNIerr(ESNI_F_SSL_ESNI_ENC, ERR_R_INTERNAL_ERROR);
        goto err;
    }
    esnikeys->Z=OPENSSL_malloc(esnikeys->Z_len);
    if (esnikeys->Z == NULL) {
        ESNIerr(ESNI_F_SSL_ESNI_ENC, ERR_R_INTERNAL_ERROR);
        goto err;
    }
    if (EVP_PKEY_derive(pctx, esnikeys->Z, &esnikeys->Z_len) <= 0) {
        ESNIerr(ESNI_F_SSL_ESNI_ENC, ERR_R_INTERNAL_ERROR);
        goto err;
    }

    if (makeesnicontenthash(esnikeys,0)!=1) {
        ESNIerr(ESNI_F_SSL_ESNI_ENC, ERR_R_INTERNAL_ERROR);
        goto err;
    }

    /*
     * Form up the inner SNI stuff
     */
    esnikeys->realSNI_len=esnikeys->padded_length;
    esnikeys->realSNI=esni_pad(esnikeys->encservername,esnikeys->realSNI_len);
    if (esnikeys->realSNI==NULL) {
        ESNIerr(ESNI_F_SSL_ESNI_ENC, ERR_R_INTERNAL_ERROR);
        goto err;
    }
    esnikeys->nonce_len=16;
    esnikeys->nonce=esni_nonce(esnikeys->nonce_len);
    if (!esnikeys->nonce) {
        ESNIerr(ESNI_F_SSL_ESNI_ENC, ERR_R_INTERNAL_ERROR);
        goto err;
    }

    /*
     * encode into our plaintext
     */
    esnikeys->plain_len=esnikeys->nonce_len+esnikeys->realSNI_len;
    esnikeys->plain=OPENSSL_malloc(esnikeys->plain_len);
    if (esnikeys->plain == NULL) {
        ESNIerr(ESNI_F_SSL_ESNI_ENC, ERR_R_INTERNAL_ERROR);
        goto err;
    }
    unsigned char *pip=esnikeys->plain;
    memcpy(pip,esnikeys->nonce,esnikeys->nonce_len); pip+=esnikeys->nonce_len;
    memcpy(pip,esnikeys->realSNI,esnikeys->realSNI_len); pip+=esnikeys->realSNI_len;

    /*
     * Derive key and encrypt
     * encrypt the actual SNI based on shared key, Z - the I-D says:
     *    Zx = HKDF-Extract(0, Z)
     *    key = HKDF-Expand-Label(Zx, "esni key", Hash(ESNIContents), key_length)
     *    iv = HKDF-Expand-Label(Zx, "esni iv", Hash(ESNIContents), iv_length)
     */
    const SSL_CIPHER *sc=cs2sc(esnikeys->ciphersuite);
    const EVP_MD *md=ssl_md(sc->algorithm2);
    esnikeys->Zx_len=0;
    esnikeys->Zx=esni_hkdf_extract(esnikeys->Z,esnikeys->Z_len,&esnikeys->Zx_len,md);
    if (esnikeys->Zx==NULL) {
        ESNIerr(ESNI_F_SSL_ESNI_ENC, ERR_R_INTERNAL_ERROR);
        goto err;
    }

    /* 
     * derive key and iv length from suite
     */
    if (key_derivation(esnikeys)!=1) {
        ESNIerr(ESNI_F_SSL_ESNI_ENC, ERR_R_INTERNAL_ERROR);
        goto err;
    }

    /*
     * The actual encryption... from the I-D:
     *     encrypted_sni = AEAD-Encrypt(key, iv, ClientHello.KeyShareClientHello, ClientESNIInner)
     */

    /*
     * Tag is in ciphertext anyway, but sure may as well keep it
     */
    esnikeys->tag_len=EVP_GCM_TLS_TAG_LEN;
    esnikeys->tag=OPENSSL_malloc(esnikeys->tag_len);
    if (esnikeys->tag == NULL) {
        ESNIerr(ESNI_F_SSL_ESNI_ENC, ERR_R_MALLOC_FAILURE);
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
        ESNIerr(ESNI_F_SSL_ESNI_ENC, ERR_R_INTERNAL_ERROR);
        goto err;
    }

    if (esnikeys->cipher_len>SSL_MAX_SSL_ENCRYPTED_SNI_LENGTH) {
        ESNIerr(ESNI_F_SSL_ESNI_ENC, ERR_R_INTERNAL_ERROR);
        goto err;
    }
    EVP_PKEY_CTX_free(pctx);
    pctx=NULL;

    /* 
     * finish up
     */

    CLIENT_ESNI *tc=OPENSSL_malloc(sizeof(CLIENT_ESNI));
    if (tc==NULL) {
        ESNIerr(ESNI_F_SSL_ESNI_ENC, ERR_R_INTERNAL_ERROR);
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
    return 1;
 err:
    /*
     * Everything else should be pointed to via esnikeys, and should
     * be freed elsewhen, so this is all we need to explictly handle
     */
    if (pctx!=NULL) EVP_PKEY_CTX_free(pctx);
    return 0;
}

/**
 * @brief Attempt/do the serveri-side decryption during a TLS handshake
 *
 * This is the internal API called as part of the state machine
 * dealing with this extension.
 * 
 * Note that the decrypted server name is just a set of octets - there
 * is no guarantee it's a DNS name or printable etc. (Same as with
 * SNI generally.)
 *
 * @param esni is the SSL_ESNI structure
 * @param client_random_len is the number of bytes of
 * @param client_random being the TLS h/s client random
 * @param curve_id is the curve_id of the client keyshare
 * @param client_keyshare_len is the number of bytes of
 * @param client_keyshare is the h/s client keyshare
 * @return NULL for error, or the decrypted servername when it works
 */
unsigned char *SSL_ESNI_dec(SSL_ESNI *esni,
                size_t    client_random_len,
                unsigned char *client_random,
                uint16_t curve_id,
                size_t    client_keyshare_len,
                unsigned char *client_keyshare,
                size_t *encservername_len)
{
    EVP_PKEY_CTX *pctx=NULL;
    if (!esni) {
        ESNIerr(ESNI_F_SSL_ESNI_DEC, ERR_R_INTERNAL_ERROR);
        goto err;
    }
    if (!esni->the_esni) {
        ESNIerr(ESNI_F_SSL_ESNI_DEC, ERR_R_INTERNAL_ERROR);
        goto err;
    }
    if (!client_random || !client_random_len) {
        ESNIerr(ESNI_F_SSL_ESNI_DEC, ERR_R_INTERNAL_ERROR);
        goto err;
    }
    if (!client_keyshare || !client_keyshare_len) {
        ESNIerr(ESNI_F_SSL_ESNI_DEC, ERR_R_INTERNAL_ERROR);
        goto err;
    }
    if (!encservername_len) {
        ESNIerr(ESNI_F_SSL_ESNI_DEC, ERR_R_INTERNAL_ERROR);
        goto err;
    }

    /*
     * The plan
     * - check what we can before doing crypto
     *       - record_digest esni vs. ESNIKeys
     *       - ciphersuite/curve IDs
     * - do key derivation
     * - try decrypt
     * - compare what we can after crypto
     * - try extract and return SNI
     */
    CLIENT_ESNI *er=esni->the_esni;
    /*
     * Check record_digest
     */
    if (esni->rd_len!=er->record_digest_len) {
        ESNIerr(ESNI_F_SSL_ESNI_DEC, ERR_R_INTERNAL_ERROR);
        goto err;
    }
    if (CRYPTO_memcmp(esni->rd,er->record_digest,er->record_digest_len)) {
        ESNIerr(ESNI_F_SSL_ESNI_DEC, ERR_R_INTERNAL_ERROR);
        goto err;
    }
    if (er->ciphersuite!=esni->ciphersuite) {
        ESNIerr(ESNI_F_SSL_ESNI_DEC, ERR_R_INTERNAL_ERROR);
        goto err;
    }

    /*
     * copy inputs to state
     */
    esni->hs_cr_len=client_random_len;
    esni->hs_cr=OPENSSL_malloc(esni->hs_cr_len);
    if (esni->hs_cr==NULL) {
        ESNIerr(ESNI_F_SSL_ESNI_DEC, ERR_R_INTERNAL_ERROR);
        goto err;
    }
    memcpy(esni->hs_cr,client_random,esni->hs_cr_len);

    esni->hs_kse_len=client_keyshare_len;
    esni->hs_kse=OPENSSL_malloc(esni->hs_kse_len);
    if (esni->hs_kse==NULL) {
        ESNIerr(ESNI_F_SSL_ESNI_DEC, ERR_R_INTERNAL_ERROR);
        goto err;
    }
    memcpy(esni->hs_kse,client_keyshare,esni->hs_kse_len);

    esni->cipher_len=esni->the_esni->encrypted_sni_len;
    esni->cipher=OPENSSL_malloc(esni->cipher_len);
    if (esni->cipher==NULL) {
        ESNIerr(ESNI_F_SSL_ESNI_DEC, ERR_R_INTERNAL_ERROR);
        goto err;
    }
    memcpy(esni->cipher,esni->the_esni->encrypted_sni,esni->cipher_len);

    /*
     * Ok, let's go for Z
     */

    pctx = EVP_PKEY_CTX_new(esni->keyshare,NULL);
    if (EVP_PKEY_derive_init(pctx) <= 0 ) {
        ESNIerr(ESNI_F_SSL_ESNI_DEC, ERR_R_INTERNAL_ERROR);
        goto err;
    }
    /* mao er.encoded_keyshare to esni.esni_peer_pkey */
    if (esni->esni_peer_pkey!=NULL) {
        EVP_PKEY_free(esni->esni_peer_pkey);
        esni->esni_peer_pkey=NULL;
    }
    esni->esni_peer_pkey=ssl_generate_param_group(curve_id);
    if (esni->esni_peer_pkey==NULL) {
        ESNIerr(ESNI_F_SSL_ESNI_DEC, ERR_R_INTERNAL_ERROR);
        goto err;
    }
    if (!EVP_PKEY_set1_tls_encodedpoint(esni->esni_peer_pkey,
                er->encoded_keyshare+6,er->encoded_keyshare_len-6)) {
            ESNIerr(ESNI_F_SSL_ESNI_DEC, ESNI_R_RR_DECODE_ERROR);
            goto err;
    }
    if (EVP_PKEY_derive_set_peer(pctx, esni->esni_peer_pkey) <= 0 ) {
        ESNIerr(ESNI_F_SSL_ESNI_DEC, ERR_R_INTERNAL_ERROR);
        goto err;
    }
    if (EVP_PKEY_derive(pctx, NULL, &esni->Z_len) <= 0) {
        ESNIerr(ESNI_F_SSL_ESNI_DEC, ERR_R_INTERNAL_ERROR);
        goto err;
    }
    esni->Z=OPENSSL_malloc(esni->Z_len);
    if (esni->Z == NULL) {
        ESNIerr(ESNI_F_SSL_ESNI_DEC, ERR_R_INTERNAL_ERROR);
        goto err;
    }
    if (EVP_PKEY_derive(pctx, esni->Z, &esni->Z_len) <= 0) {
        ESNIerr(ESNI_F_SSL_ESNI_DEC, ERR_R_INTERNAL_ERROR);
        goto err;
    }

    const SSL_CIPHER *sc=cs2sc(esni->ciphersuite);
    const EVP_MD *md=ssl_md(sc->algorithm2);
    esni->Zx_len=0;
    esni->Zx=esni_hkdf_extract(esni->Z,esni->Z_len,&esni->Zx_len,md);
    if (esni->Zx==NULL) {
        ESNIerr(ESNI_F_SSL_ESNI_DEC, ERR_R_INTERNAL_ERROR);
        goto err;
    }

    if (makeesnicontenthash(esni,1)!=1) {
        ESNIerr(ESNI_F_SSL_ESNI_DEC, ERR_R_INTERNAL_ERROR);
        goto err;
    }

    /* 
     * derive key and iv length from suite
     */
    if (key_derivation(esni)!=1) {
        ESNIerr(ESNI_F_SSL_ESNI_DEC, ERR_R_INTERNAL_ERROR);
        goto err;
    }

    esni->plain=esni_aead_dec(esni->key, esni->key_len,
            esni->iv, esni->iv_len,
            esni->aad, esni->aad_len,
            esni->cipher, esni->cipher_len,
            &esni->plain_len,
            esni->ciphersuite);
    if (esni->plain==NULL) {
        ESNIerr(ESNI_F_SSL_ESNI_DEC, ERR_R_INTERNAL_ERROR);
        goto err;
    }

    /* yay! */
    esni->nonce_len=16;
    esni->nonce=OPENSSL_malloc(esni->nonce_len);
    if (esni->nonce==NULL) {
        ESNIerr(ESNI_F_SSL_ESNI_DEC, ERR_R_INTERNAL_ERROR);
        goto err;
    }
    memcpy(esni->nonce,esni->plain,esni->nonce_len);

    size_t outer_es_len=esni->plain[16]*256+esni->plain[17];
    size_t inner_es_len=outer_es_len-3;
    if (inner_es_len+21>esni->plain_len) {
        ESNIerr(ESNI_F_SSL_ESNI_DEC, ERR_R_INTERNAL_ERROR);
        goto err;
    }
    unsigned char *result=OPENSSL_malloc(inner_es_len+1);
    if (result==NULL) {
        ESNIerr(ESNI_F_SSL_ESNI_DEC, ERR_R_INTERNAL_ERROR);
        goto err;
    }
    memcpy(result,esni->plain+21,inner_es_len);
    result[inner_es_len]=0x00; /* make it a safe-ish string */
    esni->encservername=(char*)result;

    if (pctx!=NULL) EVP_PKEY_CTX_free(pctx);
    *encservername_len=inner_es_len;
    return result;
err:
    if (pctx!=NULL) EVP_PKEY_CTX_free(pctx);
    return NULL;
}

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
    if (elen==flen && !CRYPTO_memcmp(encservername,covername,elen)) {
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


/**
 * @brief: Turn on SNI encryption for an (upcoming) TLS session
 * 
 * @param s is the SSL context
 * @param hidde is the hidden service name
 * @param cover is the cleartext SNI name to use
 * @param esni is an array of SSL_ESNI structures
 * @param nesnis says how many structures are in the esni array
 * @param require_hidden_match say whether to require (==1) the TLS server cert matches the hidden name
 * @return 1 for success, other otherwise
 * 
 */
int SSL_esni_enable(SSL *s, const char *hidden, const char *cover, SSL_ESNI *esni, int nesnis, int require_hidden_match)
{
    int i; /* loop counter - android build doesn't like C99;-( */
    if (nesnis==0 || s==NULL || esni==NULL || hidden==NULL) {
        return 0;
    }
    /*
     * If there was an earlier SSL_ESNI structure loaded, we'll just
     * zap that first and use the one presented here.
     * We'll select which of the ESNIKeys included in the SSL_ESNI data
     * structure to use at this point on the client side. Selection 
     * criteria are: 1) most recent ESNIKeys version first, 2) the
     * most recently created based on not_before. We do not care 
     * about not_after (for now; TODO: care about that sometime).
     */
    if (s->esni!=NULL) {
        for (i=0;i!=s->nesni;i++) {
            SSL_ESNI_free(&s->esni[i]);
        }
        OPENSSL_free(s->esni);
        s->esni=NULL;
    }
    s->esni=esni;
    s->nesni=nesnis;
    for (i=0;i!=nesnis;i++) {
        s->esni[i].require_hidden_match=require_hidden_match;
        s->esni[i].encservername=OPENSSL_strndup(hidden,TLSEXT_MAXLEN_host_name);
        s->esni[i].covername=NULL;
        if (cover != NULL) {
            s->esni[i].covername=OPENSSL_strndup(cover,TLSEXT_MAXLEN_host_name);
        }
    }
    if (s->ext.hostname!=NULL) {
        OPENSSL_free(s->ext.hostname);
        s->ext.hostname=NULL;
    }
    /*
     * the chosen index into the set of ESNIKeys in this SSL_ESNI
     */
    int keysind=0; 
    int most_recent=0;
    for (i=0;i!=nesnis;i++) {
        if (esni[i].not_before>most_recent) {
            most_recent=esni[i].not_before;
            keysind=i;
        }
    }

    /* 
     * We prefer Draft-03 public_name over locally supplied 
     * covername. 
     */
    if (s->esni[keysind].public_name!=NULL) {
        s->ext.hostname=OPENSSL_strndup(s->esni[keysind].public_name,TLSEXT_MAXLEN_host_name);
    } else {
        if (cover!=NULL) {
            s->ext.hostname=OPENSSL_strndup(cover,TLSEXT_MAXLEN_host_name);
        }
    }

    /*
     * Set to 1 when nonce returned
     * Checked for 0 when final_esni called
     */
    s->esni_done=0;
    /*
     * Optionally enable hostname checking 
     */
    if (require_hidden_match==1) {
        if (SSL_set1_host(s,hidden)!=1) {
            return 0;
        }
    }

    /*
     * Handle padding - the server needs to do padding in case the
     * certificate/key-size exposes the ESNI. But so can lots of 
     * the other application interactions, so to be at least a bit
     * cautious, we'll also pad the crap out of everything on the
     * client side (at least to see what happens:-)
     * This could be over-ridden by the client appication if it
     * wants by setting a callback via SSL_set_record_padding_callback
     * We'll try set to 512 bytes, minus the 16 overhead so that
     * wireshark shows us nice round numbers and we're less
     * likely to go beyond an MTU (1550)
     */

    if (SSL_set_block_padding(s,ESNI_DEFAULT_PADDED)!=1) {
        return 0;
    }
    return 1;
}

int SSL_esni_server_enable(SSL_CTX *ctx, const char *esnikeyfile, const char *esnipubfile)
{
    /*
     * open and parse files (private key is PEM, public is binary/ESNIKeys)
     * and store in context
     */
    BIO *priv_in=NULL;
    BIO *pub_in=NULL;
    EVP_PKEY *pkey=NULL;
    ESNI_RECORD *er=NULL;
    SSL_ESNI *the_esni=NULL;
    unsigned char *inbuf=NULL;
    if (ctx==NULL || esnikeyfile==NULL || esnipubfile==NULL) {
        ESNIerr(ESNI_F_SSL_ESNI_SERVER_ENABLE, ERR_R_INTERNAL_ERROR);
        goto err;
    }
    priv_in = BIO_new(BIO_s_file());
    if (priv_in==NULL) {
        ESNIerr(ESNI_F_SSL_ESNI_SERVER_ENABLE, ERR_R_INTERNAL_ERROR);
        goto err;
    }
    if (BIO_read_filename(priv_in,esnikeyfile)<=0) {
        ESNIerr(ESNI_F_SSL_ESNI_SERVER_ENABLE, ERR_R_INTERNAL_ERROR);
        goto err;
    }
    if (!PEM_read_bio_PrivateKey(priv_in,&pkey,NULL,NULL)) {
        ESNIerr(ESNI_F_SSL_ESNI_SERVER_ENABLE, ERR_R_INTERNAL_ERROR);
        goto err;
    }
    BIO_free(priv_in);

    pub_in = BIO_new(BIO_s_file());
    if (pub_in==NULL) {
        ESNIerr(ESNI_F_SSL_ESNI_SERVER_ENABLE, ERR_R_INTERNAL_ERROR);
        goto err;
    }
    if (BIO_read_filename(pub_in,esnipubfile)<=0) {
        ESNIerr(ESNI_F_SSL_ESNI_SERVER_ENABLE, ERR_R_INTERNAL_ERROR);
        goto err;
    }
    inbuf=OPENSSL_malloc(ESNI_MAX_RRVALUE_LEN);
    if (inbuf==NULL) {
        ESNIerr(ESNI_F_SSL_ESNI_SERVER_ENABLE, ERR_R_INTERNAL_ERROR);
        goto err;
    }
    size_t inblen=0;
    inblen=BIO_read(pub_in,inbuf,ESNI_MAX_RRVALUE_LEN);
    if (inblen<=0) {
        ESNIerr(ESNI_F_SSL_ESNI_SERVER_ENABLE, ERR_R_INTERNAL_ERROR);
        goto err;
    }
    BIO_free(pub_in);
    int leftover=0;
    er=SSL_ESNI_RECORD_new_from_binary(inbuf,inblen,&leftover);
    if (er==NULL) {
        ESNIerr(ESNI_F_SSL_ESNI_SERVER_ENABLE, ERR_R_INTERNAL_ERROR);
        goto err;
    }

    /*
     * store in context
     */
    if (ctx->ext.esni==NULL) {
        ctx->ext.nesni=1;
        the_esni=(SSL_ESNI*)OPENSSL_malloc(sizeof(SSL_ESNI));
        if (the_esni==NULL) {
            ESNIerr(ESNI_F_SSL_ESNI_SERVER_ENABLE, ERR_R_INTERNAL_ERROR);
            goto err;
        }
    } else {
        ctx->ext.nesni+=1;
        the_esni=(SSL_ESNI*)OPENSSL_realloc(ctx->ext.esni,ctx->ext.nesni*sizeof(SSL_ESNI));
        if (the_esni==NULL) {
            ESNIerr(ESNI_F_SSL_ESNI_SERVER_ENABLE, ERR_R_INTERNAL_ERROR);
            goto err;
        }
    }
    ctx->ext.esni=the_esni;

    SSL_ESNI* latest_esni=&ctx->ext.esni[ctx->ext.nesni-1];
    memset(latest_esni,0,sizeof(SSL_ESNI));
    latest_esni->encoded_rr=inbuf;
    latest_esni->encoded_rr_len=inblen;
    if (esni_make_se_from_er(er,latest_esni,1)!=1) {
        ESNIerr(ESNI_F_SSL_ESNI_SERVER_ENABLE, ERR_R_INTERNAL_ERROR);
        goto err;
    }
    // add my private key in there, the public was handled above
    latest_esni->keyshare=pkey;

    /*
     * Handle padding - we need to pad the Certificate and CertificateVerify
     * messages as those can expose the ESNI value due to differing sizes.
     * We might want to make this cleverer, e.g. by checking the sizes of
     * the certificates/public keys involved, but for now, we'll try to 
     * use the standard record padding scheme via SSL_CTX_set_block_padding
     * to set padding to 486 sized blocks and see what happens.
     * This can be over-ridden by the appication if it wants by setting a 
     * callback via SSL_CTX_set_record_padding_callback
     */
    if (SSL_CTX_set_block_padding(ctx,ESNI_DEFAULT_PADDED)!=1) {
        ESNIerr(ESNI_F_SSL_ESNI_SERVER_ENABLE, ERR_R_INTERNAL_ERROR);
        goto err;
    }

    ESNI_RECORD_free(er);
    OPENSSL_free(er);
    return 1;

err:
    if (inbuf!=NULL) {
        OPENSSL_free(inbuf);
        if (the_esni!=NULL && the_esni->encoded_rr==inbuf) {
            /*
             * don't double free
             */
            the_esni->encoded_rr=NULL;
        }
    }
    if (the_esni!=NULL) {
        SSL_ESNI_free(the_esni);
        OPENSSL_free(the_esni);
    }
    if (er!=NULL) {
        ESNI_RECORD_free(er);
        OPENSSL_free(er);
    }
    if (pkey!=NULL) {
        EVP_PKEY_free(pkey);
    }
    BIO_free(priv_in);
    BIO_free(pub_in);
    return 0;
};

int SSL_get_esni_status(SSL *s, char **hidden, char **cover)
{
    if (cover==NULL || hidden==NULL) {
        return SSL_ESNI_STATUS_BAD_CALL;
    }
    *cover=NULL;
    *hidden=NULL;
    if (s->esni!=NULL) {
        long vr=X509_V_OK;
        if (s->esni->require_hidden_match) {
            vr=SSL_get_verify_result(s);
        }
        *hidden=s->esni->encservername;
        /*
         * Prefer draft-03 public_name to locally supplied covername
         * TODO: consider whether or not that's a good plan
         */
        if (s->esni->public_name) {
            *cover=s->esni->public_name;
        } else {
            *cover=s->esni->covername;
        }
        if (s->esni_done==1) {
            if (vr == X509_V_OK ) {
                return SSL_ESNI_STATUS_SUCCESS;
            } else {
                return SSL_ESNI_STATUS_BAD_NAME;
            }
        } else {
            return SSL_ESNI_STATUS_FAILED;
        }
    } 
    return SSL_ESNI_STATUS_NOT_TRIED;
}

void SSL_set_esni_callback(SSL *s, SSL_esni_client_cb_func f)
{
    s->esni_cb=f;
}

void SSL_set_esni_callback_ctx(SSL_CTX *s, SSL_esni_client_cb_func f)
{
    s->ext.esni_cb=f;
}

int SSL_ESNI_get_esni(SSL *s, SSL_ESNI **esni)
{
    if (s==NULL || esni==NULL) {
        return 0;
    }
    *esni=s->esni;
    return 1;
}
 
int SSL_ESNI_get_esni_ctx(SSL_CTX *s, SSL_ESNI **esni){
    if (s==NULL || esni==NULL) {
        return 0;
    }
    *esni=s->ext.esni;
    return s->ext.nesni;
}

int SSL_ESNI_set_private(SSL_ESNI *esni, char *private_str)
{
#ifdef ESNI_CRYPT_INTEROP
    esni->private_str=private_str;
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

SSL_ESNI* SSL_ESNI_dup(SSL_ESNI* orig, size_t nesni)
{
    SSL_ESNI *new=NULL;

    if (orig==NULL) return NULL;
    new=OPENSSL_malloc(nesni*sizeof(SSL_ESNI));
    if (new==NULL) {
        ESNIerr(ESNI_F_SSL_ESNI_DUP, ERR_R_INTERNAL_ERROR);
        goto err;
    }
    memset(new,0,nesni*sizeof(SSL_ESNI));

    int i; /* loop counter - android build doesn't like C99;-( */
    for (i=0;i!=nesni;i++) {

        SSL_ESNI *origi=&orig[i];
        SSL_ESNI *newi=&new[i];

        if (origi->encoded_rr) {
            newi->encoded_rr_len=origi->encoded_rr_len;
            newi->encoded_rr=OPENSSL_malloc(newi->encoded_rr_len);
            if (newi->encoded_rr==NULL) {
                ESNIerr(ESNI_F_SSL_ESNI_DUP, ERR_R_INTERNAL_ERROR);
                goto err;
            }
            memcpy(newi->encoded_rr,origi->encoded_rr,newi->encoded_rr_len);
        }
    
        if (origi->rd) {
            newi->rd_len=origi->rd_len;
            newi->rd=OPENSSL_malloc(newi->rd_len);
            if (newi->rd==NULL) {
                ESNIerr(ESNI_F_SSL_ESNI_DUP, ERR_R_INTERNAL_ERROR);
                goto err;
            }
            memcpy(newi->rd,origi->rd,newi->rd_len);
        }
        if (origi->encoded_keyshare) {
            newi->encoded_keyshare_len=origi->encoded_keyshare_len;
            newi->encoded_keyshare=OPENSSL_malloc(newi->encoded_keyshare_len);
            if (newi->encoded_keyshare==NULL) {
                ESNIerr(ESNI_F_SSL_ESNI_DUP, ERR_R_INTERNAL_ERROR);
                goto err;
            }
            memcpy(newi->encoded_keyshare,origi->encoded_keyshare,newi->encoded_keyshare_len);
        }
        newi->keyshare=origi->keyshare;
        if (EVP_PKEY_up_ref(origi->keyshare)!=1) {
               ESNIerr(ESNI_F_SSL_ESNI_DUP, ERR_R_INTERNAL_ERROR);
               goto err;
        }
        newi->group_id=origi->group_id;
        newi->padded_length=origi->padded_length;
        newi->not_before=origi->not_before;
        newi->not_after=origi->not_after;
        newi->ciphersuite=origi->ciphersuite;
    }

    return new;
err:
    if (new!=NULL) {
        SSL_ESNI_free(new);
        OPENSSL_free(new);
    }
    return NULL;
}

#endif

